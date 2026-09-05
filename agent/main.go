// Command relay-agent is a minimal, outbound-only "troubleshooting relay" agent.
//
// It listens on 127.0.0.1 ONLY and exposes two token-protected endpoints:
//
//	POST /exec    run one shell command, return stdout / stderr / exit code
//	GET  /health  liveness + basic host info (also confirms the token)
//
// The only intended way in is an outbound tunnel the operator starts by hand,
// e.g. `cloudflared tunnel --url http://127.0.0.1:<port>`. The agent never binds
// a routable interface, so nothing is reachable without that tunnel.
//
// POC scope. Deliberately NOT implemented (phase 2): end-to-end encryption
// beyond the tunnel's TLS, persistent shell sessions, output streaming,
// auto-reconnect, and file read/write.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const version = "0.1.0-poc"

const (
	// loopback is hard-wired: the agent must never listen on a routable
	// address. Only the port is configurable.
	loopback = "127.0.0.1"

	maxRequestBytes = 64 << 10 // 64 KiB is plenty for an /exec request body.
	maxStreamBytes  = 1 << 20  // 1 MiB cap per captured stream (stdout/stderr).
	maxTimeout      = 3600 * time.Second
)

type execRequest struct {
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

type execResponse struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	TimedOut   bool   `json:"timed_out"`
	Truncated  bool   `json:"truncated"`
	DurationMS int64  `json:"duration_ms"`
}

type config struct {
	port    int
	timeout time.Duration
	token   string
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	var (
		port      = flag.Int("port", envInt("RELAY_PORT", 47600), "TCP port to listen on (always bound to 127.0.0.1)")
		timeout   = flag.Int("timeout", envInt("RELAY_TIMEOUT", 30), "default per-command timeout, in seconds")
		tokenFile = flag.String("token-file", os.Getenv("RELAY_TOKEN_FILE"), "file holding the bearer token (alternative to RELAY_TOKEN)")
		genToken  = flag.Bool("gen-token", false, "print a fresh random token and exit")
		showVer   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("relay-agent", version)
		return
	}
	if *genToken {
		fmt.Println(newToken())
		return
	}
	if *timeout <= 0 || *timeout > int(maxTimeout/time.Second) {
		log.Fatalf("startup: --timeout must be between 1 and 3600 seconds")
	}

	token, err := loadToken(*tokenFile)
	if err != nil {
		log.Fatalf("startup: %v", err)
	}

	cfg := config{
		port:    *port,
		timeout: time.Duration(*timeout) * time.Second,
		token:   token,
	}
	if err := run(cfg); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run(cfg config) error {
	if cfg.token == "" || cfg.timeout <= 0 || cfg.timeout > maxTimeout {
		return errors.New("invalid agent configuration")
	}
	addr := net.JoinHostPort(loopback, fmt.Sprintf("%d", cfg.port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	// Belt and braces: refuse to serve if we somehow ended up non-loopback.
	if ta, ok := ln.Addr().(*net.TCPAddr); !ok || !ta.IP.IsLoopback() {
		ln.Close()
		return errors.New("refusing to serve on a non-loopback TCP address")
	}

	log.Printf("relay-agent %s listening on http://%s (os=%s arch=%s default-timeout=%s)",
		version, ln.Addr().String(), runtime.GOOS, runtime.GOARCH, cfg.timeout)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, cfg, ln)
}

// A manager closes admission before waiting, so no handler can register a new
// command after shutdown has started. Canceling its context stops active trees.
type commandManager struct {
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	stopping bool
	active   sync.WaitGroup
}

func newCommandManager() *commandManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &commandManager{ctx: ctx, cancel: cancel}
}

func (m *commandManager) begin() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return false
	}
	m.active.Add(1)
	return true
}

func (m *commandManager) stop() {
	m.mu.Lock()
	m.stopping = true
	m.cancel()
	m.mu.Unlock()
}

func newHTTPServer(cfg config, commands *commandManager) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", withAuth(cfg.token, handleHealth(cfg.timeout)))
	mux.HandleFunc("/exec", withAuth(cfg.token, handleExec(cfg.timeout, commands)))
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		// Execution may take longer than body upload; do not set WriteTimeout.
		BaseContext: func(net.Listener) context.Context { return commands.ctx },
	}
}

func serve(ctx context.Context, cfg config, ln net.Listener) error {
	commands := newCommandManager()
	srv := newHTTPServer(cfg, commands)
	stopped := make(chan struct{})
	idle := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
		case <-stopped:
			return
		}
		log.Printf("shutting down")
		commands.stop()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := srv.Shutdown(ctx)
		if err != nil {
			_ = srv.Close()
		}
		commands.active.Wait()
		idle <- err
	}()
	defer close(stopped)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		commands.stop()
		_ = srv.Close()
		commands.active.Wait()
		return err
	}
	return <-idle
}

// withAuth enforces a constant-time bearer-token check. The token is never
// written to the logs, on success or failure.
func withAuth(token string, next http.HandlerFunc) http.HandlerFunc {
	want := []byte("Bearer " + token)
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			// Otherwise net/http may drain an unauthenticated, incomplete body
			// before emitting the 401. Refuse it without waiting for an upload.
			w.Header().Set("Connection", "close")
			logRequest(r, http.StatusUnauthorized, start)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next(sw, r)
		logRequest(r, sw.status, start)
	}
}

func handleHealth(defaultTimeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":                  "ok",
			"agent":                   "relay-agent",
			"version":                 version,
			"os":                      runtime.GOOS,
			"arch":                    runtime.GOARCH,
			"pid":                     os.Getpid(),
			"default_timeout_seconds": int(defaultTimeout / time.Second),
			"time":                    time.Now().UTC().Format(time.RFC3339),
		})
	}
}

func handleExec(defaultTimeout time.Duration, commands *commandManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var req execRequest
		if err := dec.Decode(&req); err != nil {
			w.Header().Set("Connection", "close")
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			w.Header().Set("Connection", "close")
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must contain one JSON object within 64 KiB"})
			return
		}
		if strings.TrimSpace(req.Command) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "command is required"})
			return
		}

		timeout := defaultTimeout
		if req.TimeoutSeconds < 0 || req.TimeoutSeconds > int(maxTimeout/time.Second) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "timeout_seconds must be between 0 and 3600"})
			return
		}
		if req.TimeoutSeconds > 0 {
			timeout = time.Duration(req.TimeoutSeconds) * time.Second
		}
		if !commands.begin() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent is shutting down"})
			return
		}
		defer commands.active.Done()
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		stop := context.AfterFunc(commands.ctx, cancel)
		defer stop()

		stdout := &capBuffer{limit: maxStreamBytes}
		stderr := &capBuffer{limit: maxStreamBytes}
		start := time.Now()
		exitCode, runErr := runCommand(ctx, req.Command, stdout, stderr)
		dur := time.Since(start)

		resp := execResponse{
			Stdout:     stdout.String(),
			Stderr:     stderr.String(),
			Truncated:  stdout.truncated || stderr.truncated,
			DurationMS: dur.Milliseconds(),
		}
		// Success is checked first: a command that completes cleanly right at
		// the deadline returns runErr==nil and must be reported as exit 0, not
		// a spurious timeout. A timed-out command is always killed, so its
		// runErr is non-nil and it falls through to the deadline case.
		switch {
		case runErr == nil:
			resp.ExitCode = 0
		case ctx.Err() == context.DeadlineExceeded:
			resp.TimedOut = true
			resp.ExitCode = -1
		default:
			resp.ExitCode = exitCode
		}
		if resp.Stderr == "" && runErr != nil {
			// In particular, do not hide cleanup failures behind timed_out=true.
			resp.Stderr = runErr.Error()
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// capBuffer is an io.Writer that keeps at most `limit` bytes and flags when it
// had to drop the rest. It always reports a full write so the child process is
// never blocked by a short write on its stdout/stderr pipe.
type capBuffer struct {
	buf       []byte
	limit     int
	truncated bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if room := c.limit - len(c.buf); room > 0 {
		if room >= len(p) {
			c.buf = append(c.buf, p...)
		} else {
			c.buf = append(c.buf, p[:room]...)
			c.truncated = true
		}
	} else {
		c.truncated = true
	}
	return len(p), nil
}

func (c *capBuffer) String() string { return string(c.buf) }

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status = http.StatusOK
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// logRequest logs method, path, status and duration only — never request
// headers or bodies, so the bearer token and command text stay out of the logs.
func logRequest(r *http.Request, status int, start time.Time) {
	log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, status, time.Since(start).Round(time.Millisecond))
}

func loadToken(file string) (string, error) {
	if t := strings.TrimSpace(os.Getenv("RELAY_TOKEN")); t != "" {
		return t, nil
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("reading token file %q: %w", file, err)
		}
		if t := strings.TrimSpace(string(b)); t != "" {
			return t, nil
		}
		return "", fmt.Errorf("token file %q is empty", file)
	}
	return "", errors.New("no token configured: set RELAY_TOKEN or --token-file (generate one with: relay-agent --gen-token)")
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("generating token: %v", err)
	}
	return hex.EncodeToString(b)
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return def
}
