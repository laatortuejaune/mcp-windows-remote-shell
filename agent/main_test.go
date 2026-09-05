package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	m := newCommandManager()
	t.Cleanup(func() { m.stop(); m.active.Wait() })
	return newHTTPServer(config{token: "test-bearer", timeout: 30 * time.Second}, m).Handler
}

func TestAuthenticationAndHealth(t *testing.T) {
	handler := testHandler(t)
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	for _, path := range []string{"/exec", "/health"} {
		for _, auth := range []string{"", "Bearer invalid", "Basic test-bearer"} {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
			r.Header.Set("Authorization", auth)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized || w.Header().Get("Connection") != "close" {
				t.Fatalf("%s unauthorized response: %d, %v", path, w.Code, w.Header())
			}
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	r.Header.Set("Authorization", "Bearer test-bearer")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var health struct {
		PID                   int `json:"pid"`
		DefaultTimeoutSeconds int `json:"default_timeout_seconds"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || health.PID != os.Getpid() || health.DefaultTimeoutSeconds != 30 {
		t.Fatalf("invalid health response: %d, %+v", w.Code, health)
	}
	if strings.Contains(logs.String(), "test-bearer") || strings.Contains(logs.String(), "invalid") {
		t.Fatal("authentication information appeared in logs")
	}
}

func TestExecutionRejectsInvalidBodies(t *testing.T) {
	handler := testHandler(t)
	for name, body := range map[string]string{
		"unknown field":        `{"command":"echo ok","extra":true}`,
		"second document":      `{"command":"echo ok"}{}`,
		"trailing junk":        `{"command":"echo ok"}x`,
		"oversize command":     `{"command":"` + strings.Repeat("x", maxRequestBytes) + `"}`,
		"oversize tail":        `{"command":"echo ok"}` + strings.Repeat(" ", maxRequestBytes),
		"empty command":        `{"command":" "}`,
		"negative timeout":     `{"command":"echo ok","timeout_seconds":-1}`,
		"timeout over maximum": `{"command":"echo ok","timeout_seconds":3601}`,
		"timeout overflow":     `{"command":"echo ok","timeout_seconds":9223372036854775807}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/exec", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer test-bearer")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected rejection, got %d: %s", w.Code, w.Body)
			}
		})
	}
}

func TestCapBufferConsumesAllBytes(t *testing.T) {
	b := &capBuffer{limit: 7}
	for _, input := range []string{"abc", "defg", "hijkl"} {
		n, err := b.Write([]byte(input))
		if n != len(input) || err != nil {
			t.Fatalf("short write: %d, %v", n, err)
		}
	}
	if b.String() != "abcdefg" || !b.truncated {
		t.Fatalf("incorrect capped output: %q, %v", b.String(), b.truncated)
	}
	exact := &capBuffer{limit: 3}
	_, _ = exact.Write([]byte("abc"))
	_, _ = exact.Write(nil)
	if exact.truncated {
		t.Fatal("empty write incorrectly marked an exact-length output truncated")
	}
}

func TestCommandEnvironment(t *testing.T) {
	got := commandEnvironment([]string{
		"PATH=/bin", "RELAY_TOKEN=private", "relay_token_file=private-file",
		"ReLaY_RENDEZVOUS_READ_KEY=private-key", "NORMAL=value", "=C:=C:\\",
	})
	want := []string{"PATH=/bin", "NORMAL=value", "=C:=C:\\"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected command environment: %v", got)
	}
}

func TestFailedTerminationDoesNotBlockRequest(t *testing.T) {
	pipes, err := newCommandPipes()
	if err != nil {
		t.Fatal(err)
	}
	defer pipes.close()
	waitFinished := make(chan struct{})
	handlesClosed := make(chan struct{})
	p := &runningCommand{
		stdout: pipes.outR, stderr: pipes.errR,
		wait:      func() (int, error) { <-waitFinished; return 0, nil },
		terminate: func() error { return errors.New("permission denied") },
		close:     func() error { close(handlesClosed); return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	code, err := runStartedCommand(ctx, p, io.Discard, io.Discard, 50*time.Millisecond)
	if code != -1 || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "process did not exit") {
		t.Fatalf("missing cancellation failure: %d, %v", code, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("failed kill blocked the request")
	}
	select {
	case <-handlesClosed:
		t.Fatal("closed process handle while Wait was using it")
	default:
	}
	close(waitFinished)
	select {
	case <-handlesClosed:
	case <-time.After(time.Second):
		t.Fatal("process handle not released after Wait finished")
	}
}

func TestMissingTokenIsRejected(t *testing.T) {
	t.Setenv("RELAY_TOKEN", "")
	if _, err := loadToken(""); err == nil {
		t.Fatal("empty token was accepted")
	}
	if err := run(config{timeout: time.Second}); err == nil {
		t.Fatal("run accepted missing authentication")
	}
}

func TestIncompleteUnauthenticatedBodyIsRejectedImmediately(t *testing.T) {
	m := newCommandManager()
	server := httptest.NewUnstartedServer(nil)
	server.Config = newHTTPServer(config{token: "test-bearer", timeout: 30 * time.Second}, m)
	server.Start()
	t.Cleanup(func() { m.stop(); server.Close(); m.active.Wait() })
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(conn, "POST /exec HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("agent waited for unauthenticated body: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 401 || !response.Close {
		t.Fatalf("unexpected response: %s, close=%v", response.Status, response.Close)
	}
}

func TestIncompleteAuthenticatedBodyHasReadDeadline(t *testing.T) {
	m := newCommandManager()
	server := httptest.NewUnstartedServer(nil)
	server.Config = newHTTPServer(config{token: "test-bearer", timeout: 30 * time.Second}, m)
	server.Config.ReadTimeout = 100 * time.Millisecond
	server.Start()
	t.Cleanup(func() { m.stop(); server.Close(); m.active.Wait() })
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = fmt.Fprint(conn, "POST /exec HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer test-bearer\r\nContent-Length: 20\r\n\r\n{\"command\":")
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read deadline failed to produce a refusal: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatalf("unexpected response: %s", response.Status)
	}
}
