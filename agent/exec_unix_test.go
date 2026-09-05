//go:build !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func assertProcessStopped(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("command descendant %d survived cleanup", pid)
}

func TestCommandTreeCleanup(t *testing.T) {
	for _, test := range []struct {
		name, command string
		timeout       bool
	}{
		{"timeout", "sleep 30 & echo $!; wait", true},
		{"shell exits first", "sleep 30 & echo $!", false},
		{"redirected background", "sleep 30 >/dev/null 2>&1 & echo $!", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			var stdout, stderr bytes.Buffer
			start := time.Now()
			code, err := runCommand(ctx, test.command, &stdout, &stderr)
			if test.timeout && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected timeout, code=%d err=%v", code, err)
			}
			if !test.timeout && (code != 0 || err != nil) {
				t.Fatalf("normal shell exit failed: %d, %v", code, err)
			}
			if time.Since(start) > time.Second {
				t.Fatal("cleanup waited for inherited output pipes")
			}
			pid, err := strconv.Atoi(strings.TrimSpace(stdout.String()))
			if err != nil || pid <= 0 {
				t.Fatalf("missing test child PID: %q", stdout.String())
			}
			assertProcessStopped(t, pid)
		})
	}
}

func TestCommandEnvironmentDoesNotExposeRelaySecrets(t *testing.T) {
	t.Setenv("RELAY_TOKEN", "test-secret-do-not-inherit")
	t.Setenv("relay_token_file", "private-token-file")
	t.Setenv("KEEP_FOR_TEST", "expected")
	var stdout, stderr bytes.Buffer
	code, err := runCommand(context.Background(), "env", &stdout, &stderr)
	if code != 0 || err != nil || strings.Contains(stdout.String(), "test-secret") || strings.Contains(stdout.String(), "private-token-file") {
		t.Fatalf("command environment leak or failure: code=%d, err=%v", code, err)
	}
	if !strings.Contains(stdout.String(), "KEEP_FOR_TEST=expected") {
		t.Fatal("non-relay environment was lost")
	}
}

func TestBodyDeadlineDoesNotCancelLongExecution(t *testing.T) {
	m := newCommandManager()
	server := httptest.NewUnstartedServer(nil)
	server.Config = newHTTPServer(config{token: "test-bearer", timeout: time.Second}, m)
	server.Config.ReadTimeout = 50 * time.Millisecond
	server.Start()
	t.Cleanup(func() { m.stop(); server.Close(); m.active.Wait() })
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/exec", strings.NewReader(`{"command":"sleep 0.2; echo ok"}`))
	req.Header.Set("Authorization", "Bearer test-bearer")
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result execResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || result.TimedOut || strings.TrimSpace(result.Stdout) != "ok" {
		t.Fatalf("read deadline affected command execution: %+v", result)
	}
}

func TestShutdownStopsActiveCommands(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- serve(ctx, config{token: "test-bearer", timeout: 30 * time.Second}, ln) }()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	body, _ := json.Marshal(execRequest{Command: "sleep 30 & echo $! > '" + strings.ReplaceAll(pidFile, "'", "'\\''") + "'; wait"})
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		req, _ := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/exec", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-bearer")
		client := &http.Client{Timeout: 3 * time.Second}
		if response, err := client.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
	}()
	var pid int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(pidFile); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
			if pid > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid <= 0 {
		t.Fatal("test command did not start")
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish after canceling commands")
	}
	<-requestDone
	assertProcessStopped(t, pid)
}
