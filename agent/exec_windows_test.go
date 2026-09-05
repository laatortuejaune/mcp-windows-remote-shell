//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestWindowsNativeLayouts(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		if unsafe.Sizeof(jobExtendedLimitInformation{}) != 144 || unsafe.Sizeof(startupInfoEx{}) != 112 {
			t.Fatal("Windows SDK structure layout mismatch")
		}
	}
	block, err := windowsEnvironmentBlock([]string{"z=last", "A0=second", "A=first"})
	if err != nil || syscall.UTF16ToString(block) != "A=first" || block[len(block)-1] != 0 || block[len(block)-2] != 0 {
		t.Fatalf("invalid Unicode environment block: %v", err)
	}
}

func TestWindowsHelperProcess(t *testing.T) {
	mode := ""
	for i, arg := range os.Args {
		if arg == "--relay-agent-helper" && i+1 < len(os.Args) {
			mode = os.Args[i+1]
		}
	}
	if mode == "" {
		return
	}
	switch mode {
	case "in-job":
		current, _ := syscall.GetCurrentProcess()
		var inJob int32
		ok, _, _ := kernel32.NewProc("IsProcessInJob").Call(uintptr(current), 0, uintptr(unsafe.Pointer(&inJob)))
		if ok == 0 || inJob == 0 {
			os.Exit(2)
		}
		fmt.Print("in-job")
	case "sleep":
		time.Sleep(30 * time.Second)
	case "spawn", "spawn-and-wait":
		child := exec.Command(os.Args[0], "-test.run=^TestWindowsHelperProcess$", "--", "--relay-agent-helper", "sleep")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(3)
		}
		fmt.Println(child.Process.Pid)
		if mode == "spawn-and-wait" {
			_ = child.Wait()
		}
	default:
		os.Exit(4)
	}
	os.Exit(0)
}

func windowsHelperCommand(mode string) string {
	return `"` + os.Args[0] + `" -test.run=^TestWindowsHelperProcess$ -- --relay-agent-helper ` + mode
}

func TestWindowsCommandStartsInJob(t *testing.T) {
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	code, err := runCommand(ctx, windowsHelperCommand("in-job"), &stdout, &stderr)
	if code != 0 || err != nil || stdout.String() != "in-job" {
		t.Fatalf("command did not start in job: code=%d err=%v stdout=%q stderr=%q", code, err, &stdout, &stderr)
	}
}

func TestWindowsQuotedPathsAndFilteredEnvironment(t *testing.T) {
	file := filepath.Join(t.TempDir(), "path with spaces.txt")
	if err := os.WriteFile(file, []byte("quoted-path-ok"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELAY_TOKEN", "test-secret-do-not-inherit")
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := `if defined RELAY_TOKEN (exit /b 3) else type "` + file + `"`
	code, err := runCommand(ctx, command, &stdout, &stderr)
	if code != 0 || err != nil || stdout.String() != "quoted-path-ok" {
		t.Fatalf("quoted path or environment failed: code=%d err=%v stderr=%q", code, err, &stderr)
	}
}

func TestWindowsCommandTreeCleanup(t *testing.T) {
	for _, mode := range []string{"spawn", "spawn-and-wait"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var stdout, stderr bytes.Buffer
			_, err := runCommand(ctx, windowsHelperCommand(mode), &stdout, &stderr)
			if mode == "spawn" && err != nil {
				t.Fatal(err)
			}
			if mode == "spawn-and-wait" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected command timeout, got %v", err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(stdout.String()))
			if err != nil || pid <= 0 {
				t.Fatalf("missing test child PID: %q, stderr=%q", &stdout, &stderr)
			}
			process, err := syscall.OpenProcess(syscall.SYNCHRONIZE|syscall.PROCESS_TERMINATE, false, uint32(pid))
			if errors.Is(err, syscall.Errno(87)) { // ERROR_INVALID_PARAMETER
				return // The terminated process has already disappeared.
			}
			if err != nil {
				t.Fatal(err)
			}
			defer syscall.CloseHandle(process)
			state, err := syscall.WaitForSingleObject(process, 1000)
			if err != nil || state != syscall.WAIT_OBJECT_0 {
				_ = syscall.TerminateProcess(process, 1)
				t.Fatalf("command descendant survived job cleanup: state=%d err=%v", state, err)
			}
		})
	}
}
