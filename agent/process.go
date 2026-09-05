package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const outputDrainTimeout = 5 * time.Second

// The platform implementation waits only for the direct process. Pipe readers
// are managed separately so a shell that exits early cannot disable tree cleanup.
type runningCommand struct {
	stdout    *os.File
	stderr    *os.File
	wait      func() (int, error)
	terminate func() error
	close     func() error
}

func runCommand(ctx context.Context, command string, stdout, stderr io.Writer) (int, error) {
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	p, err := startCommand(command, commandEnvironment(os.Environ()))
	if err != nil {
		return -1, err
	}
	return runStartedCommand(ctx, p, stdout, stderr, outputDrainTimeout)
}

func runStartedCommand(ctx context.Context, p *runningCommand, stdout, stderr io.Writer, cleanupTimeout time.Duration) (int, error) {
	closeProcess := true
	defer func() {
		if closeProcess {
			_ = p.close()
		}
	}()
	defer p.stdout.Close()
	defer p.stderr.Close()
	var copying sync.WaitGroup
	copying.Add(2)
	go func() { defer copying.Done(); _, _ = io.Copy(stdout, p.stdout) }()
	go func() { defer copying.Done(); _, _ = io.Copy(stderr, p.stderr) }()
	type result struct {
		code int
		err  error
	}
	finished := make(chan result, 1)
	go func() {
		code, err := p.wait()
		finished <- result{code, err}
	}()
	var outcome result
	var err error
	select {
	case outcome = <-finished:
		// Clean up descendants even when their direct parent has already exited.
		err = p.terminate()
	case <-ctx.Done():
		err = p.terminate()
		timer := time.NewTimer(cleanupTimeout)
		select {
		case outcome = <-finished:
			outcome.err = errors.Join(outcome.err, ctx.Err())
		case <-timer.C:
			// A failed kill (for example a child that changed Unix credentials)
			// must not make HTTP and server shutdown wait indefinitely. Keep the
			// process handle valid until Wait finishes, especially on Windows.
			closeProcess = false
			go func() { <-finished; _ = p.close() }()
			_ = p.stdout.Close()
			_ = p.stderr.Close()
			outcome = result{-1, errors.Join(ctx.Err(), errors.New("process did not exit after cancellation"))}
		}
		timer.Stop()
	}
	if err != nil {
		outcome.code = -1
		outcome.err = errors.Join(outcome.err, err)
	}
	drained := make(chan struct{})
	go func() { copying.Wait(); close(drained) }()
	timer := time.NewTimer(cleanupTimeout)
	defer timer.Stop()
	select {
	case <-drained:
	case <-timer.C:
		// A process outside the group (for example a daemon using setsid) can
		// retain inherited pipes. It must not keep the HTTP request alive forever.
		_ = p.stdout.Close()
		_ = p.stderr.Close()
		<-drained
		outcome.code = -1
		outcome.err = errors.Join(outcome.err, errors.New("output pipes remained open after process cleanup"))
	}
	return outcome.code, outcome.err
}

// Relay configuration belongs to the control plane, not to diagnostic commands.
// Windows environment names are case-insensitive; use the same rule everywhere.
func commandEnvironment(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, item := range env {
		key, _, _ := strings.Cut(item, "=")
		if !strings.HasPrefix(strings.ToUpper(key), "RELAY_") {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

type commandPipes struct {
	in, outR, outW, errR, errW *os.File
}

func newCommandPipes() (*commandPipes, error) {
	p := &commandPipes{}
	var err error
	if p.in, err = os.Open(os.DevNull); err == nil {
		if p.outR, p.outW, err = os.Pipe(); err == nil {
			p.errR, p.errW, err = os.Pipe()
		}
	}
	if err != nil {
		p.close()
		return nil, err
	}
	return p, nil
}

func (p *commandPipes) closeChildEnds() {
	if p.in != nil {
		_ = p.in.Close()
	}
	if p.outW != nil {
		_ = p.outW.Close()
	}
	if p.errW != nil {
		_ = p.errW.Close()
	}
}

func (p *commandPipes) close() {
	p.closeChildEnds()
	if p.outR != nil {
		_ = p.outR.Close()
	}
	if p.errR != nil {
		_ = p.errR.Close()
	}
}
