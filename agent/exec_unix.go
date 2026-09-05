//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func startCommand(command string, env []string) (*runningCommand, error) {
	pipes, err := newCommandPipes()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("sh", "-c", command)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = pipes.in, pipes.outW, pipes.errW
	if err := cmd.Start(); err != nil {
		pipes.close()
		return nil, err
	}
	pipes.closeChildEnds()
	pid := cmd.Process.Pid
	return &runningCommand{
		stdout: pipes.outR,
		stderr: pipes.errR,
		wait: func() (int, error) {
			err := cmd.Wait()
			if cmd.ProcessState == nil {
				return -1, err
			}
			return cmd.ProcessState.ExitCode(), err
		},
		terminate: func() error {
			// This is independent of os/exec's context watcher and runs both at
			// the deadline and after normal shell exit, while descendants remain.
			if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
				fallback := cmd.Process.Kill()
				if errors.Is(fallback, os.ErrProcessDone) {
					fallback = nil
				}
				return errors.Join(err, fallback)
			}
			return nil
		},
		close: func() error { return nil },
	}, nil
}
