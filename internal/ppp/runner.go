package ppp

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Command is one program invocation; Env is added to the hub's environment.
type Command struct {
	Path string
	Args []string
	Env  []string
}

// Process is a started long-running command. Stop asks it to exit (SIGTERM);
// Kill does not ask.
type Process interface {
	Wait() error
	Stop() error
	Kill() error
}

// Runner starts daemons and runs one-shot commands; tests replace it so no
// real binary is executed.
type Runner interface {
	Start(c Command) (Process, error)
	Run(c Command) error
}

// ExecRunner runs commands as child processes. Daemons log to the hub's own
// stdout and stderr, so their lines land in the container log.
type ExecRunner struct{}

// Start launches c and returns without waiting for it.
func (ExecRunner) Start(c Command) (Process, error) {
	cmd := exec.Command(c.Path, c.Args...)
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return execProcess{cmd}, nil
}

// Run runs c to completion; a failure carries the command's output, which for
// swanctl and accel-cmd names connections and addresses but never a secret.
func (ExecRunner) Run(c Command) error {
	cmd := exec.Command(c.Path, c.Args...)
	cmd.Env = append(os.Environ(), c.Env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", c.Path, err, bytes.TrimSpace(out))
	}
	return nil
}

type execProcess struct{ cmd *exec.Cmd }

func (p execProcess) Wait() error { return p.cmd.Wait() }
func (p execProcess) Stop() error { return p.cmd.Process.Signal(syscall.SIGTERM) }
func (p execProcess) Kill() error { return p.cmd.Process.Kill() }
