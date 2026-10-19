//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type iptables struct{}

// NewIPTables returns an IPTables that execs the iptables binary. -w waits for
// the xtables lock, which Docker holds while it rewrites its own rules.
func NewIPTables() IPTables { return iptables{} }

func (iptables) Run(args ...string) (bool, error) {
	cmd := exec.Command("iptables", append([]string{"-w"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return false, nil
	default:
		return false, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
}
