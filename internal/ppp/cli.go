package ppp

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	cliAddr    = "127.0.0.1:2001"
	cliTimeout = 5 * time.Second
)

// cliSection is appended to the daemon configuration by the supervisor, the
// only holder of the password. A host-network hub shares 127.0.0.1 with every
// process on the host, so the CLI must not be open.
func cliSection(password string) string {
	return "\n[cli]\ntcp=" + cliAddr + "\npassword=" + password + "\n"
}

// Terminate ends the session at addr through accel-ppp's TCP CLI, spoken here
// rather than through accel-cmd so the password never sits on an argv.
//
// The protocol is line based: the first line is the password, a wrong one
// closes the connection; each later line is a command. "terminate" answers
// nothing on success, so "show version" follows it: exactly its one line back
// proves the password was taken and terminate raised no error. Closing the
// write side makes accel-ppp flush its replies and hang up.
func (s *Supervisor) Terminate(addr netip.Addr) error {
	c, err := net.DialTimeout("tcp", s.cliAddr, cliTimeout)
	if err != nil {
		return fmt.Errorf("ppp: accel-ppp cli: %w", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(cliTimeout)); err != nil {
		return fmt.Errorf("ppp: accel-ppp cli: %w", err)
	}
	req := s.cliPassword + "\nterminate ip " + addr.String() + "\nshow version\n"
	if _, err := io.WriteString(c, req); err != nil {
		return fmt.Errorf("ppp: accel-ppp cli: %w", err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		return fmt.Errorf("ppp: accel-ppp cli: %w", err)
	}
	reply, err := io.ReadAll(c)
	if err != nil {
		return fmt.Errorf("ppp: accel-ppp cli: %w", err)
	}
	if len(reply) == 0 {
		return fmt.Errorf("ppp: accel-ppp cli closed without answering: password refused")
	}
	if lines := strings.Split(strings.TrimSuffix(string(reply), "\r\n"), "\r\n"); len(lines) != 1 {
		return fmt.Errorf("ppp: terminate ip %s: %q", addr, lines[0])
	}
	return nil
}
