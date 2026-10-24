package ppp

import "net/netip"

// Sessions sees the PPP sessions the daemon holds and ends one.
type Sessions interface {
	// Live returns the router address of every session that is up.
	Live() (map[netip.Addr]bool, error)
	// Terminate ends the session at addr. The router dials again within
	// seconds, so its login must already be gone from chap-secrets.
	Terminate(addr netip.Addr) error
}

// terminateCommand is the spike's way to end one session, through the CLI the
// daemon configuration opens on 127.0.0.1:2001.
func terminateCommand(addr netip.Addr) Command {
	return Command{Path: accelCmd, Args: []string{"terminate", "ip", addr.String()}}
}
