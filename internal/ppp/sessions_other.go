//go:build !linux

package ppp

import (
	"errors"
	"net/netip"
)

// errUnsupported keeps development on macOS building; PPP sessions only exist
// on the Linux hosts the hub runs on.
var errUnsupported = errors.New("ppp sessions require linux")

type unsupported struct{}

// NewLinuxSessions returns a stand-in that fails every call; the real
// implementation is in sessions_linux.go.
func NewLinuxSessions(netip.Addr, *Supervisor) Sessions {
	return unsupported{}
}

func (unsupported) Live() (map[netip.Addr]bool, error) { return nil, errUnsupported }

func (unsupported) Terminate(netip.Addr) error { return errUnsupported }
