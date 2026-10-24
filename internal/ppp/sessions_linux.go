//go:build linux

package ppp

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

type linuxSessions struct{ run Runner }

// NewLinuxSessions reads sessions from the kernel's PPP interfaces and ends
// them through run.
func NewLinuxSessions(run Runner) Sessions {
	return linuxSessions{run: run}
}

// Live lists the links of type ppp that are up, keyed by their peer address:
// the session's router end, which chap-secrets bound to its login.
func (linuxSessions) Live() (map[netip.Addr]bool, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("ppp: list links: %w", err)
	}
	live := map[netip.Addr]bool{}
	for _, l := range links {
		a := l.Attrs()
		if a.EncapType != "ppp" || a.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("ppp: addresses of %s: %w", a.Name, err)
		}
		for _, ad := range addrs {
			if ad.Peer == nil {
				continue
			}
			if p, ok := netip.AddrFromSlice(ad.Peer.IP.To4()); ok {
				live[p] = true
			}
		}
	}
	return live, nil
}

func (s linuxSessions) Terminate(addr netip.Addr) error {
	return s.run.Run(terminateCommand(addr))
}
