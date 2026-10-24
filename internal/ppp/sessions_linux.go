//go:build linux

package ppp

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

type linuxSessions struct {
	gw  netip.Addr
	cli *Supervisor
}

// NewLinuxSessions reads the sessions whose hub end is gw from the kernel's
// PPP interfaces and ends them through the supervisor's CLI.
func NewLinuxSessions(gw netip.Addr, cli *Supervisor) Sessions {
	return linuxSessions{gw: gw, cli: cli}
}

// Live keys each session by its peer address: the router end, which
// chap-secrets bound to its login.
func (s linuxSessions) Live() (map[netip.Addr]bool, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("ppp: list links: %w", err)
	}
	var out []pppLink
	for _, l := range links {
		a := l.Attrs()
		if a.EncapType != "ppp" {
			continue
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("ppp: addresses of %s: %w", a.Name, err)
		}
		for _, ad := range addrs {
			pl := pppLink{name: a.Name, encap: a.EncapType, up: a.Flags&net.FlagUp != 0}
			pl.local, _ = netip.AddrFromSlice(ad.IP.To4())
			if ad.Peer != nil {
				pl.peer, _ = netip.AddrFromSlice(ad.Peer.IP.To4())
			}
			out = append(out, pl)
		}
	}
	return livePeers(out, s.gw), nil
}

func (s linuxSessions) Terminate(addr netip.Addr) error {
	return s.cli.Terminate(addr)
}
