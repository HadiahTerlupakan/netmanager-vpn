package wgdevice

import (
	"fmt"
	"net"
)

// planRoutes decides which link routes the interface needs added and which of
// its existing destinations are stale. The kernel's allowed-ips do not create
// routes by themselves, and a route left behind by a deleted peer would
// blackhole that subnet.
func planRoutes(cfg Config, existing []*net.IPNet) (add []*net.IPNet, stale map[string]bool, err error) {
	wanted := make(map[string]*net.IPNet)
	for _, peer := range cfg.Peers {
		for _, entry := range peer.AllowedIPs {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, nil, fmt.Errorf("parse route %s: %w", entry, err)
			}
			wanted[network.String()] = network
		}
	}

	// The kernel installs a connected route for the interface's own address
	// when the link comes up. It belongs to no peer and must survive, or the
	// VPS loses its route to every peer's tunnel address. A peer listing that
	// same prefix (the core peer on wg-up lists 10.99.0.0/24) is already
	// routed by it, and adding it again fails with EEXIST.
	_, connected, err := net.ParseCIDR(cfg.Address)
	if err != nil {
		return nil, nil, fmt.Errorf("parse interface address %s: %w", cfg.Address, err)
	}
	delete(wanted, connected.String())

	stale = map[string]bool{}
	for _, dst := range existing {
		if dst == nil || dst.String() == connected.String() {
			continue
		}
		if _, keep := wanted[dst.String()]; keep {
			delete(wanted, dst.String())
			continue
		}
		stale[dst.String()] = true
	}
	for _, network := range wanted {
		add = append(add, network)
	}
	return add, stale, nil
}
