package wgdevice

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
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

// addRoutes adds each route with add and carries on past one that fails, so a
// collision on one peer's address cannot leave every later peer unrouted.
// holder names the link that holds a route add was refused for.
//
// A route held by a yieldTo link (a PPP session the hub is ending as its
// router moves to WireGuard) is skipped, not replaced: the session's teardown
// is asynchronous, and a failed terminate leaves it up, so the link may still
// be carrying the router. Waiting costs a reconcile pass; RouteReplace would
// take the route from a link that still holds it. Any other collision fails
// loudly rather than hijack a route someone else put there.
func addRoutes(nets []*net.IPNet, yieldTo string, add func(*net.IPNet) error, holder func(*net.IPNet) string) error {
	var errs []error
	var busy []string
	for _, n := range nets {
		err := add(n)
		switch {
		case err == nil:
		case !errors.Is(err, syscall.EEXIST):
			errs = append(errs, fmt.Errorf("add route %s: %w", n, err))
		case yieldTo != "" && strings.HasPrefix(holder(n), yieldTo):
			busy = append(busy, n.String())
		default:
			errs = append(errs, fmt.Errorf("add route %s: already routed via another interface, remove the conflicting route or change the peer's subnet: %w", n, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if len(busy) > 0 {
		return fmt.Errorf("%w: %s", ErrRouteBusy, strings.Join(busy, ", "))
	}
	return nil
}
