package core

import (
	"context"
	"errors"
	"log/slog"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

// SyncPending retries peers a hub missed, then prunes peers no router owns. The
// prune is what makes address reuse safe: a failed delete leaves a stale peer
// that would otherwise collide with the next router given that address.
func (c *Core) SyncPending(ctx context.Context) error {
	hubs, err := c.st.ListHubs()
	if err != nil {
		return err
	}
	var errs []error
	for _, h := range hubs {
		if h.Status != store.HubStatusOnline {
			continue
		}
		errs = append(errs, c.retryPending(ctx, h), c.prune(ctx, h))
	}
	return errors.Join(errs...)
}

func (c *Core) retryPending(ctx context.Context, h store.Hub) error {
	routers, err := c.st.ListRouters()
	if err != nil {
		return err
	}
	for _, rt := range routers {
		links, err := c.st.ListRouterHubs(rt.ID)
		if err != nil {
			return err
		}
		for _, l := range links {
			if l.HubID == h.ID && l.SyncState == store.SyncStatePending {
				c.pushPeer(ctx, rt, h)
			}
		}
	}
	return nil
}

// prune lists the hub's peers before reading the registry: a router registered
// in between is then in the registry snapshot and is kept. Reading in the
// other order would delete peers that were created a moment ago.
func (c *Core) prune(ctx context.Context, h store.Hub) error {
	peers, err := c.hubs.Peers(ctx, h)
	if err != nil {
		slog.Warn("hub peers not listed for prune", "hub", h.ID, "err", err)
		return nil
	}
	keep, err := c.routerKeysOn(h.ID)
	if err != nil {
		return err
	}
	for _, p := range peers {
		if keep[p.PublicKey] {
			continue
		}
		if err := c.hubs.DeletePeer(ctx, h, p.PublicKey); err != nil {
			slog.Warn("stray hub peer not removed", "hub", h.ID, "err", err)
		}
	}
	return nil
}

func (c *Core) routerKeysOn(hubID string) (map[string]bool, error) {
	routers, err := c.st.ListRouters()
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, rt := range routers {
		links, err := c.st.ListRouterHubs(rt.ID)
		if err != nil {
			return nil, err
		}
		for _, l := range links {
			if l.HubID == hubID {
				keep[rt.PublicKey] = true
			}
		}
	}
	return keep, nil
}
