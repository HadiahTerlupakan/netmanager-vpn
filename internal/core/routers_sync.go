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
	routers, err := c.st.ListRouters()
	if err != nil {
		return err
	}
	hubs, err := c.st.ListHubs()
	if err != nil {
		return err
	}
	online := map[string]store.Hub{}
	for _, h := range hubs {
		if h.Status == store.HubStatusOnline {
			online[h.ID] = h
		}
	}
	wanted := map[string]map[string]bool{}
	for _, rt := range routers {
		links, err := c.st.ListRouterHubs(rt.ID)
		if err != nil {
			return err
		}
		for _, l := range links {
			if wanted[l.HubID] == nil {
				wanted[l.HubID] = map[string]bool{}
			}
			wanted[l.HubID][rt.PublicKey] = true
			if h, ok := online[l.HubID]; ok && l.SyncState == store.SyncStatePending {
				c.pushPeer(ctx, rt, h)
			}
		}
	}
	var errs []error
	for _, h := range hubs {
		if _, ok := online[h.ID]; ok {
			errs = append(errs, c.prune(ctx, h, wanted[h.ID]))
		}
	}
	return errors.Join(errs...)
}

func (c *Core) prune(ctx context.Context, h store.Hub, keep map[string]bool) error {
	peers, err := c.hubs.Peers(ctx, h)
	if err != nil {
		slog.Warn("hub peers not listed for prune", "hub", h.ID, "err", err)
		return nil
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
