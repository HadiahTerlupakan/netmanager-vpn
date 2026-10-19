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

// pushPeer registers the router on a hub and records the outcome. A failure is
// not returned: the row stays pending and SyncPending retries it. The router
// and its link are re-read first because callers work from snapshots: pushing
// for a router deleted or unassigned since would re-register a revoked peer.
func (c *Core) pushPeer(ctx context.Context, rt store.Router, h store.Hub) {
	if c.linkState(rt.ID, h.ID) != store.SyncStatePending {
		return
	}
	c.register(ctx, rt, h)
}

// register upserts the router's peer on the hub and marks the link synced. A
// link gone by then was revoked while the push was in flight, so the peer is
// taken back off.
func (c *Core) register(ctx context.Context, rt store.Router, h store.Hub) {
	if err := c.hubs.UpsertPeer(ctx, h, rt.PublicKey, rt.Address); err != nil {
		slog.Warn("router peer not registered", "router", rt.ID, "hub", h.ID, "err", err)
		return
	}
	err := c.st.UpdateRouterHubSyncState(rt.ID, h.ID, store.SyncStateSynced)
	if errors.Is(err, store.ErrNotFound) {
		if derr := c.hubs.DeletePeer(ctx, h, rt.PublicKey); derr != nil {
			slog.Warn("revoked router peer not undone", "router", rt.ID, "hub", h.ID, "err", derr)
		}
		return
	}
	if err != nil {
		slog.Warn("router sync state not recorded", "router", rt.ID, "hub", h.ID, "err", err)
	}
}

// linkState re-reads the sync state of the router's link to the hub; it is
// empty when the router is gone or no longer lists the hub.
func (c *Core) linkState(routerID, hubID string) string {
	if _, err := c.st.GetRouter(routerID); err != nil {
		return ""
	}
	links, err := c.st.ListRouterHubs(routerID)
	if err != nil {
		return ""
	}
	for _, l := range links {
		if l.HubID == hubID {
			return l.SyncState
		}
	}
	return ""
}

// prune lists the hub's peers before reading the registry: a router registered
// in between is then in the registry snapshot and is kept. Reading in the
// other order would delete peers that were created a moment ago. A synced
// router missing from the list was lost on the hub (a restore, a hand
// reinstall) and is pushed again; pending ones are retryPending's.
func (c *Core) prune(ctx context.Context, h store.Hub) error {
	peers, err := c.hubs.Peers(ctx, h)
	if err != nil {
		slog.Warn("hub peers not listed for prune", "hub", h.ID, "err", err)
		return nil
	}
	assigned, err := c.routersOn(h.ID)
	if err != nil {
		return err
	}
	have := make(map[string]bool, len(peers))
	for _, p := range peers {
		have[p.PublicKey] = true
		if _, ok := assigned[p.PublicKey]; ok {
			continue
		}
		if err := c.hubs.DeletePeer(ctx, h, p.PublicKey); err != nil {
			slog.Warn("stray hub peer not removed", "hub", h.ID, "err", err)
		}
	}
	for pub, rt := range assigned {
		if !have[pub] && c.linkState(rt.ID, h.ID) == store.SyncStateSynced {
			c.register(ctx, rt, h)
		}
	}
	return nil
}

// routersOn maps the public key of every router listing the hub to the router.
func (c *Core) routersOn(hubID string) (map[string]store.Router, error) {
	routers, err := c.st.ListRouters()
	if err != nil {
		return nil, err
	}
	out := map[string]store.Router{}
	for _, rt := range routers {
		links, err := c.st.ListRouterHubs(rt.ID)
		if err != nil {
			return nil, err
		}
		for _, l := range links {
			if l.HubID == hubID {
				out[rt.PublicKey] = rt
			}
		}
	}
	return out, nil
}
