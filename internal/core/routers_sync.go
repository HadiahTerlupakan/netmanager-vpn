package core

import (
	"context"
	"errors"
	"log/slog"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/routeros"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

// SyncPending gives each online hub its IPsec key and records its protocols,
// retries peers a hub missed, then prunes peers no router owns. The
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
		if err := c.syncHubIPsec(ctx, h); err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, err)
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
// not returned: the row stays pending and SyncPending retries it.
func (c *Core) pushPeer(ctx context.Context, rt store.Router, h store.Hub) {
	c.pushIf(ctx, rt.ID, h, store.SyncStatePending)
}

func (c *Core) pushIf(ctx context.Context, routerID string, h store.Hub, state string) {
	c.protoMu.Lock()
	defer c.protoMu.Unlock()
	c.pushIfLocked(ctx, routerID, h, state)
}

// pushIfLocked pushes the router as it is stored now, if its link to the hub
// is in state. Callers work from snapshots: pushing for a router deleted or
// unassigned since would re-register a revoked peer, and pushing an older row
// would put the hub back on a protocol the router has left.
func (c *Core) pushIfLocked(ctx context.Context, routerID string, h store.Hub, state string) {
	rt, got := c.linkState(routerID, h.ID)
	if got != state {
		return
	}
	c.register(ctx, rt, h)
}

// register upserts the router's peer on the hub and marks the link synced. A
// link gone by then was revoked while the push was in flight, so the peer is
// taken back off.
func (c *Core) register(ctx context.Context, rt store.Router, h store.Hub) {
	spec, err := c.peerSpec(rt)
	if err != nil {
		slog.Warn("router peer not built", "router", rt.ID, "err", err)
		return
	}
	if err := c.hubs.UpsertPeer(ctx, h, spec); err != nil {
		slog.Warn("router peer not registered", "router", rt.ID, "hub", h.ID, "err", err)
		return
	}
	err = c.st.UpdateRouterHubSyncState(rt.ID, h.ID, store.SyncStateSynced)
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

// peerSpec is the router as a hub carries it. A WireGuard peer carries no PPP
// login even when the router keeps one from an earlier L2TP spell.
func (c *Core) peerSpec(rt store.Router) (PeerSpec, error) {
	spec := PeerSpec{PublicKey: rt.PublicKey, Address: rt.Address, Protocol: routerProtocol(rt)}
	if spec.Protocol != routeros.ProtocolL2TP {
		return spec, nil
	}
	pass, err := c.box.Open(rt.PPPPassword)
	if err != nil {
		return PeerSpec{}, err
	}
	spec.PPPUser, spec.PPPPassword = rt.PPPUser, pass
	return spec, nil
}

// linkState re-reads the router and the sync state of its link to the hub;
// the state is empty when the router is gone or no longer lists the hub.
func (c *Core) linkState(routerID, hubID string) (store.Router, string) {
	rt, err := c.st.GetRouter(routerID)
	if err != nil {
		return store.Router{}, ""
	}
	links, err := c.st.ListRouterHubs(routerID)
	if err != nil {
		return store.Router{}, ""
	}
	for _, l := range links {
		if l.HubID == hubID {
			return rt, l.SyncState
		}
	}
	return store.Router{}, ""
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
		if !have[pub] {
			c.pushIf(ctx, rt.ID, h, store.SyncStateSynced)
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
