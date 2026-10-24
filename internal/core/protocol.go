package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"slices"
	"sort"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/routeros"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

const (
	pppUserPrefix    = "nmvpn-"
	pppPasswordBytes = 24
	pskBytes         = 32
	// l2tpPort is IKE's port, which a RouterOS L2TP client always dials.
	l2tpPort = 500
)

// FirstServer is the hub a router tries first, with what it needs to dial
// it over its protocol.
type FirstServer struct {
	Protocol    string `json:"protocol"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	PublicKey   string `json:"publicKey,omitempty"`
	IPsecSecret string `json:"ipsecSecret,omitempty"`
}

// normalizeProtocol maps an omitted protocol to WireGuard and rejects any
// the routers cannot run.
func normalizeProtocol(p string) (string, error) {
	switch p {
	case "", routeros.ProtocolWireGuard:
		return routeros.ProtocolWireGuard, nil
	case routeros.ProtocolL2TP:
		return p, nil
	}
	return "", fmt.Errorf("%w: unknown protocol %q", ErrValidation, p)
}

// routerProtocol reads rows written before routers had a protocol as WireGuard.
func routerProtocol(rt store.Router) string {
	if rt.Protocol == "" {
		return routeros.ProtocolWireGuard
	}
	return rt.Protocol
}

func hubProtocols(h store.Hub) []string {
	if len(h.Protocols) == 0 {
		return []string{routeros.ProtocolWireGuard}
	}
	return h.Protocols
}

// requireSupport refuses a hub that cannot carry the protocol. An L2TP hub
// also needs a PSK here, or the core has no secret to give the router.
func requireSupport(h store.Hub, protocol string) error {
	if protocol == routeros.ProtocolWireGuard {
		return nil
	}
	if !slices.Contains(hubProtocols(h), protocol) {
		return fmt.Errorf("%w: hub %s does not serve %s", ErrValidation, h.Name, protocol)
	}
	if h.IPsecPSK == "" {
		return fmt.Errorf("%w: hub %s has no IPsec key yet", ErrValidation, h.Name)
	}
	return nil
}

// sealedRandom returns n random bytes, base64url without padding, sealed.
func (c *Core) sealedRandom(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return c.box.Seal(base64.RawURLEncoding.EncodeToString(raw))
}

// ensurePPP gives the router a PPP login once and keeps it for good, so a
// switch back to L2TP does not need the router's script re-pasted. rt may be
// stale: the store keeps whichever login was written first, and the row is
// re-read for it, protocol included.
func (c *Core) ensurePPP(rt store.Router) (store.Router, error) {
	if rt.PPPUser != "" && rt.PPPPassword != "" {
		return rt, nil
	}
	sealed, err := c.sealedRandom(pppPasswordBytes)
	if err != nil {
		return store.Router{}, err
	}
	if err := c.st.SetRouterPPPLogin(rt.ID, pppUserPrefix+rt.ID, sealed); err != nil {
		return store.Router{}, err
	}
	return c.st.GetRouter(rt.ID)
}

// ensureHubPSK gives a hub created before L2TP its PSK.
func (c *Core) ensureHubPSK(h store.Hub) (store.Hub, error) {
	if h.IPsecPSK != "" {
		return h, nil
	}
	sealed, err := c.sealedRandom(pskBytes)
	if err != nil {
		return store.Hub{}, err
	}
	if err := c.st.UpdateHubPSK(h.ID, sealed); err != nil {
		return store.Hub{}, err
	}
	h.IPsecPSK = sealed
	return h, nil
}

// routerHubs returns the router's hubs in priority order.
func (c *Core) routerHubs(id string) ([]store.Hub, error) {
	links, err := c.st.ListRouterHubs(id)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(links, func(i, j int) bool { return links[i].Priority < links[j].Priority })
	hubs := make([]store.Hub, 0, len(links))
	for _, l := range links {
		h, err := c.st.GetHub(l.HubID)
		if err != nil {
			return nil, err
		}
		hubs = append(hubs, h)
	}
	return hubs, nil
}

// prepareProtocol checks that every hub of the router serves the protocol
// and, for L2TP, makes sure the router has its login.
func (c *Core) prepareProtocol(id, protocol string) (store.Router, string, error) {
	protocol, err := normalizeProtocol(protocol)
	if err != nil {
		return store.Router{}, "", err
	}
	rt, err := c.st.GetRouter(id)
	if err != nil {
		return store.Router{}, "", err
	}
	hubs, err := c.routerHubs(id)
	if err != nil {
		return store.Router{}, "", err
	}
	for _, h := range hubs {
		if err := requireSupport(h, protocol); err != nil {
			return store.Router{}, "", err
		}
	}
	if protocol == routeros.ProtocolL2TP {
		rt, err = c.ensurePPP(rt)
	}
	return rt, protocol, err
}

// ProtocolScript renders the full script for protocol without switching the
// router or touching its hubs: the operator pastes it first, then switches.
func (c *Core) ProtocolScript(id, protocol string) (string, error) {
	unlock := c.routerMu.lock(id)
	rt, protocol, err := c.prepareProtocol(id, protocol)
	unlock()
	if err != nil {
		return "", err
	}
	in, err := c.routerInputFor(rt, protocol)
	if err != nil {
		return "", err
	}
	if err := in.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrValidation, err)
	}
	return routeros.RenderFull(in), nil
}

// SetRouterProtocol switches the router's protocol and re-registers it on
// every online hub; offline ones are left to SyncPending. Every link goes
// pending before the protocol is written, so a failure part-way leaves no hub
// marked synced on the old protocol. The current protocol is a no-op even if
// a hub has since stopped serving it.
func (c *Core) SetRouterProtocol(ctx context.Context, id, protocol string) (RouterView, error) {
	defer c.routerMu.lock(id)()
	same, err := c.hasProtocol(id, protocol)
	if err != nil {
		return RouterView{}, err
	}
	if same {
		return c.GetRouter(id)
	}
	rt, protocol, err := c.prepareProtocol(id, protocol)
	if err != nil {
		return RouterView{}, err
	}
	hubs, err := c.routerHubs(id)
	if err != nil {
		return RouterView{}, err
	}
	for _, h := range hubs {
		if err := c.st.UpdateRouterHubSyncState(id, h.ID, store.SyncStatePending); err != nil {
			return RouterView{}, err
		}
	}
	if err := c.st.SetRouterProtocol(id, protocol, rt.PPPUser, rt.PPPPassword); err != nil {
		return RouterView{}, err
	}
	for _, h := range hubs {
		if h.Status == store.HubStatusOnline {
			c.pushIfLocked(ctx, id, h, store.SyncStatePending)
		}
	}
	return c.GetRouter(id)
}

func (c *Core) hasProtocol(id, protocol string) (bool, error) {
	protocol, err := normalizeProtocol(protocol)
	if err != nil {
		return false, err
	}
	rt, err := c.st.GetRouter(id)
	if err != nil {
		return false, err
	}
	return routerProtocol(rt) == protocol, nil
}

// FirstServer returns the router's highest-priority hub.
func (c *Core) FirstServer(id string) (FirstServer, error) {
	rt, err := c.st.GetRouter(id)
	if err != nil {
		return FirstServer{}, err
	}
	hubs, err := c.routerHubs(id)
	if err != nil {
		return FirstServer{}, err
	}
	if len(hubs) == 0 {
		return FirstServer{}, fmt.Errorf("%w: router has no hubs", ErrValidation)
	}
	s, err := c.server(hubs[0], routerProtocol(rt))
	if err != nil {
		return FirstServer{}, err
	}
	return FirstServer{Protocol: routerProtocol(rt), Host: s.Host, Port: s.Port,
		PublicKey: s.PublicKey, IPsecSecret: s.IPsecSecret}, nil
}

// server is a hub as a router of the given protocol dials it.
func (c *Core) server(h store.Hub, protocol string) (routeros.Server, error) {
	if protocol != routeros.ProtocolL2TP {
		return routeros.Server{Host: h.PublicHost, Port: h.ListenPort, PublicKey: h.PublicKey}, nil
	}
	s := routeros.Server{Host: h.PublicHost, Port: l2tpPort}
	if h.IPsecPSK == "" {
		return s, nil
	}
	psk, err := c.box.Open(h.IPsecPSK)
	if err != nil {
		return routeros.Server{}, err
	}
	s.IPsecSecret = psk
	return s, nil
}

// syncHubIPsec gives the hub its PSK and records what it serves. A hub that
// cannot be reached is only logged: its WireGuard peers still get synced.
func (c *Core) syncHubIPsec(ctx context.Context, h store.Hub) error {
	h, err := c.ensureHubPSK(h)
	if err != nil {
		return err
	}
	psk, err := c.box.Open(h.IPsecPSK)
	if err != nil {
		return err
	}
	// Without the key this pass, an L2TP the hub reports may rest on a
	// different PSK, so the stored protocols are kept as they are.
	if err := c.hubs.SetIPsecPSK(ctx, h, psk); err != nil {
		slog.Warn("hub IPsec key not pushed", "hub", h.ID, "err", err)
		return nil
	}
	info, err := c.hubs.Info(ctx, h)
	if err != nil {
		slog.Warn("hub info not read", "hub", h.ID, "err", err)
		return nil
	}
	if len(info.Protocols) == 0 {
		info.Protocols = []string{routeros.ProtocolWireGuard}
	}
	return c.st.UpdateHubProtocols(h.ID, info.Protocols)
}
