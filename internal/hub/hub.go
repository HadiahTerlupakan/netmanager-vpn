// Package hub runs a regional hub: routers connect to wg-nm and the hub
// tunnels back to the core over wg-up, routing rather than translating.
package hub

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/firewall"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/joinbundle"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/ppp"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/routeros"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/secret"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/wgdevice"
)

const (
	ifaceUp = "wg-up"
	ifaceNM = "wg-nm"
	// defaultNMPort is wg-nm's port when the join bundle predates carrying it.
	defaultNMPort  = 51821
	upMTU          = 1380 // leaves room for the router tunnel's own overhead inside wg-up
	nmMTU          = 1420
	coreKeepalive  = 25 * time.Second
	backhaulPrefix = 24
	ipForwardKey   = "net.ipv4.ip_forward"
)

// coreAllowedIPs are the backhaul and admin subnets reachable through the core.
var coreAllowedIPs = []string{"10.99.0.0/24", "10.99.128.0/24"}

// Options override the clock, the sysctl writer and iptables; zero values use
// the real ones. Sessions and PPP add L2TP/IPsec; left nil, as in tests and on
// hosts without /dev/ppp, the hub serves WireGuard only.
type Options struct {
	Now      func() time.Time
	Sysctl   func(key, value string) error
	IPTables firewall.IPTables
	Sessions ppp.Sessions
	PPP      PPPRuntime
}

// Service owns the hub's configuration and keeps the kernel in line with it.
type Service struct {
	dev    wgdevice.Device
	st     *store.Store
	fw     firewall.Applier
	ipt    firewall.IPTables
	box    *secret.Box
	now    func() time.Time
	sysctl func(string, string) error
	// sessions and ppp are both set or both nil.
	sessions ppp.Sessions
	ppp      PPPRuntime
	// pppFailed is set while the last PPP apply failed; L2TP is then not
	// offered, and WireGuard carries on regardless.
	pppFailed atomic.Bool
	mu        sync.Mutex
}

// PeerStatus is a router peer with its live counters. The JSON shape is relied
// on by the core.
type PeerStatus struct {
	PublicKey       string     `json:"publicKey"`
	Address         string     `json:"address"`
	LastHandshakeAt *time.Time `json:"lastHandshakeAt"`
	RxBytes         int64      `json:"rxBytes"`
	TxBytes         int64      `json:"txBytes"`
}

// New builds a Service.
func New(dev wgdevice.Device, st *store.Store, fw firewall.Applier, box *secret.Box, opts Options) *Service {
	s := &Service{dev: dev, st: st, fw: fw, ipt: opts.IPTables, box: box, now: opts.Now, sysctl: opts.Sysctl,
		sessions: opts.Sessions, ppp: opts.PPP}
	if s.sessions == nil || s.ppp == nil {
		s.sessions, s.ppp = nil, nil
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.sysctl == nil {
		s.sysctl = writeSysctl
	}
	if s.ipt == nil {
		s.ipt = firewall.NewIPTables()
	}
	return s
}

// Join stores the bundle's configuration and brings the interfaces up.
func (s *Service) Join(b joinbundle.Bundle) error {
	if b.ExpiresAt.Before(s.now()) {
		return errors.New("hub: join bundle has expired")
	}
	addr, err := netip.ParseAddr(b.BackhaulAddr)
	if err != nil {
		return fmt.Errorf("hub: backhaul address: %w", err)
	}
	port := b.ListenPort
	if port == 0 {
		port = defaultNMPort
	}
	sealed, err := s.box.Seal(b.PrivateKey)
	if err != nil {
		return err
	}
	// A rejoin keeps the IPsec settings: the bundle does not carry them, and
	// dropping them would stop L2TP until the core next pushes them.
	prev, err := s.st.LoadHubConfig()
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	err = s.st.SaveHubConfig(store.HubConfig{
		CorePublicKey: b.CorePublicKey, CoreEndpoint: b.CoreEndpoint, BackhaulAddr: addr, ListenPort: port,
		APIToken: b.APIToken, PrivateKeyUp: sealed, PrivateKeyNM: sealed,
		IPsecPSK: prev.IPsecPSK, IPsecLocalID: prev.IPsecLocalID,
	})
	if err != nil {
		return err
	}
	return s.Reconcile()
}

// Reconcile applies the stored state. Everything is read before anything is
// applied so a failed read can never push an empty peer set onto the kernel.
func (s *Service) Reconcile() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reconcile()
}

// reconcile runs PPP before wg-nm: a router moving from L2TP to WireGuard
// still has its session's nmpppN holding its /32, and its login must be gone
// and the session ended before wg-nm can route it. A failed wg-nm apply
// still lets the firewall and forwarding through, so one router's trouble
// cannot leave the hub unfiltered.
func (s *Service) reconcile() error {
	cfg, err := s.st.LoadHubConfig()
	if err != nil {
		return fmt.Errorf("hub: load config: %w", err)
	}
	peers, err := s.st.ListPeers()
	if err != nil {
		return fmt.Errorf("hub: list peers: %w", err)
	}
	key, err := s.box.Open(cfg.PrivateKeyUp)
	if err != nil {
		return fmt.Errorf("hub: open private key: %w", err)
	}
	s.applyPPP(cfg, peers)
	if err := s.dev.Apply(upConfig(cfg, key)); err != nil {
		return fmt.Errorf("hub: apply %s: %w", ifaceUp, err)
	}
	nmErr := s.dev.Apply(nmConfig(cfg, key, peers))
	if errors.Is(nmErr, wgdevice.ErrRouteBusy) {
		// The session's link goes away a moment after it is ended; the next
		// pass routes the address.
		slog.Warn("hub: router address still on its PPP link, routed on a later pass", "err", nmErr)
		nmErr = nil
	}
	if err := s.applyHost(); err != nil {
		return err
	}
	if nmErr != nil {
		return fmt.Errorf("hub: apply %s: %w", ifaceNM, nmErr)
	}
	return nil
}

// applyHost installs the firewall and turns forwarding on. The PPP rules
// are installed only on a hub that can serve L2TP: they need kernel modules
// a WireGuard-only host may lack, and nft rejects the whole table without them.
func (s *Service) applyHost() error {
	pppEnabled := s.ppp != nil
	if err := s.fw.Apply(firewall.RenderHub(pppEnabled)); err != nil {
		return fmt.Errorf("hub: apply firewall: %w", err)
	}
	if err := firewall.EnsureDockerUserAccepts(s.ipt, firewall.HubDockerAccepts(pppEnabled)); err != nil {
		return fmt.Errorf("hub: docker forward accepts: %w", err)
	}
	if err := s.sysctl(ipForwardKey, "1"); err != nil {
		return fmt.Errorf("hub: enable forwarding: %w", err)
	}
	return nil
}

func upConfig(cfg store.HubConfig, key string) wgdevice.Config {
	return wgdevice.Config{
		InterfaceName: ifaceUp, PrivateKey: key, MTU: upMTU,
		Address: netip.PrefixFrom(cfg.BackhaulAddr, backhaulPrefix).String(),
		Peers: []wgdevice.PeerConfig{{
			PublicKey: cfg.CorePublicKey, AllowedIPs: coreAllowedIPs,
			Endpoint: cfg.CoreEndpoint, Keepalive: coreKeepalive,
		}},
	}
}

// nmConfig borrows the backhaul address as a /32: the Linux device requires an
// interface address, and a host route to it cannot shadow any router subnet.
// Only WireGuard peers belong here; an L2TP router's /32 is routed by the PPP
// daemon over its nmpppN, and a wg-nm route for it would take its traffic.
// wg-nm yields to such a link while a router's session is being ended.
func nmConfig(cfg store.HubConfig, key string, peers []store.Peer) wgdevice.Config {
	c := wgdevice.Config{
		InterfaceName: ifaceNM, PrivateKey: key, ListenPort: cfg.ListenPort, MTU: nmMTU,
		Address: netip.PrefixFrom(cfg.BackhaulAddr, 32).String(), YieldTo: ppp.LinkPrefix,
	}
	for _, p := range peers {
		if p.Protocol != routeros.ProtocolWireGuard {
			continue
		}
		c.Peers = append(c.Peers, wgdevice.PeerConfig{
			PublicKey: p.PublicKey, AllowedIPs: []string{netip.PrefixFrom(p.Address, 32).String()},
		})
	}
	return c
}

// ErrAddressInUse means another public key already holds the address; the
// kernel would give it to only one of them and black-hole the other.
var ErrAddressInUse = errors.New("hub: address already held by another peer")

// PeerSpec is a router as the core describes it. PPPPassword is plaintext and
// is sealed before it is stored.
type PeerSpec struct {
	PublicKey   string
	Address     netip.Addr
	Protocol    string
	PPPUser     string
	PPPPassword string
}

// UpsertPeer records a router and applies it. The check and the write share
// one lock so two concurrent requests cannot both claim an address. A session
// the change leaves without a login, as when the router moves to WireGuard,
// is ended by the reconcile; one on replaced credentials at the same address
// is ended after it.
func (s *Service) UpsertPeer(spec PeerSpec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	peers, err := s.st.ListPeers()
	if err != nil {
		return err
	}
	var prev store.Peer
	for _, p := range peers {
		if p.Address == spec.Address && p.PublicKey != spec.PublicKey {
			return ErrAddressInUse
		}
		if p.PublicKey == spec.PublicKey {
			prev = p
		}
	}
	peer := store.Peer{PublicKey: spec.PublicKey, Address: spec.Address, Protocol: spec.Protocol, PPPUser: spec.PPPUser}
	if spec.PPPPassword != "" {
		if peer.PPPPassword, err = s.box.Seal(spec.PPPPassword); err != nil {
			return err
		}
	}
	if err := s.st.UpsertPeer(peer); err != nil {
		return err
	}
	if err := s.reconcile(); err != nil {
		return err
	}
	s.endReplacedLogin(prev, spec)
	return nil
}

// DeletePeer removes a router and applies the change, ending its PPP session.
func (s *Service) DeletePeer(pub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.st.DeletePeer(pub); err != nil {
		return err
	}
	return s.reconcile()
}

// PeerStatuses lists stored peers with the kernel's counters; a peer the
// kernel has not reported yet shows zeros. An L2TP peer with a session up is
// stamped as handshaking now, which is what the core's hub choice reads.
func (s *Service) PeerStatuses() ([]PeerStatus, error) {
	peers, err := s.st.ListPeers()
	if err != nil {
		return nil, err
	}
	live, err := s.dev.Status(ifaceNM)
	if err != nil {
		return nil, err
	}
	sessions := s.liveSessions()
	now := s.now()
	byKey := make(map[string]wgdevice.PeerStatus, len(live))
	for _, l := range live {
		byKey[l.PublicKey] = l
	}
	out := make([]PeerStatus, 0, len(peers))
	for _, p := range peers {
		if p.Protocol != routeros.ProtocolWireGuard {
			out = append(out, PeerStatus{PublicKey: p.PublicKey, Address: p.Address.String(),
				LastHandshakeAt: stampIf(sessions[p.Address], now)})
			continue
		}
		l := byKey[p.PublicKey]
		out = append(out, PeerStatus{
			PublicKey: p.PublicKey, Address: p.Address.String(),
			LastHandshakeAt: l.LastHandshakeAt, RxBytes: l.RxBytes, TxBytes: l.TxBytes,
		})
	}
	return out, nil
}
