package hub

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/ppp"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/routeros"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

// PPPRuntime runs the L2TP/IPsec daemons; ppp.Supervisor is the real one.
type PPPRuntime interface {
	Apply(secrets, ipsec, daemon string) error
	Running() bool
	SecretsPath() string
}

// applyPPP never fails the reconcile: a broken PPP side must not keep wg-nm
// from being applied, the API from listening, or the core from pushing the
// PSK that fixes it. The error names peers and files, never a secret.
func (s *Service) applyPPP(cfg store.HubConfig, peers []store.Peer) {
	err := s.reconcilePPP(cfg, peers)
	s.pppFailed.Store(err != nil)
	if err != nil {
		slog.Error("hub: PPP not applied, serving WireGuard only", "err", err)
	}
}

// endReplacedLogin ends a session still up on the login an upsert just
// replaced at the same address; the sweep in reconcilePPP sees only
// addresses, so it keeps such a session. It runs only after chap-secrets was
// rewritten, or the router would log in again on the old credentials.
func (s *Service) endReplacedLogin(prev store.Peer, spec PeerSpec) {
	if s.sessions == nil || s.pppFailed.Load() || prev.Protocol != routeros.ProtocolL2TP ||
		spec.Protocol != routeros.ProtocolL2TP || prev.Address != spec.Address {
		return
	}
	if prev.PPPUser == spec.PPPUser {
		old, err := s.box.Open(prev.PPPPassword)
		if err == nil && subtle.ConstantTimeCompare([]byte(old), []byte(spec.PPPPassword)) == 1 {
			return
		}
	}
	live, err := s.sessions.Live()
	if err != nil {
		slog.Error("hub: list PPP sessions", "err", err)
		return
	}
	if !live[prev.Address] {
		return
	}
	if err := s.sessions.Terminate(prev.Address); err != nil {
		slog.Error("hub: end PPP session on replaced login", "addr", prev.Address, "err", err)
	}
}

// reconcilePPP hands the daemons their configuration, then ends every session
// whose address no longer belongs to an L2TP peer. The order matters: the
// router redials within seconds, so its login must be gone first. Without a
// PSK there is nothing to serve and the daemons stay down.
func (s *Service) reconcilePPP(cfg store.HubConfig, peers []store.Peer) error {
	if s.ppp == nil || cfg.IPsecPSK == "" {
		return nil
	}
	psk, err := s.box.Open(cfg.IPsecPSK)
	if err != nil {
		return fmt.Errorf("hub: open IPsec PSK: %w", err)
	}
	ipsec, err := ppp.RenderIPsec(psk, cfg.IPsecLocalID)
	if err != nil {
		return fmt.Errorf("hub: %w", err)
	}
	secrets, err := ppp.RenderSecrets(peers, s.box.Open)
	if err != nil {
		return fmt.Errorf("hub: %w", err)
	}
	daemon := ppp.RenderDaemon(cfg.BackhaulAddr, s.ppp.SecretsPath())
	if err := s.ppp.Apply(secrets, ipsec, daemon); err != nil {
		return fmt.Errorf("hub: apply PPP: %w", err)
	}
	return s.endStraySessions(peers)
}

// endStraySessions terminates only sessions that are up. accel-cmd's
// "terminate ip" also matches a session that has no address yet, so calling it
// for an address with no session could end some other router's login.
func (s *Service) endStraySessions(peers []store.Peer) error {
	live, err := s.sessions.Live()
	if err != nil {
		return fmt.Errorf("hub: list PPP sessions: %w", err)
	}
	for _, p := range peers {
		if p.Protocol == routeros.ProtocolL2TP {
			delete(live, p.Address)
		}
	}
	var errs []error
	for addr := range live {
		if err := s.sessions.Terminate(addr); err != nil {
			errs = append(errs, fmt.Errorf("hub: end PPP session %s: %w", addr, err))
		}
	}
	return errors.Join(errs...)
}

// liveSessions returns nil when the list cannot be read: L2TP peers then show
// no handshake, and WireGuard peers are still reported.
func (s *Service) liveSessions() map[netip.Addr]bool {
	if s.sessions == nil {
		return nil
	}
	live, err := s.sessions.Live()
	if err != nil {
		slog.Error("hub: list PPP sessions", "err", err)
		return nil
	}
	return live
}

func stampIf(live bool, now time.Time) *time.Time {
	if !live {
		return nil
	}
	return &now
}

// SetIPsec stores the PSK and the hub's IKE identity and applies them. The
// same values change nothing, so the core's periodic push reloads nothing.
func (s *Service) SetIPsec(psk, localID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.st.LoadHubConfig()
	if err != nil {
		return err
	}
	if cfg.IPsecPSK != "" && cfg.IPsecLocalID == localID {
		old, err := s.box.Open(cfg.IPsecPSK)
		if err == nil && subtle.ConstantTimeCompare([]byte(old), []byte(psk)) == 1 {
			return nil
		}
	}
	sealed, err := s.box.Seal(psk)
	if err != nil {
		return err
	}
	if err := s.st.SaveHubIPsec(sealed, localID); err != nil {
		return err
	}
	return s.reconcile()
}

// Protocols lists what routers can reach this hub with. L2TP counts only once
// the host has PPP, a PSK is stored, the last apply succeeded, and both
// daemons are up.
func (s *Service) Protocols() ([]string, error) {
	out := []string{routeros.ProtocolWireGuard}
	if s.ppp == nil || s.pppFailed.Load() || !s.ppp.Running() {
		return out, nil
	}
	cfg, err := s.st.LoadHubConfig()
	if err != nil {
		return nil, err
	}
	if cfg.IPsecPSK != "" {
		out = append(out, routeros.ProtocolL2TP)
	}
	return out, nil
}
