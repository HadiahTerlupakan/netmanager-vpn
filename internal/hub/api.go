package hub

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/ipam"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/ppp"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/routeros"
)

const maxBodyBytes = 4 << 10

type putPeerRequest struct {
	Address     string `json:"address"`
	Protocol    string `json:"protocol"`
	PPPUsername string `json:"pppUsername"`
	PPPPassword string `json:"pppPassword"`
}

type putIPsecRequest struct {
	PSK     string `json:"psk"`
	LocalID string `json:"localId"`
}

type infoResponse struct {
	Protocols []string `json:"protocols"`
}

// Handler serves the peer API the core calls. Every route but /healthz needs
// the bearer token.
func (s *Service) Handler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("PUT /v1/peers/{pub}", s.putPeer)
	mux.HandleFunc("DELETE /v1/peers/{pub}", s.deletePeer)
	mux.HandleFunc("GET /v1/peers", s.listPeers)
	mux.HandleFunc("PUT /v1/ipsec", s.putIPsec)
	mux.HandleFunc("GET /v1/info", s.info)
	return authenticate(token, mux)
}

func authenticate(token string, next http.Handler) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			got, hasPrefix := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !hasPrefix || len(want) == 0 || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func validKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	key, err := wgtypes.ParseKey(r.PathValue("pub"))
	if err != nil {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return "", false
	}
	// Non-canonical base64 decodes to the same key; storing the canonical
	// form keeps one peer from appearing under two spellings.
	return key.String(), true
}

func (s *Service) putPeer(w http.ResponseWriter, r *http.Request) {
	pub, ok := validKey(w, r)
	if !ok {
		return
	}
	var body putPeerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	addr, err := netip.ParseAddr(body.Address)
	if err != nil || !usableRouterAddr(addr) {
		http.Error(w, "address outside the router pool", http.StatusBadRequest)
		return
	}
	spec := PeerSpec{PublicKey: pub, Address: addr, Protocol: body.Protocol,
		PPPUser: body.PPPUsername, PPPPassword: body.PPPPassword}
	if spec.Protocol == "" {
		spec.Protocol = routeros.ProtocolWireGuard
	}
	if !validLogin(spec) {
		http.Error(w, "invalid protocol or PPP login", http.StatusBadRequest)
		return
	}
	if err := s.UpsertPeer(spec); err != nil {
		if errors.Is(err, ErrAddressInUse) {
			writeError(w, http.StatusConflict, "address_in_use")
			return
		}
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validLogin: a WireGuard peer carries no PPP login, an L2TP peer needs one.
func validLogin(p PeerSpec) bool {
	switch p.Protocol {
	case routeros.ProtocolWireGuard:
		return p.PPPUser == "" && p.PPPPassword == ""
	case routeros.ProtocolL2TP:
		return ppp.UserRE.MatchString(p.PPPUser) && ppp.PasswordRE.MatchString(p.PPPPassword)
	}
	return false
}

func (s *Service) putIPsec(w http.ResponseWriter, r *http.Request) {
	var body putIPsecRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if !ppp.PSKRE.MatchString(body.PSK) || !routeros.ValidHost(body.LocalID) {
		http.Error(w, "invalid psk or localId", http.StatusBadRequest)
		return
	}
	if err := s.SetIPsec(body.PSK, body.LocalID); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) info(w http.ResponseWriter, _ *http.Request) {
	protocols, err := s.Protocols()
	if err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(infoResponse{Protocols: protocols})
}

func (s *Service) deletePeer(w http.ResponseWriter, r *http.Request) {
	pub, ok := validKey(w, r)
	if !ok {
		return
	}
	if err := s.DeletePeer(pub); err != nil {
		internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) listPeers(w http.ResponseWriter, _ *http.Request) {
	statuses, err := s.PeerStatuses()
	if err != nil {
		internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(statuses)
}

// usableRouterAddr excludes the pool's network and broadcast addresses, which
// no router can be given.
func usableRouterAddr(a netip.Addr) bool {
	if !ipam.RouterPool.Contains(a) {
		return false
	}
	return a != ipam.RouterPool.Masked().Addr() && a != lastAddr(ipam.RouterPool)
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	for i := 0; i < host; i++ {
		b[3-i/8] |= 1 << (i % 8)
	}
	return netip.AddrFrom4(b)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// internalError hides the cause from the caller; it may name paths or keys.
func internalError(w http.ResponseWriter, err error) {
	slog.Error("hub api", "err", err)
	writeError(w, http.StatusInternalServerError, "internal")
}
