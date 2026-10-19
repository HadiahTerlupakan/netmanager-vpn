package hub

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/ipam"
)

type putPeerRequest struct {
	Address string `json:"address"`
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
	return authenticate(token, mux)
}

func authenticate(token string, next http.Handler) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			got := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if len(want) == 0 || subtle.ConstantTimeCompare(got, want) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func validKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	pub := r.PathValue("pub")
	if _, err := wgtypes.ParseKey(pub); err != nil {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return "", false
	}
	return pub, true
}

func (s *Service) putPeer(w http.ResponseWriter, r *http.Request) {
	pub, ok := validKey(w, r)
	if !ok {
		return
	}
	var body putPeerRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	addr, err := netip.ParseAddr(body.Address)
	if err != nil || !ipam.RouterPool.Contains(addr) {
		http.Error(w, "address outside the router pool", http.StatusBadRequest)
		return
	}
	if err := s.UpsertPeer(pub, addr); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) deletePeer(w http.ResponseWriter, r *http.Request) {
	pub, ok := validKey(w, r)
	if !ok {
		return
	}
	if err := s.DeletePeer(pub); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) listPeers(w http.ResponseWriter, _ *http.Request) {
	statuses, err := s.PeerStatuses()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(statuses)
}
