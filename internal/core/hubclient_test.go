package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/hub"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

// mimicHub answers like internal/hub's API so the JSON contract between the
// two packages is pinned from the core's side.
func mimicHub(t *testing.T, hs time.Time) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		switch {
		case r.Method == "PUT" && r.URL.EscapedPath() == "/v1/peers/ab%2Fc=":
			var body struct{ Address string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Address == "10.100.0.9" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(409)
				_, _ = w.Write([]byte(`{"error":"address_in_use"}`))
				return
			}
			w.WriteHeader(204)
		case r.Method == "DELETE" && r.URL.EscapedPath() == "/v1/peers/ab%2Fc=":
			w.WriteHeader(204)
		case r.Method == "GET" && r.URL.Path == "/v1/peers":
			_ = json.NewEncoder(w).Encode([]hub.PeerStatus{{
				PublicKey: "k1", Address: "10.100.0.5", LastHandshakeAt: &hs, RxBytes: 7, TxBytes: 9}})
		default:
			http.Error(w, "boom", 500)
		}
	}))
}

func clientFor(t *testing.T, f fixture, srv *httptest.Server) (HubClient, store.Hub) {
	t.Helper()
	sealed, _ := f.box.Seal("secret-token")
	u, _ := url.Parse(srv.URL)
	c := newHTTPHubClient(f.box, func(h store.Hub) string { return "http://" + u.Host })
	return c, store.Hub{APIToken: sealed, BackhaulAddr: netip.MustParseAddr("10.99.0.2")}
}

func TestHTTPHubClientContract(t *testing.T) {
	f := newFixture(t)
	hs := time.Date(2026, 10, 19, 11, 59, 0, 0, time.UTC)
	srv := mimicHub(t, hs)
	defer srv.Close()
	c, h := clientFor(t, f, srv)
	ctx := context.Background()

	if err := c.UpsertPeer(ctx, h, "ab/c=", netip.MustParseAddr("10.100.0.8")); err != nil {
		t.Fatal(err)
	}
	if err := c.UpsertPeer(ctx, h, "ab/c=", netip.MustParseAddr("10.100.0.9")); !errors.Is(err, ErrHubAddressInUse) {
		t.Fatalf("err = %v, want ErrHubAddressInUse", err)
	}
	if err := c.DeletePeer(ctx, h, "ab/c="); err != nil {
		t.Fatal(err)
	}
	peers, err := c.Peers(ctx, h)
	if err != nil || len(peers) != 1 {
		t.Fatalf("peers %v err %v", peers, err)
	}
	p := peers[0]
	if p.PublicKey != "k1" || p.Address != "10.100.0.5" || p.RxBytes != 7 || p.TxBytes != 9 ||
		p.LastHandshakeAt == nil || !p.LastHandshakeAt.Equal(hs) {
		t.Fatalf("decoded %+v", p)
	}
}

func TestHTTPHubClientErrors(t *testing.T) {
	f := newFixture(t)
	srv := mimicHub(t, time.Now())
	defer srv.Close()
	c, h := clientFor(t, f, srv)
	err := c.DeletePeer(context.Background(), h, "other")
	if err == nil || !strings.Contains(err.Error(), "500") || errors.Is(err, ErrHubAddressInUse) {
		t.Fatalf("err = %v", err)
	}
	h.APIToken, _ = f.box.Seal("wrong")
	if _, err := c.Peers(context.Background(), h); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v", err)
	}
}
