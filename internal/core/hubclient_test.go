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
	"sync"
	"testing"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/hub"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/ppp"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/routeros"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

// hubBodies records what mimicHub decoded, strictly, into the hub's own
// request types.
type hubBodies struct {
	mu    sync.Mutex
	peers []hub.PutPeerRequest
	ipsec []hub.PutIPsecRequest
}

func decodeStrict(t *testing.T, r *http.Request, v any) {
	t.Helper()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Errorf("hub cannot decode %s %s: %v", r.Method, r.URL.Path, err)
	}
}

// mimicHub answers like internal/hub's API so the JSON contract between the
// two packages is pinned from the core's side.
func mimicHub(t *testing.T, hs time.Time) *httptest.Server {
	return mimicHubRecording(t, hs, &hubBodies{})
}

func mimicHubRecording(t *testing.T, hs time.Time, got *hubBodies) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			http.Error(w, "unauthorized", 401)
			return
		}
		switch {
		case r.Method == "PUT" && r.URL.Path == "/v1/ipsec":
			var body hub.PutIPsecRequest
			decodeStrict(t, r, &body)
			got.mu.Lock()
			got.ipsec = append(got.ipsec, body)
			got.mu.Unlock()
			w.WriteHeader(204)
		case r.Method == "GET" && r.URL.Path == "/v1/info":
			_ = json.NewEncoder(w).Encode(hub.InfoResponse{Protocols: []string{"wireguard", "l2tp"}})
		case r.Method == "PUT" && r.URL.EscapedPath() == "/v1/peers/ab%2Fc=":
			var body hub.PutPeerRequest
			decodeStrict(t, r, &body)
			got.mu.Lock()
			got.peers = append(got.peers, body)
			got.mu.Unlock()
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

	if err := c.UpsertPeer(ctx, h, PeerSpec{PublicKey: "ab/c=", Address: netip.MustParseAddr("10.100.0.8")}); err != nil {
		t.Fatal(err)
	}
	spec := PeerSpec{PublicKey: "ab/c=", Address: netip.MustParseAddr("10.100.0.9")}
	if err := c.UpsertPeer(ctx, h, spec); !errors.Is(err, ErrHubAddressInUse) {
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

// Thousands of routers on one hub exceed a megabyte of JSON; truncating it
// would fail the parse and look like the hub lost every peer.
func TestHTTPHubClientReadsLargePeerList(t *testing.T) {
	f := newFixture(t)
	peers := make([]hub.PeerStatus, 20000)
	for i := range peers {
		peers[i] = hub.PeerStatus{PublicKey: strings.Repeat("k", 44), Address: "10.100.0.5"}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(peers)
	}))
	defer srv.Close()
	c, h := clientFor(t, f, srv)
	got, err := c.Peers(context.Background(), h)
	if err != nil || len(got) != len(peers) {
		t.Fatalf("got %d peers, err %v", len(got), err)
	}
}

// The hub decodes the peer body into hub.PutPeerRequest and checks the PPP
// login against ppp's patterns; a WireGuard peer must carry no login at all.
func TestHubClientPeerBodyMatchesHub(t *testing.T) {
	f := newFixture(t)
	got := &hubBodies{}
	srv := mimicHubRecording(t, time.Now(), got)
	defer srv.Close()
	c, h := clientFor(t, f, srv)
	ctx := context.Background()
	addr := netip.MustParseAddr("10.100.0.8")
	wg := PeerSpec{PublicKey: "ab/c=", Address: addr, Protocol: routeros.ProtocolWireGuard}
	l2tp := PeerSpec{PublicKey: "ab/c=", Address: addr, Protocol: routeros.ProtocolL2TP,
		PPPUser: "nmvpn-0123abcd", PPPPassword: strings.Repeat("aB3_-", 6) + "zz"}
	for _, s := range []PeerSpec{wg, l2tp} {
		if err := c.UpsertPeer(ctx, h, s); err != nil {
			t.Fatal(err)
		}
	}
	want := []hub.PutPeerRequest{
		{Address: "10.100.0.8", Protocol: "wireguard"},
		{Address: "10.100.0.8", Protocol: "l2tp", PPPUsername: l2tp.PPPUser, PPPPassword: l2tp.PPPPassword},
	}
	if len(got.peers) != 2 || got.peers[0] != want[0] || got.peers[1] != want[1] {
		t.Fatalf("hub decoded %+v, want %+v", got.peers, want)
	}
	if !ppp.UserRE.MatchString(got.peers[1].PPPUsername) || !ppp.PasswordRE.MatchString(got.peers[1].PPPPassword) {
		t.Fatalf("hub would refuse the login %+v", got.peers[1])
	}
}

func TestHubClientIPsecAndInfo(t *testing.T) {
	f := newFixture(t)
	got := &hubBodies{}
	srv := mimicHubRecording(t, time.Now(), got)
	defer srv.Close()
	c, h := clientFor(t, f, srv)
	h.PublicHost = "hub-a.example.com"
	psk := strings.Repeat("k", 43)
	if err := c.SetIPsecPSK(context.Background(), h, psk); err != nil {
		t.Fatal(err)
	}
	want := hub.PutIPsecRequest{PSK: psk, LocalID: "hub-a.example.com"}
	if len(got.ipsec) != 1 || got.ipsec[0] != want {
		t.Fatalf("hub decoded %+v, want %+v", got.ipsec, want)
	}
	info, err := c.Info(context.Background(), h)
	if err != nil || len(info.Protocols) != 2 || info.Protocols[1] != "l2tp" {
		t.Fatalf("info %+v err %v", info, err)
	}
}

// A hub built before L2TP has neither route; Go's mux answers 404 for both.
func TestHubClientOldHubIsWireGuardOnly(t *testing.T) {
	f := newFixture(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c, h := clientFor(t, f, srv)
	if err := c.SetIPsecPSK(context.Background(), h, strings.Repeat("k", 43)); err != nil {
		t.Fatalf("psk push to old hub: %v", err)
	}
	info, err := c.Info(context.Background(), h)
	if err != nil || len(info.Protocols) != 1 || info.Protocols[0] != "wireguard" {
		t.Fatalf("info %+v err %v", info, err)
	}
	err = c.DeletePeer(context.Background(), h, "k")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("a 404 on the peer API must still fail: %v", err)
	}
}
