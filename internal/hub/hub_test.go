package hub

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/joinbundle"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/secret"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/wgdevice"
)

// recorder keeps the last config per interface, which wgdevice.Memory cannot:
// it holds only the most recent Apply regardless of interface.
type recorder struct {
	*wgdevice.Memory
	mu      sync.Mutex
	applied map[string]wgdevice.Config
	calls   int
}

func newRecorder() *recorder {
	return &recorder{Memory: wgdevice.NewMemory(), applied: map[string]wgdevice.Config{}}
}

func (r *recorder) Apply(c wgdevice.Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.applied[c.InterfaceName] = c
	return r.Memory.Apply(c)
}

type fakeFW struct{ rules string }

func (f *fakeFW) Apply(s string) error { f.rules = s; return nil }

// fakeIPTables has a DOCKER-USER chain, as every hub with Docker does.
type fakeIPTables struct{ calls [][]string }

func (f *fakeIPTables) Run(args ...string) (bool, error) {
	f.calls = append(f.calls, args)
	return args[0] != "-C", nil
}

type env struct {
	svc     *Service
	st      *store.Store
	dev     *recorder
	fw      *fakeFW
	ipt     *fakeIPTables
	sysctls map[string]string
	now     time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, err := secret.NewBox("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{st: st, dev: newRecorder(), fw: &fakeFW{}, ipt: &fakeIPTables{}, sysctls: map[string]string{},
		now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	e.svc = New(e.dev, st, e.fw, box, Options{
		Now:      func() time.Time { return e.now },
		Sysctl:   func(k, v string) error { e.sysctls[k] = v; return nil },
		IPTables: e.ipt,
	})
	return e
}

func (e *env) bundle() joinbundle.Bundle {
	return joinbundle.Bundle{
		CoreEndpoint: "core.example:51820", CorePublicKey: "corepub", BackhaulAddr: "10.99.0.2",
		PrivateKey: "hubpriv", APIToken: "tok", ExpiresAt: e.now.Add(time.Hour),
	}
}

func TestReconcileBuildsBothInterfaces(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.Join(e.bundle()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.UpsertPeer("routerpub", netip.MustParseAddr("10.100.0.10")); err != nil {
		t.Fatal(err)
	}
	nm := e.dev.applied["wg-nm"]
	if len(nm.Peers) != 1 || nm.Peers[0].PublicKey != "routerpub" ||
		nm.Peers[0].AllowedIPs[0] != "10.100.0.10/32" || nm.ListenPort != 51821 || nm.PrivateKey != "hubpriv" {
		t.Fatalf("wg-nm = %+v", nm)
	}
	up := e.dev.applied["wg-up"]
	if len(up.Peers) != 1 || up.Peers[0].Endpoint != "core.example:51820" ||
		up.Peers[0].Keepalive != 25*time.Second || up.Address != "10.99.0.2/24" ||
		len(up.Peers[0].AllowedIPs) != 2 || up.Peers[0].PublicKey != "corepub" {
		t.Fatalf("wg-up = %+v", up)
	}
	if e.fw.rules == "" || e.sysctls["net.ipv4.ip_forward"] != "1" {
		t.Fatalf("firewall %q sysctl %v", e.fw.rules, e.sysctls)
	}
	var inserted []string
	for _, c := range e.ipt.calls {
		if c[0] == "-I" {
			inserted = append(inserted, strings.Join(c, " "))
		}
	}
	if len(inserted) < 2 || inserted[0] != "-I DOCKER-USER -i wg-nm -o wg-up -j ACCEPT" ||
		inserted[1] != "-I DOCKER-USER -i wg-up -o wg-nm -j ACCEPT" {
		t.Fatalf("DOCKER-USER accepts not requested: %v", inserted)
	}
}

func TestReconcileWithEmptyStoreDoesNotWipeBeforeLoad(t *testing.T) {
	e := newEnv(t)
	e.st.Close()
	if err := e.svc.Reconcile(); err == nil {
		t.Fatal("expected load error")
	}
	if e.dev.calls != 0 {
		t.Fatalf("Apply called %d times after a failed load", e.dev.calls)
	}
}

func TestJoinRejectsExpiredBundle(t *testing.T) {
	e := newEnv(t)
	b := e.bundle()
	b.ExpiresAt = e.now.Add(-time.Second)
	if err := e.svc.Join(b); err == nil {
		t.Fatal("expected expiry error")
	}
	if _, err := e.st.LoadHubConfig(); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("config saved despite expiry: %v", err)
	}
}

func TestPeerStatusesJoinsStoredAddress(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.Join(e.bundle()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.UpsertPeer("routerpub", netip.MustParseAddr("10.100.0.10")); err != nil {
		t.Fatal(err)
	}
	hs := e.now.Add(-time.Minute)
	e.dev.SetStatus([]wgdevice.PeerStatus{
		{PublicKey: "routerpub", LastHandshakeAt: &hs, RxBytes: 5, TxBytes: 7},
		{PublicKey: "stray", RxBytes: 1},
	})
	got, err := e.svc.PeerStatuses()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Address != "10.100.0.10" || got[0].RxBytes != 5 || got[0].LastHandshakeAt == nil {
		t.Fatalf("statuses = %+v", got)
	}
}

func TestUpsertPeerRejectsAddressHeldByOtherKey(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.Join(e.bundle()); err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr("10.100.0.10")
	if err := e.svc.UpsertPeer("keyA", a); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.UpsertPeer("keyA", a); err != nil {
		t.Fatalf("same key and address must stay idempotent: %v", err)
	}
	if err := e.svc.UpsertPeer("keyB", a); !errors.Is(err, ErrAddressInUse) {
		t.Fatalf("err = %v", err)
	}
	if err := e.svc.UpsertPeer("keyA", netip.MustParseAddr("10.100.0.11")); err != nil {
		t.Fatalf("same key, new address: %v", err)
	}
	if err := e.svc.UpsertPeer("keyB", a); err != nil {
		t.Fatalf("freed address: %v", err)
	}
}
