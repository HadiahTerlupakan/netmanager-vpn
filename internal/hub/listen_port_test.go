package hub

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/core"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/joinbundle"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/secret"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/wgdevice"
)

// The port an operator gives the hub is the one routers are told to dial, so
// wg-nm must listen on it rather than on the default.
func TestHubListensOnPortChosenAtCreate(t *testing.T) {
	e := newEnv(t)
	cst, err := store.Open(filepath.Join(t.TempDir(), "core.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cst.Close() })
	box, err := secret.NewBox("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	c := core.New(wgdevice.NewMemory(), cst, box, nil, core.Config{CoreEndpoint: "vpn.example:51822",
		InstallURL: "https://x/install-hub.sh", HubImage: "img:tag-1", Now: func() time.Time { return e.now }})
	_, cmd, err := c.CreateHub("Jakarta", "hub1.example.com", 51900)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(cmd)
	b, err := joinbundle.Decode(fields[len(fields)-1])
	if err != nil {
		t.Fatal(err)
	}
	if b.ListenPort != 51900 {
		t.Fatalf("bundle listen port = %d", b.ListenPort)
	}
	if err := e.svc.Join(b); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if got := e.dev.applied["wg-nm"].ListenPort; got != 51900 {
		t.Fatalf("wg-nm listens on %d", got)
	}
}
