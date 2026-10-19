package core

import (
	"net/http"
	"strings"
	"testing"
)

func TestHubUpgradeCommandIsPlainText(t *testing.T) {
	f := newFixture(t)
	hub, _, err := f.core.CreateHub("jkt", "jkt.example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	h := f.core.Handler(testToken)
	rec := call(t, h, "GET", "/v1/hubs/"+hub.ID+"/upgrade-command", "", true)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	want := "curl -fsSL https://example.test/install-hub.sh | sudo NMVPN_IMAGE=ghcr.io/example/netmanager-vpn:abc123def456-1760000000 sh -s -- upgrade"
	if rec.Body.String() != want {
		t.Fatalf("command = %q", rec.Body)
	}
	if rec := call(t, h, "GET", "/v1/hubs/missing/upgrade-command", "", true); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown hub: %d", rec.Code)
	}
}
