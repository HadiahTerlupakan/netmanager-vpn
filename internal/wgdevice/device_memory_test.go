package wgdevice

import (
	"testing"
	"time"
)

func TestMemoryRecordsLastConfig(t *testing.T) {
	m := NewMemory()
	first := Config{InterfaceName: "wg-core", Address: "10.99.0.1/24", ListenPort: 51822, MTU: 1380}
	second := Config{
		InterfaceName: "wg-core",
		Address:       "10.99.0.1/24",
		ListenPort:    51822,
		MTU:           1380,
		Peers: []PeerConfig{{
			PublicKey:  "pub",
			AllowedIPs: []string{"10.99.0.2/32"},
			Endpoint:   "hub.example.net:51821",
			Keepalive:  25 * time.Second,
		}},
	}

	for _, cfg := range []Config{first, second} {
		if err := m.Apply(cfg); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	}

	got := m.Last()
	if len(got.Peers) != 1 || got.Peers[0].Endpoint != "hub.example.net:51821" || got.Peers[0].Keepalive != 25*time.Second {
		t.Fatalf("Last() = %+v, want the second config", got)
	}
}

func TestMemoryStatusReturnsSet(t *testing.T) {
	m := NewMemory()
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	want := []PeerStatus{{PublicKey: "pub", LastHandshakeAt: &at, RxBytes: 10, TxBytes: 20}}
	m.SetStatus(want)

	got, err := m.Status("wg-core")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(got) != 1 || got[0].PublicKey != "pub" || !got[0].LastHandshakeAt.Equal(at) || got[0].RxBytes != 10 || got[0].TxBytes != 20 {
		t.Fatalf("Status = %+v, want %+v", got, want)
	}
}
