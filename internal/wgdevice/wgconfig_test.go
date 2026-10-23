package wgdevice

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func testKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func noResolve(string) (*net.UDPAddr, error) { return nil, errors.New("not expected") }

// wg-up has no fixed port; sending zero would make the kernel pick a new
// random one on every reconcile.
func TestDeviceConfigOmitsZeroListenPort(t *testing.T) {
	cfg := Config{PrivateKey: testKey(t).String()}
	got, err := deviceConfig(cfg, nil, noResolve)
	if err != nil {
		t.Fatal(err)
	}
	if got.ListenPort != nil {
		t.Fatalf("listen port sent: %d", *got.ListenPort)
	}
	cfg.ListenPort = 51821
	got, err = deviceConfig(cfg, nil, noResolve)
	if err != nil || got.ListenPort == nil || *got.ListenPort != 51821 {
		t.Fatalf("listen port = %v, err %v", got.ListenPort, err)
	}
}

// A hub whose DNS name does not resolve right now must not stop the rest of
// the interface from being applied; its peer keeps the learned endpoint.
func TestDeviceConfigLeavesUnresolvableEndpointUnset(t *testing.T) {
	peer := testKey(t).PublicKey()
	cfg := Config{PrivateKey: testKey(t).String(), Peers: []PeerConfig{{
		PublicKey: peer.String(), AllowedIPs: []string{"10.99.0.0/24"},
		Endpoint: "gone.example:51822", Keepalive: 25 * time.Second,
	}}}
	got, err := deviceConfig(cfg, nil, func(string) (*net.UDPAddr, error) { return nil, errors.New("no such host") })
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != 1 || got.Peers[0].Endpoint != nil || len(got.Peers[0].AllowedIPs) != 1 {
		t.Fatalf("peers = %+v", got.Peers)
	}
}

func TestDeviceConfigRemovesUnwantedPeers(t *testing.T) {
	keep, gone := testKey(t).PublicKey(), testKey(t).PublicKey()
	cfg := Config{PrivateKey: testKey(t).String(), Peers: []PeerConfig{{PublicKey: keep.String()}}}
	got, err := deviceConfig(cfg, []wgtypes.Key{keep, gone}, noResolve)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReplacePeers || len(got.Peers) != 2 || got.Peers[0].PublicKey != keep || got.Peers[0].Remove ||
		got.Peers[1].PublicKey != gone || !got.Peers[1].Remove {
		t.Fatalf("config = %+v", got)
	}
}
