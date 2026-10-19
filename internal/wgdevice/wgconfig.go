package wgdevice

import (
	"fmt"
	"log/slog"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// deviceConfig builds the wgctrl request that brings an interface holding the
// present peers to cfg. resolve turns a peer's host:port into an address.
func deviceConfig(cfg Config, present []wgtypes.Key, resolve func(string) (*net.UDPAddr, error)) (wgtypes.Config, error) {
	key, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("parse server key: %w", err)
	}
	peers, wanted, err := peerConfigs(cfg.Peers, resolve)
	if err != nil {
		return wgtypes.Config{}, err
	}
	// Peers the device holds that cfg no longer lists. Without ReplacePeers
	// nothing else would take them away, and a revoked site would keep its
	// tunnel.
	for _, k := range present {
		if !wanted[k] {
			peers = append(peers, wgtypes.PeerConfig{PublicKey: k, Remove: true})
		}
	}
	out := wgtypes.Config{
		PrivateKey: &key,
		// Deliberately NOT ReplacePeers. That flag drops every peer and re-adds
		// it, discarding each site's learned endpoint along with its session —
		// and a site behind NAT is the only side that can start a new one, so
		// the tunnel stays down until its key ages out, about two minutes. The
		// peers this function does want gone are removed explicitly instead.
		ReplacePeers: false,
		Peers:        peers,
	}
	// wg-up has no fixed port; sending zero would rebind it to a new random
	// one on every reconcile and break the core's view of its endpoint.
	if cfg.ListenPort != 0 {
		port := cfg.ListenPort
		out.ListenPort = &port
	}
	return out, nil
}

func peerConfigs(in []PeerConfig, resolve func(string) (*net.UDPAddr, error)) ([]wgtypes.PeerConfig, map[wgtypes.Key]bool, error) {
	peers := make([]wgtypes.PeerConfig, 0, len(in))
	wanted := make(map[wgtypes.Key]bool, len(in))
	for _, peer := range in {
		peerKey, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("parse peer key: %w", err)
		}
		allowed, err := parseAllowedIPs(peer.AllowedIPs)
		if err != nil {
			return nil, nil, err
		}
		keepalive := peer.Keepalive
		wanted[peerKey] = true
		peers = append(peers, wgtypes.PeerConfig{
			PublicKey: peerKey,
			// UpdateOnly is deliberately left false so a new peer is created,
			// while ReplaceAllowedIPs still rewrites the subnets of one that
			// already exists — in place, without disturbing its session.
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  allowed,
			Endpoint:                    peerEndpoint(peer.Endpoint, resolve),
			PersistentKeepaliveInterval: &keepalive,
		})
	}
	return peers, wanted, nil
}

// peerEndpoint leaves the endpoint unset when it is empty or does not resolve
// right now: the kernel then keeps the endpoint it learned, and one hub's DNS
// outage does not stop the rest of the interface from being applied.
func peerEndpoint(endpoint string, resolve func(string) (*net.UDPAddr, error)) *net.UDPAddr {
	if endpoint == "" {
		return nil
	}
	addr, err := resolve(endpoint)
	if err != nil {
		slog.Warn("peer endpoint not resolved, keeping the learned one", "endpoint", endpoint, "err", err)
		return nil
	}
	return addr
}

// resolveEndpoint turns a host:port into an address at Apply time, because the
// kernel only stores the resolved IP and a hub's DNS name can change.
func resolveEndpoint(endpoint string) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr("udp", endpoint)
}

func parseAllowedIPs(entries []string) ([]net.IPNet, error) {
	allowed := make([]net.IPNet, 0, len(entries))
	for _, entry := range entries {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("parse allowed ip %s: %w", entry, err)
		}
		allowed = append(allowed, *network)
	}
	return allowed, nil
}
