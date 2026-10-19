//go:build linux

package wgdevice

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// linuxDevice drives the kernel interface. It needs CAP_NET_ADMIN.
type linuxDevice struct{}

// NewLinux returns a device that drives real kernel WireGuard interfaces.
func NewLinux() Device {
	return linuxDevice{}
}

// Apply makes the kernel interface match cfg: link, address, WireGuard peers,
// and routes are each brought to the desired state in turn.
func (linuxDevice) Apply(cfg Config) error {
	link, err := ensureLink(cfg.InterfaceName, cfg.MTU)
	if err != nil {
		return err
	}
	if err := ensureAddress(link, cfg.Address); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring %s up: %w", cfg.InterfaceName, err)
	}
	if err := applyWireGuardConfig(cfg); err != nil {
		return err
	}
	return syncRoutes(link, cfg)
}

func ensureLink(name string, mtu int) (netlink.Link, error) {
	link, err := netlink.LinkByName(name)
	if err == nil {
		return link, setMTU(link, mtu)
	}
	// Only a genuinely absent interface justifies creating one. A permission or
	// netlink failure reported here would otherwise be answered with LinkAdd,
	// whose "file exists" points the operator at the wrong problem entirely.
	var notFound netlink.LinkNotFoundError
	if !errors.As(err, &notFound) {
		return nil, fmt.Errorf("look up %s: %w", name, err)
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	wg := &netlink.Wireguard{LinkAttrs: attrs}
	if err := netlink.LinkAdd(wg); err != nil {
		return nil, fmt.Errorf("create %s (load the wireguard kernel module on the VPS host: modprobe wireguard): %w", name, err)
	}
	link, err = netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("look up created %s: %w", name, err)
	}
	return link, setMTU(link, mtu)
}

func setMTU(link netlink.Link, mtu int) error {
	if mtu == 0 || link.Attrs().MTU == mtu {
		return nil
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("set %s mtu %d: %w", link.Attrs().Name, mtu, err)
	}
	return nil
}

func ensureAddress(link netlink.Link, address string) error {
	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return fmt.Errorf("parse address %s: %w", address, err)
	}

	existing, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}

	// The whole list is scanned rather than stopping at the first match: an
	// address left behind by a previous configuration would leave the
	// interface answering on two subnets.
	found := false
	for i := range existing {
		if existing[i].Equal(*addr) {
			found = true
			continue
		}
		if err := netlink.AddrDel(link, &existing[i]); err != nil {
			return fmt.Errorf("remove stale address %s: %w", existing[i].IPNet, err)
		}
	}

	if found {
		return nil
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("add address %s: %w", address, err)
	}
	return nil
}

func applyWireGuardConfig(cfg Config) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wireguard control: %w", err)
	}
	defer client.Close()

	key, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse server key: %w", err)
	}

	peers := make([]wgtypes.PeerConfig, 0, len(cfg.Peers))
	wanted := make(map[wgtypes.Key]bool, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		peerKey, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return fmt.Errorf("parse peer key: %w", err)
		}
		allowed, err := parseAllowedIPs(peer.AllowedIPs)
		if err != nil {
			return err
		}
		endpoint, err := resolveEndpoint(peer.Endpoint)
		if err != nil {
			return err
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
			Endpoint:                    endpoint,
			PersistentKeepaliveInterval: &keepalive,
		})
	}

	removals, err := peersToRemove(client, cfg.InterfaceName, wanted)
	if err != nil {
		return err
	}
	peers = append(peers, removals...)

	port := cfg.ListenPort
	return client.ConfigureDevice(cfg.InterfaceName, wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &port,
		// Deliberately NOT ReplacePeers. That flag drops every peer and re-adds
		// it, discarding each site's learned endpoint along with its session —
		// and a site behind NAT is the only side that can start a new one, so
		// the tunnel stays down until its key ages out, about two minutes. The
		// peers this function does want gone are removed explicitly instead.
		ReplacePeers: false,
		Peers:        peers,
	})
}

// peersToRemove names the peers the device still holds that the desired state no
// longer lists. Without ReplacePeers nothing else would take them away, and a
// revoked site would keep its tunnel.
func peersToRemove(client *wgctrl.Client, interfaceName string, wanted map[wgtypes.Key]bool) ([]wgtypes.PeerConfig, error) {
	device, err := client.Device(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("read device %s: %w", interfaceName, err)
	}

	var removals []wgtypes.PeerConfig
	for _, existing := range device.Peers {
		if wanted[existing.PublicKey] {
			continue
		}
		removals = append(removals, wgtypes.PeerConfig{
			PublicKey: existing.PublicKey,
			Remove:    true,
		})
	}
	return removals, nil
}

// resolveEndpoint turns a host:port into an address at Apply time, because the
// kernel only stores the resolved IP and a hub's DNS name can change. An empty
// endpoint stays nil so the peer's learned endpoint is not overwritten.
func resolveEndpoint(endpoint string) (*net.UDPAddr, error) {
	if endpoint == "" {
		return nil, nil
	}
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("resolve endpoint %s: %w", endpoint, err)
	}
	return addr, nil
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

// syncRoutes makes the routing table match the peers, as planRoutes decides.
func syncRoutes(link netlink.Link, cfg Config) error {
	existing, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	dsts := make([]*net.IPNet, 0, len(existing))
	for _, route := range existing {
		dsts = append(dsts, route.Dst)
	}
	add, stale, err := planRoutes(cfg, dsts)
	if err != nil {
		return err
	}
	for i := range existing {
		route := existing[i]
		if route.Dst == nil || !stale[route.Dst.String()] {
			continue
		}
		if err := netlink.RouteDel(&route); err != nil {
			return fmt.Errorf("remove stale route %s: %w", route.Dst, err)
		}
	}
	for _, network := range add {
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: network}
		if err := netlink.RouteAdd(route); err != nil {
			// Deliberately not RouteReplace: a peer subnet that collides with an
			// existing host route must fail loudly rather than hijack it.
			if errors.Is(err, syscall.EEXIST) {
				return fmt.Errorf("add route %s: already routed via another interface, remove the conflicting route or change the peer's subnet: %w", network, err)
			}
			return fmt.Errorf("add route %s: %w", network, err)
		}
	}
	return nil
}

// Status reads the live peer state back from the kernel via wgctrl.
func (linuxDevice) Status(interfaceName string) ([]PeerStatus, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("open wireguard control: %w", err)
	}
	defer client.Close()

	device, err := client.Device(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("read device %s: %w", interfaceName, err)
	}

	statuses := make([]PeerStatus, 0, len(device.Peers))
	for _, peer := range device.Peers {
		status := PeerStatus{
			PublicKey: peer.PublicKey.String(),
			RxBytes:   peer.ReceiveBytes,
			TxBytes:   peer.TransmitBytes,
		}
		if !peer.LastHandshakeTime.IsZero() {
			handshake := peer.LastHandshakeTime.UTC()
			status.LastHandshakeAt = &handshake
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}
