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

	device, err := client.Device(cfg.InterfaceName)
	if err != nil {
		return fmt.Errorf("read device %s: %w", cfg.InterfaceName, err)
	}
	present := make([]wgtypes.Key, 0, len(device.Peers))
	for _, p := range device.Peers {
		present = append(present, p.PublicKey)
	}
	wgcfg, err := deviceConfig(cfg, present, resolveEndpoint)
	if err != nil {
		return err
	}
	return client.ConfigureDevice(cfg.InterfaceName, wgcfg)
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
	return addRoutes(add, cfg.YieldTo, func(dst *net.IPNet) error {
		return netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst})
	}, routeHolder)
}

// routeHolder names the link the main table routes dst through, or "" when
// that cannot be read.
func routeHolder(dst *net.IPNet) string {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: dst}, netlink.RT_FILTER_DST)
	if err != nil || len(routes) == 0 {
		return ""
	}
	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return ""
	}
	return link.Attrs().Name
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

// EnsureUnreachable adds the route only when the main table has none for
// prefix. Another route on exactly that prefix is reported, not replaced: it
// was put there by someone else and must not be silently taken over.
func (linuxDevice) EnsureUnreachable(prefix string) error {
	_, dst, err := net.ParseCIDR(prefix)
	if err != nil {
		return fmt.Errorf("parse prefix %s: %w", prefix, err)
	}
	existing, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: dst}, netlink.RT_FILTER_DST)
	if err != nil {
		return fmt.Errorf("list routes for %s: %w", prefix, err)
	}
	for _, r := range existing {
		if r.Type == syscall.RTN_UNREACHABLE {
			return nil
		}
	}
	if len(existing) > 0 {
		return fmt.Errorf("%s is already routed by another route; remove it so unrouted routers fail locally", prefix)
	}
	if err := netlink.RouteAdd(&netlink.Route{Dst: dst, Type: syscall.RTN_UNREACHABLE}); err != nil {
		return fmt.Errorf("add unreachable %s: %w", prefix, err)
	}
	return nil
}
