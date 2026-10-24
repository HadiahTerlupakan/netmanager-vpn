// Package firewall renders and applies the nftables rulesets of the core and hub.
package firewall

// Applier installs a ruleset on the host.
type Applier interface {
	Apply(ruleset string) error
}

// The preamble declares the table before flushing it so the first apply does
// not fail, and so `nft -f -` swaps only our table atomically and leaves
// kube-proxy's and docker's tables alone.
const preamble = `table inet netmanager_vpn
flush table inet netmanager_vpn
table inet netmanager_vpn {
`

// The hub's rules for routers on L2TP are rendered only when the hub serves
// it: the fib and meta ipsec expressions need nft_fib_inet and nft_xfrm, and
// a kernel without them rejects the whole table, which would keep a
// WireGuard-only hub from ever listening. accel-ppp names its links nmppp*,
// so a PPP uplink of the host's own (ppp0) is never matched.
//
// The anti-spoof rule sits in prerouting because kernel 5.15 rejects fib in
// the input and forward hooks ("Not supported") and accepts it only here;
// prerouting also covers packets to the hub and forwarded ones alike. L2TP is
// legitimate only inside IPsec, so plain UDP 1701 is dropped.
//
// Chains use policy accept because they share hooks with other software's
// tables; we only drop what we own. No hub rule tracks connections: the hub
// keeps no state, so replies are matched by port. A bare SYN from wg-nm is
// dropped first because the source port alone would let a router open
// connections.
const (
	hubPrerouting = `	chain prerouting {
		type filter hook prerouting priority -150; policy accept;
		iifname "nmppp*" fib saddr . iif oif missing drop
	}
`
	hubForwardHead = `	chain forward {
		type filter hook forward priority 0; policy accept;
`
	hubForwardWG = `		iifname "wg-nm" oifname "wg-up" ip daddr 10.99.0.1 udp dport { 30812, 30813 } accept
		iifname "wg-nm" oifname "wg-up" ip daddr 10.99.0.1 icmp type { echo-request, echo-reply } accept
		iifname "wg-nm" oifname "wg-up" ip daddr 10.99.128.0/24 icmp type echo-reply accept
		iifname "wg-nm" tcp flags & (syn | ack) == syn drop
		iifname "wg-nm" oifname "wg-up" ip daddr { 10.99.0.1, 10.99.128.0/24 } tcp sport { 8728, 8291, 22 } accept
		iifname "wg-nm" drop
		iifname "wg-up" oifname "wg-nm" ip saddr { 10.99.0.1, 10.99.128.0/24 } accept
		iifname "wg-up" oifname "wg-nm" drop
`
	hubForwardPPP = `		iifname "nmppp*" oifname "wg-up" ip daddr 10.99.0.1 udp dport { 30812, 30813 } accept
		iifname "nmppp*" oifname "wg-up" ip daddr 10.99.0.1 icmp type { echo-request, echo-reply } accept
		iifname "nmppp*" oifname "wg-up" ip daddr 10.99.128.0/24 icmp type echo-reply accept
		iifname "nmppp*" tcp flags & (syn | ack) == syn drop
		iifname "nmppp*" oifname "wg-up" ip daddr { 10.99.0.1, 10.99.128.0/24 } tcp sport { 8728, 8291, 22 } accept
		iifname "nmppp*" drop
		iifname "wg-up" oifname "nmppp*" ip saddr { 10.99.0.1, 10.99.128.0/24 } accept
		iifname "wg-up" oifname "nmppp*" drop
`
	hubInputHead = `	chain input {
		type filter hook input priority 0; policy accept;
`
	hubInputWG = `		iifname "wg-up" ip saddr 10.99.0.1 tcp dport 7480 accept
		tcp dport 7480 drop
		iifname "wg-nm" icmp type echo-request accept
		iifname "wg-nm" drop
`
	hubInputPPP = `		udp dport 1701 meta ipsec missing drop
		iifname "nmppp*" icmp type echo-request accept
		iifname "nmppp*" drop
`
	chainEnd  = "\t}\n"
	coreInput = `	chain input {
		type filter hook input priority 0; policy accept;
		tcp dport 7480 ip saddr { 127.0.0.1, 10.42.0.0/16 } accept
		tcp dport 7480 drop
	}
`
	// wgcore_in runs before kube-proxy's NodePort DNAT (priority -100) so a
	// hub cannot reach a NodePort, kubelet or the k3s API on 10.99.0.1, or the
	// pod network. Conntrack (-200) has already run, and unlike a hub the core
	// sees both directions of every flow, so replies are matched by state.
	coreWgIn = `	chain wgcore_in {
		type filter hook prerouting priority -150; policy accept;
		iifname "wg-core" ct state established,related accept
		iifname "wg-core" ip saddr 10.100.0.0/14 ip daddr 10.99.0.1 udp dport { 30812, 30813 } accept
		iifname "wg-core" ip saddr 10.100.0.0/14 ip daddr 10.99.0.1 icmp type { echo-request, echo-reply } accept
		iifname "wg-core" ip saddr 10.99.128.0/24 ip daddr 10.100.0.0/14 accept
		iifname "wg-core" drop
	}
`
	postamble = "}\n"
)

// RenderHub returns the hub ruleset: wg-nm traffic, and with pppEnabled that
// of nmppp* too, is confined to the management flows, and the control port is
// open only to the core.
func RenderHub(pppEnabled bool) string {
	if !pppEnabled {
		return preamble + hubForwardHead + hubForwardWG + chainEnd + hubInputHead + hubInputWG + chainEnd + postamble
	}
	return preamble + hubPrerouting +
		hubForwardHead + hubForwardWG + hubForwardPPP + chainEnd +
		hubInputHead + hubInputWG + hubInputPPP + chainEnd + postamble
}

// RenderCore returns the core ruleset: the control port answers only the
// local host and the pod network, and wg-core admits only router RADIUS and
// ping to the core and admin traffic to routers.
func RenderCore() string {
	return preamble + coreInput + coreWgIn + postamble
}
