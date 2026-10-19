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

// Chains use policy accept because they share hooks with other software's
// tables; we only drop what we own. No hub rule tracks connections: the hub
// keeps no state, so replies are matched by port. A bare SYN from wg-nm is
// dropped first because the source port alone would let a router open
// connections.
const (
	hubForward = `	chain forward {
		type filter hook forward priority 0; policy accept;
		iifname "wg-nm" oifname "wg-up" ip daddr 10.99.0.1 udp dport { 30812, 30813 } accept
		iifname "wg-nm" oifname "wg-up" ip daddr 10.99.0.1 icmp type { echo-request, echo-reply } accept
		iifname "wg-nm" tcp flags & (syn | ack) == syn drop
		iifname "wg-nm" oifname "wg-up" ip daddr { 10.99.0.1, 10.99.128.0/24 } tcp sport { 8728, 8291, 22 } accept
		iifname "wg-nm" drop
		iifname "wg-up" oifname "wg-nm" ip saddr { 10.99.0.1, 10.99.128.0/24 } accept
		iifname "wg-up" oifname "wg-nm" drop
	}
`
	hubInput = `	chain input {
		type filter hook input priority 0; policy accept;
		iifname "wg-up" ip saddr 10.99.0.1 tcp dport 7480 accept
		tcp dport 7480 drop
		iifname "wg-nm" icmp type echo-request accept
		iifname "wg-nm" drop
	}
`
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

// RenderHub returns the hub ruleset: wg-nm traffic is confined to the
// management flows and the control port is open only to the core.
func RenderHub() string {
	return preamble + hubForward + hubInput + postamble
}

// RenderCore returns the core ruleset: the control port answers only the
// local host and the pod network, and wg-core admits only router RADIUS and
// ping to the core and admin traffic to routers.
func RenderCore() string {
	return preamble + coreInput + coreWgIn + postamble
}
