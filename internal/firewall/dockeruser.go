package firewall

import (
	"errors"
	"fmt"
)

// IPTables runs one iptables command against the filter table. ok is false
// when iptables exits 1, which is how it answers "no such rule" to -C and "no
// such chain" to -S; err is reserved for anything else.
type IPTables interface {
	Run(args ...string) (ok bool, err error)
}

const dockerUserChain = "DOCKER-USER"

// Docker sets the iptables FORWARD policy to DROP, and an accept in our own
// nftables table cannot override another base chain's drop. DOCKER-USER is the
// chain Docker keeps for exactly this; these accepts only let routed tunnel
// traffic past Docker's policy, while our nft table still applies its drops.
var (
	hubWGAccepts = [][]string{
		{"-i", "wg-nm", "-o", "wg-up", "-j", "ACCEPT"},
		{"-i", "wg-up", "-o", "wg-nm", "-j", "ACCEPT"},
	}
	// accel-ppp names its links nmppp*, so the host's own PPP uplink is not
	// let through.
	hubPPPAccepts = [][]string{
		{"-i", "nmppp+", "-o", "wg-up", "-j", "ACCEPT"},
		{"-i", "wg-up", "-o", "nmppp+", "-j", "ACCEPT"},
	}
	// The core forwards wg-core to wg-core: an admin device reaching a router
	// through radpro.
	CoreDockerAccepts = [][]string{
		{"-i", "wg-core", "-o", "wg-core", "-j", "ACCEPT"},
	}
)

// HubDockerAccepts returns the hub's DOCKER-USER accepts; the nmppp ones only
// when the hub serves L2TP, as with RenderHub.
func HubDockerAccepts(pppEnabled bool) [][]string {
	if !pppEnabled {
		return hubWGAccepts
	}
	return append(append([][]string{}, hubWGAccepts...), hubPPPAccepts...)
}

// EnsureDockerUserAccepts inserts each rule into DOCKER-USER unless it is
// already there. A host without Docker has no such chain and is left alone.
func EnsureDockerUserAccepts(ipt IPTables, rules [][]string) error {
	exists, err := ipt.Run("-S", dockerUserChain)
	if err != nil {
		return fmt.Errorf("iptables -S %s: %w", dockerUserChain, err)
	}
	if !exists {
		return nil
	}
	for _, rule := range rules {
		present, err := ipt.Run(append([]string{"-C", dockerUserChain}, rule...)...)
		if err != nil {
			return fmt.Errorf("iptables -C %s %v: %w", dockerUserChain, rule, err)
		}
		if present {
			continue
		}
		inserted, err := ipt.Run(append([]string{"-I", dockerUserChain}, rule...)...)
		if err == nil && !inserted {
			err = errors.New("rejected")
		}
		if err != nil {
			return fmt.Errorf("iptables -I %s %v: %w", dockerUserChain, rule, err)
		}
	}
	return nil
}

// ApplyCore installs the core's nftables ruleset and its DOCKER-USER accept.
func ApplyCore(fw Applier, ipt IPTables) error {
	if err := fw.Apply(RenderCore()); err != nil {
		return fmt.Errorf("nft: %w", err)
	}
	return EnsureDockerUserAccepts(ipt, CoreDockerAccepts)
}
