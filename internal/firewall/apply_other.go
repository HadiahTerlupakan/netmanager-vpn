//go:build !linux

package firewall

import "errors"

type unsupported struct{}

// NewNft returns an Applier that always fails: nftables exists only on Linux.
func NewNft() Applier { return unsupported{} }

func (unsupported) Apply(string) error {
	return errors.New("nftables is only available on linux")
}

// NewIPTables returns an IPTables that always fails: iptables exists only on Linux.
func NewIPTables() IPTables { return unsupported{} }

func (unsupported) Run(...string) (bool, error) {
	return false, errors.New("iptables is only available on linux")
}
