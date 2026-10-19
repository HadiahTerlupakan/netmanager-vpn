//go:build linux

package firewall

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

type nft struct{}

// NewNft returns an Applier that feeds the ruleset to `nft -f -`.
func NewNft() Applier { return nft{} }

func (nft) Apply(ruleset string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f -: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
