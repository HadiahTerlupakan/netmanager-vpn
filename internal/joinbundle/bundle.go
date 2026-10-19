// Package joinbundle is the one-time token an operator pastes onto a new hub.
package joinbundle

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Bundle carries everything a hub needs to join. A single key serves both of
// the hub's interfaces because the core stores one public key per hub.
type Bundle struct {
	CoreEndpoint  string `json:"coreEndpoint"`
	CorePublicKey string `json:"corePublicKey"`
	BackhaulAddr  string `json:"backhaulAddr"`
	// ListenPort is wg-nm's port; zero in a bundle issued before it was carried.
	ListenPort int       `json:"listenPort,omitempty"`
	PrivateKey string    `json:"privateKey"`
	APIToken   string    `json:"apiToken"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// Encode returns the bundle as unpadded base64url JSON, safe to paste into a shell.
func (b Bundle) Encode() string {
	raw, _ := json.Marshal(b)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// Decode parses an encoded bundle and rejects one missing a field the hub
// cannot join without.
func Decode(s string) (Bundle, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Bundle{}, fmt.Errorf("joinbundle: decode: %w", err)
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return Bundle{}, fmt.Errorf("joinbundle: parse: %w", err)
	}
	if b.CoreEndpoint == "" || b.CorePublicKey == "" || b.PrivateKey == "" || b.APIToken == "" {
		return Bundle{}, errors.New("joinbundle: missing required field")
	}
	if _, err := netip.ParseAddr(b.BackhaulAddr); err != nil {
		return Bundle{}, fmt.Errorf("joinbundle: backhaul address: %w", err)
	}
	return b, nil
}
