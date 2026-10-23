// Package secret encrypts values stored at rest, such as WireGuard private keys.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

const keyLen = 32

// Box seals and opens strings with AES-256-GCM.
type Box struct {
	aead cipher.AEAD
}

// NewBox builds a Box from a standard-base64 encoded 32-byte key.
func NewBox(base64Key string) (*Box, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("secret: key is not base64: %w", err)
	}
	if len(key) != keyLen {
		return nil, fmt.Errorf("secret: key is %d bytes, want %d", len(key), keyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal returns base64(nonce || ciphertext) with a fresh random nonce.
func (b *Box) Seal(plain string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Open reverses Seal and fails if the input was altered.
func (b *Box) Open(sealed string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("secret: not base64: %w", err)
	}
	n := b.aead.NonceSize()
	if len(raw) < n {
		return "", errors.New("secret: sealed value too short")
	}
	plain, err := b.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", fmt.Errorf("secret: decrypt: %w", err)
	}
	return string(plain), nil
}
