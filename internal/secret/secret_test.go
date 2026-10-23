package secret

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func newKey(t *testing.T, n int) string {
	t.Helper()
	k := make([]byte, n)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k)
}

func TestSealOpenRoundTrip(t *testing.T) {
	box, err := NewBox(newKey(t, 32))
	if err != nil {
		t.Fatal(err)
	}
	s1, err := box.Seal("wg-private-key")
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := box.Seal("wg-private-key")
	if s1 == s2 {
		t.Fatal("two seals of the same plaintext are identical; nonce is not random")
	}
	got, err := box.Open(s1)
	if err != nil || got != "wg-private-key" {
		t.Fatalf("Open = %q, %v", got, err)
	}
}

func TestOpenRejectsTampered(t *testing.T) {
	box, _ := NewBox(newKey(t, 32))
	sealed, _ := box.Seal("secret")
	raw, _ := base64.StdEncoding.DecodeString(sealed)
	raw[len(raw)-1] ^= 1
	if _, err := box.Open(base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := box.Open("AA=="); err == nil {
		t.Fatal("truncated input accepted")
	}
}

func TestNewBoxRejectsShortKey(t *testing.T) {
	if _, err := NewBox(newKey(t, 16)); err == nil {
		t.Fatal("16-byte key accepted")
	}
	if _, err := NewBox("not base64!!"); err == nil {
		t.Fatal("invalid base64 accepted")
	}
}
