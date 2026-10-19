package joinbundle

import (
	"testing"
	"time"
)

func sample() Bundle {
	return Bundle{
		CoreEndpoint: "core.example:51820", CorePublicKey: "cpub", BackhaulAddr: "10.99.0.2", ListenPort: 51900,
		PrivateKey: "priv", APIToken: "tok", ExpiresAt: time.Date(2026, 10, 20, 1, 2, 3, 0, time.UTC),
	}
}

func TestBundleRoundTrip(t *testing.T) {
	want := sample()
	got, err := Decode(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestDecodeRejectsInvalid(t *testing.T) {
	noKey := sample()
	noKey.PrivateKey = ""
	badAddr := sample()
	badAddr.BackhaulAddr = "not-an-ip"
	for name, s := range map[string]string{
		"garbage": "!!!", "missing key": noKey.Encode(), "bad address": badAddr.Encode(),
	} {
		if _, err := Decode(s); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
