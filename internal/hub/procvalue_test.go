package hub

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureProcValueLeavesACorrectReadOnlyValueAlone(t *testing.T) {
	// A hub container without host networking: forwarding was set by
	// `docker run --sysctl` and /proc/sys is mounted read-only.
	path := filepath.Join(t.TempDir(), "ip_forward")
	if err := os.WriteFile(path, []byte("1\n"), 0o444); err != nil {
		t.Fatal(err)
	}

	if err := ensureProcValue(path, "1"); err != nil {
		t.Fatalf("ensureProcValue: %v", err)
	}
}

func TestEnsureProcValueWritesADifferentValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip_forward")
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ensureProcValue(path, "1"); err != nil {
		t.Fatalf("ensureProcValue: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1" {
		t.Fatalf("value = %q, want %q", got, "1")
	}
}

func TestEnsureProcValueReportsAReadOnlyWrongValue(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write a read-only file")
	}
	path := filepath.Join(t.TempDir(), "ip_forward")
	if err := os.WriteFile(path, []byte("0\n"), 0o444); err != nil {
		t.Fatal(err)
	}

	if err := ensureProcValue(path, "1"); err == nil {
		t.Fatal("expected an error when forwarding is off and cannot be written")
	}
}
