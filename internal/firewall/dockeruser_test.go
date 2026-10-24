package firewall

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// fakeIPTables models one DOCKER-USER chain: -S reports whether it exists, -C
// whether a rule is in it, -I inserts.
type fakeIPTables struct {
	chain bool
	rules []string
	calls []string
	fail  error
}

func (f *fakeIPTables) Run(args ...string) (bool, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if f.fail != nil {
		return false, f.fail
	}
	if !f.chain {
		return false, nil
	}
	rule := strings.Join(args[2:], " ")
	switch args[0] {
	case "-S":
		return true, nil
	case "-C":
		return slices.Contains(f.rules, rule), nil
	case "-I":
		f.rules = append(f.rules, rule)
		return true, nil
	}
	return false, errors.New("unexpected iptables call")
}

func TestDockerUserAcceptsInsertedOnce(t *testing.T) {
	ipt := &fakeIPTables{chain: true}
	for range 2 {
		if err := EnsureDockerUserAccepts(ipt, HubDockerAccepts(true)); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"-i wg-nm -o wg-up -j ACCEPT", "-i wg-up -o wg-nm -j ACCEPT",
		"-i nmppp+ -o wg-up -j ACCEPT", "-i wg-up -o nmppp+ -j ACCEPT",
	}
	if !slices.Equal(ipt.rules, want) {
		t.Fatalf("rules = %v", ipt.rules)
	}
	for _, c := range ipt.calls {
		if strings.HasPrefix(c, "-I") && !strings.HasPrefix(c, "-I DOCKER-USER ") {
			t.Fatalf("insert outside DOCKER-USER: %q", c)
		}
	}
	inserts := 0
	for _, c := range ipt.calls {
		if strings.HasPrefix(c, "-I") {
			inserts++
		}
	}
	if inserts != 4 {
		t.Fatalf("second pass inserted again: %v", ipt.calls)
	}
}

func TestWireGuardOnlyHubAcceptsNoPPP(t *testing.T) {
	for _, rule := range HubDockerAccepts(false) {
		if strings.Contains(strings.Join(rule, " "), "ppp") {
			t.Fatalf("WireGuard-only hub accepts %v", rule)
		}
	}
	if len(HubDockerAccepts(false)) != 2 {
		t.Fatalf("accepts = %v", HubDockerAccepts(false))
	}
}

func TestDockerUserSkippedWithoutDocker(t *testing.T) {
	ipt := &fakeIPTables{}
	if err := EnsureDockerUserAccepts(ipt, CoreDockerAccepts); err != nil {
		t.Fatal(err)
	}
	if len(ipt.calls) != 1 || ipt.calls[0] != "-S DOCKER-USER" {
		t.Fatalf("calls = %v", ipt.calls)
	}
}

func TestDockerUserCoreRule(t *testing.T) {
	ipt := &fakeIPTables{chain: true}
	if err := EnsureDockerUserAccepts(ipt, CoreDockerAccepts); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ipt.rules, []string{"-i wg-core -o wg-core -j ACCEPT"}) {
		t.Fatalf("rules = %v", ipt.rules)
	}
}

func TestDockerUserReportsIPTablesFailure(t *testing.T) {
	ipt := &fakeIPTables{chain: true, fail: errors.New("xtables lock")}
	if err := EnsureDockerUserAccepts(ipt, HubDockerAccepts(false)); err == nil {
		t.Fatal("failure swallowed")
	}
}

type recFW struct{ rules string }

func (r *recFW) Apply(s string) error { r.rules = s; return nil }

func TestApplyCoreInstallsRulesetAndAccept(t *testing.T) {
	fw, ipt := &recFW{}, &fakeIPTables{chain: true}
	if err := ApplyCore(fw, ipt); err != nil {
		t.Fatal(err)
	}
	if fw.rules != RenderCore() || !slices.Equal(ipt.rules, []string{"-i wg-core -o wg-core -j ACCEPT"}) {
		t.Fatalf("nft %q iptables %v", fw.rules, ipt.rules)
	}
}
