package hub

import (
	"os"
	"strings"
)

// ensureProcValue writes value to a /proc/sys file unless it already holds
// it. A hub container without host networking has /proc/sys mounted
// read-only, and its forwarding comes from `docker run --sysctl`; rewriting
// the same value there would fail the whole reconcile.
func ensureProcValue(path, value string) error {
	current, err := os.ReadFile(path)
	if err == nil && strings.TrimSpace(string(current)) == value {
		return nil
	}
	return os.WriteFile(path, []byte(value), 0o644)
}
