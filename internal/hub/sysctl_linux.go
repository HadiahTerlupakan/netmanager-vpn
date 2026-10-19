//go:build linux

package hub

import (
	"os"
	"strings"
)

func writeSysctl(key, value string) error {
	return os.WriteFile("/proc/sys/"+strings.ReplaceAll(key, ".", "/"), []byte(value), 0o644)
}
