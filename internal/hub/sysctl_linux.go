//go:build linux

package hub

import "strings"

func writeSysctl(key, value string) error {
	return ensureProcValue("/proc/sys/"+strings.ReplaceAll(key, ".", "/"), value)
}
