//go:build !linux

package hub

import "errors"

func writeSysctl(string, string) error {
	return errors.New("sysctl is only available on linux")
}
