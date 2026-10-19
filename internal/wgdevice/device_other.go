//go:build !linux

package wgdevice

import "errors"

// errUnsupported keeps development on macOS building. The kernel interface
// only exists on the Linux hosts the service is deployed to.
var errUnsupported = errors.New("wireguard requires linux")

type unsupported struct{}

// NewLinux returns a stand-in that fails every call; the real implementation
// is in device_linux.go.
func NewLinux() Device {
	return unsupported{}
}

func (unsupported) Apply(Config) error {
	return errUnsupported
}

func (unsupported) Status(string) ([]PeerStatus, error) {
	return nil, errUnsupported
}

func (unsupported) EnsureUnreachable(string) error {
	return errUnsupported
}
