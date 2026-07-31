//go:build !linux

package deploy

import "errors"

func hostResources(_ string) (HostResources, error) {
	return HostResources{}, errors.New("host resource probing is supported only on Linux")
}
