//go:build windows

package egress

import (
	"context"
	"errors"
)

type lifecycleLock interface{ Close() error }

func acquireLifecycleLock(context.Context, string) (lifecycleLock, error) {
	return nil, errors.New("managed Docker egress is not supported on Windows")
}
