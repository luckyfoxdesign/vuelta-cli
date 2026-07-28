//go:build windows

package vulnscan

import (
	"context"
	"errors"
)

type databaseLock interface {
	Close() error
}

func acquireDatabaseLock(context.Context, string) (databaseLock, error) {
	return nil, errors.New("managed Trivy database cache is not supported on Windows")
}
