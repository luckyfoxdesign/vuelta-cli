package toolchain

import (
	"fmt"

	"github.com/luckyfoxdesign/vuelta/internal/safeerr"
)

// BuildFailureKind is a stable machine-readable embedded scanner failure.
type BuildFailureKind string

const (
	BuildFailureVersionUnavailable BuildFailureKind = "toolchain_version_unavailable"
	BuildFailureRegistry           BuildFailureKind = "toolchain_registry_unavailable"
	BuildFailureDocker             BuildFailureKind = "toolchain_build_failed"
	BuildFailureCancelled          BuildFailureKind = "toolchain_build_cancelled"
)

// BuildError carries only approved identity and bounded sanitized diagnostics.
type BuildError struct {
	Kind      BuildFailureKind
	Manager   string
	Version   string
	Category  safeerr.Category
	ExitCode  int
	Detail    string
	Unwrapped error
}

func (e *BuildError) Error() string {
	message := fmt.Sprintf("build embedded %s scanner %s failed (%s", e.Manager, e.Version, e.Kind)
	if e.Category != "" {
		message += ", " + string(e.Category)
	}
	if e.ExitCode >= 0 {
		message += fmt.Sprintf(", exit %d", e.ExitCode)
	}
	message += ")"
	if e.Detail != "" {
		message += ": " + e.Detail
	}
	return message
}

func (e *BuildError) Unwrap() error { return e.Unwrapped }
