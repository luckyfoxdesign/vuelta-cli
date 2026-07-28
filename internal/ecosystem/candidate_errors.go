package ecosystem

import (
	"errors"
	"fmt"
	"time"
)

// CandidateFailureKind is a stable machine-readable candidate scan failure.
type CandidateFailureKind string

const (
	CandidateFailureNonJSON        CandidateFailureKind = "non_json_output"
	CandidateFailureTruncatedJSON  CandidateFailureKind = "truncated_json"
	CandidateFailureSchemaMismatch CandidateFailureKind = "schema_mismatch"
	CandidateFailureManager        CandidateFailureKind = "package_manager_failure"
	CandidateFailureTimeout        CandidateFailureKind = "package_scan_timeout"
)

// CandidateError distinguishes scanner execution failures from structured
// output contract failures without retaining arbitrary project output.
type CandidateError struct {
	Kind     CandidateFailureKind
	Manager  string
	ExitCode int
	Detail   string
	Deadline time.Duration
	Err      error
}

func (e *CandidateError) Error() string {
	switch e.Kind {
	case CandidateFailureTimeout:
		if e.Deadline > 0 {
			return fmt.Sprintf("%s candidate command exceeded deadline of %s", e.Manager, e.Deadline)
		}
		return fmt.Sprintf("%s candidate command exceeded its deadline", e.Manager)
	case CandidateFailureManager:
		if e.ExitCode >= 0 {
			return fmt.Sprintf("%s candidate command failed with exit code %d", e.Manager, e.ExitCode)
		}
		return fmt.Sprintf("%s candidate command failed", e.Manager)
	default:
		return fmt.Sprintf("%s candidate output failed %s validation", e.Manager, e.Kind)
	}
}

// Unwrap exposes the bounded boundary error for cancellation and subprocess
// classification while Error remains stable and output-free.
func (e *CandidateError) Unwrap() error { return e.Err }

// IsCandidateFailure reports whether err has the requested stable kind.
func IsCandidateFailure(err error, kind CandidateFailureKind) bool {
	var candidateErr *CandidateError
	return errors.As(err, &candidateErr) && candidateErr.Kind == kind
}

// ToolchainVersionError reports a project-declared manager version outside
// the embedded scanner policy. Operator-provided immutable overrides remain
// available for versions with a separately reviewed contract.
type ToolchainVersionError struct {
	Manager string
	Version string
	Reason  string
}

func (e *ToolchainVersionError) Error() string {
	return fmt.Sprintf("embedded %s scanner version %q is unavailable: %s", e.Manager, e.Version, e.Reason)
}
