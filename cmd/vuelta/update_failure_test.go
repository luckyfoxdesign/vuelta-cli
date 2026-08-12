package main

import (
	"errors"
	"testing"
)

func TestUpdateExecutionErrorCodeDistinguishesVerificationOutcomes(t *testing.T) {
	tests := []struct {
		name  string
		tests string
		want  string
	}{
		{name: "dependency preparation", tests: "preparation_failed", want: "verification_dependency_preparation_failed"},
		{name: "verification timeout", tests: "timed_out", want: "verification_timeout"},
		{name: "build or test failure", tests: "failed", want: "verification_failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := updateExecutionErrorCode(errors.New("bounded failure"), updateResult{Tests: test.tests})
			if got != test.want {
				t.Fatalf("code = %q, want %q", got, test.want)
			}
		})
	}
}
