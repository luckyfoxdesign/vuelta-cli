package pipeline

import (
	"context"
	"fmt"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

// NotConfiguredSecurityGate fails closed: part C's trivy/osv-scanner and
// GitHub Dependabot integration is not implemented yet. Silently reporting
// "no vulnerabilities found" when nothing was actually scanned would
// defeat the whole gate, so this stub always errors rather than passing.
type NotConfiguredSecurityGate struct{}

// Baseline implements SecurityGate.
func (NotConfiguredSecurityGate) Baseline(context.Context, config.Workspace, config.Config) (Report, error) {
	return Report{}, fmt.Errorf("security scanning is not implemented yet (see part C) — refusing to update without a CVE gate")
}

// PostCheck implements SecurityGate.
func (NotConfiguredSecurityGate) PostCheck(context.Context, config.Workspace, config.Config, Report) (Report, error) {
	return Report{}, fmt.Errorf("security scanning is not implemented yet (see part C) — refusing to update without a CVE gate")
}
