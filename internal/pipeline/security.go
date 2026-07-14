package pipeline

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/githubalerts"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

// DefaultSecurityGate runs exactly one configured dependency source. Trivy
// image scans stay independent because Dependabot cannot inspect image OS
// packages.
type DefaultSecurityGate struct {
	Scanner vulnscan.Scanner
	GitHub  githubalerts.Client
}

// Baseline implements SecurityGate against the clean configured workspace.
func (g DefaultSecurityGate) Baseline(ctx context.Context, ws config.Workspace, cfg config.Config) (Report, error) {
	findings, err := g.scan(ctx, ws.Path, ws, cfg)
	if err != nil {
		return Report{}, err
	}
	return reportFromFindings(findings), nil
}

// PostCheck implements SecurityGate against the sandbox that actually
// contains the updated lock files/images, then blocks only a newly introduced
// or higher-severity finding at/above fail_on_severity.
func (g DefaultSecurityGate) PostCheck(ctx context.Context, workDir string, ws config.Workspace, cfg config.Config, baseline Report) (Report, error) {
	findings, err := g.scan(ctx, workDir, ws, cfg)
	if err != nil {
		return Report{}, err
	}
	if err := introducedOrWorsened(baseline.details, findings, cfg.VulnScan.FailOnSeverity); err != nil {
		return Report{}, err
	}
	return reportFromFindings(findings), nil
}

func (g DefaultSecurityGate) scan(ctx context.Context, root string, ws config.Workspace, cfg config.Config) ([]vulnscan.Finding, error) {
	switch cfg.VulnScan.DependencySource {
	case "trivy", "osv-scanner":
		local, err := g.Scanner.Scan(ctx, root, ws, cfg)
		if err != nil {
			return nil, err
		}
		return local.Findings, nil
	case "github-dependabot":
		remote, err := g.GitHub.Scan(ctx, ws, cfg.GithubAdvisories)
		if err != nil {
			return nil, err
		}
		images, err := g.Scanner.ScanImages(ctx, root, ws, cfg)
		if err != nil {
			return nil, err
		}
		return append(remote, images.Findings...), nil
	default:
		return nil, fmt.Errorf("unsupported dependency vulnerability source %q", cfg.VulnScan.DependencySource)
	}
}

func reportFromFindings(findings []vulnscan.Finding) Report {
	refs := make([]string, 0, len(findings))
	seen := make(map[string]bool)
	for _, finding := range findings {
		if !seen[finding.Ref()] {
			refs = append(refs, finding.Ref())
			seen[finding.Ref()] = true
		}
	}
	sort.Strings(refs)
	return Report{Findings: refs, Ran: true, details: findings}
}

func introducedOrWorsened(baseline, post []vulnscan.Finding, threshold string) error {
	minimum := severityRank(threshold)
	if minimum == 0 {
		return fmt.Errorf("invalid CVE severity threshold %q", threshold)
	}
	previous := make(map[string]int)
	for _, finding := range baseline {
		key := comparisonKey(finding)
		if rank := severityRank(finding.Severity); rank > previous[key] {
			previous[key] = rank
		}
	}
	var blocked []string
	for _, finding := range post {
		rank := severityRank(finding.Severity)
		if rank == 0 {
			if previous[comparisonKey(finding)] == 0 {
				blocked = append(blocked, finding.ID+" (unknown severity)")
			}
			continue
		}
		if rank >= minimum && rank > previous[comparisonKey(finding)] {
			blocked = append(blocked, finding.ID+" ("+strings.ToUpper(finding.Severity)+")")
		}
	}
	if len(blocked) > 0 {
		sort.Strings(blocked)
		return fmt.Errorf("new or worsened vulnerabilities violate security gate: %s", strings.Join(blocked, ", "))
	}
	return nil
}

func comparisonKey(f vulnscan.Finding) string {
	return strings.Join([]string{f.ID, f.Package, f.Target, f.Source}, "\x00")
}

func severityRank(value string) int {
	switch strings.ToUpper(value) {
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	default:
		return 0
	}
}
