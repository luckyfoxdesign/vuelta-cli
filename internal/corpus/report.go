package corpus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	ReportSchemaVersion = 1
	maxMessageRunes     = 1024
)

// Report is the deterministic machine-readable result of one corpus run.
type Report struct {
	SchemaVersion int         `json:"schema_version"`
	RunID         string      `json:"run_id"`
	StartedAt     time.Time   `json:"started_at"`
	FinishedAt    time.Time   `json:"finished_at"`
	AppRevision   string      `json:"app_revision"`
	ManifestHash  string      `json:"manifest_hash"`
	Environment   Environment `json:"environment"`
	Summary       Summary     `json:"summary"`
	Warnings      []string    `json:"warnings"`
	Results       []Result    `json:"results"`
	Comparison    Comparison  `json:"comparison"`
}

// Environment identifies the preflighted Docker daemon and scanner build.
type Environment struct {
	DockerOS      string `json:"docker_os"`
	Architecture  string `json:"architecture"`
	ServerVersion string `json:"server_version"`
	Scanner       string `json:"scanner"`
}

// Summary separates stable regression verdicts from discovery observations.
type Summary struct {
	StablePassed      int `json:"stable_passed"`
	StableFailed      int `json:"stable_failed"`
	DiscoveryPassed   int `json:"discovery_passed"`
	DiscoveryFindings int `json:"discovery_findings"`
}

// Result records one scenario pass or one source/preflight failure.
type Result struct {
	Source                string           `json:"source"`
	Name                  string           `json:"name"`
	URL                   string           `json:"url"`
	Commit                string           `json:"commit"`
	Subdir                string           `json:"subdir"`
	Scenario              string           `json:"scenario"`
	Pass                  int              `json:"pass"`
	Argv                  []string         `json:"argv"`
	ExitCode              *int             `json:"exit_code,omitempty"`
	DurationMS            int64            `json:"duration_ms"`
	ObservedCategory      string           `json:"observed_category"`
	Verdict               string           `json:"verdict"`
	Reason                string           `json:"reason"`
	Envelope              ObservedEnvelope `json:"envelope"`
	LogPath               string           `json:"log_path"`
	ProjectURL            string           `json:"project_url"`
	CommitURL             string           `json:"commit_url"`
	ReproduceCommand      []string         `json:"reproduce_command"`
	UnexpectedChanges     []string         `json:"unexpected_changes"`
	OnboardingChanges     []string         `json:"onboarding_changes"`
	OutputTruncated       bool             `json:"output_truncated"`
	ComparableDurationMS  int64            `json:"comparable_duration_ms,omitempty"`
	PerformanceRegression bool             `json:"performance_regression,omitempty"`
	Contract              Case             `json:"contract"`
}

// ObservedEnvelope is the bounded subset of Vuelta's JSON contract retained
// in reports. Raw project output is never copied into a report.
type ObservedEnvelope struct {
	Format          int                  `json:"format,omitempty"`
	Command         string               `json:"command,omitempty"`
	DetectedStacks  []string             `json:"detected_stacks"`
	PackageManagers []string             `json:"package_managers"`
	LockFormats     []string             `json:"lock_formats"`
	Statuses        []string             `json:"statuses"`
	Stages          []ObservedStage      `json:"stages"`
	Diagnostics     []string             `json:"diagnostics"`
	Warnings        []string             `json:"warnings"`
	Errors          []ObservedError      `json:"errors"`
	Capabilities    []ObservedCapability `json:"capabilities"`
	Toolchains      []ObservedToolchain  `json:"toolchains"`
}

// ObservedStage is one extracted scan stage.
type ObservedStage struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// ObservedError is one extracted top-level or result error.
type ObservedError struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Stage    string `json:"stage,omitempty"`
	Category string `json:"category,omitempty"`
}

// ObservedCapability is one extracted structured capability result.
type ObservedCapability struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// ObservedToolchain is the bounded, non-secret identity selected by Vuelta.
type ObservedToolchain struct {
	AdapterID             string   `json:"adapter_id,omitempty"`
	AdapterVersion        string   `json:"adapter_version,omitempty"`
	Source                string   `json:"source,omitempty"`
	ProfileID             string   `json:"profile_id,omitempty"`
	Hash                  string   `json:"hash,omitempty"`
	Runtime               string   `json:"runtime,omitempty"`
	PackageManager        string   `json:"package_manager,omitempty"`
	PackageManagerVersion string   `json:"package_manager_version,omitempty"`
	Scanner               string   `json:"scanner,omitempty"`
	ScannerVersion        string   `json:"scanner_version,omitempty"`
	Image                 string   `json:"image,omitempty"`
	ImageID               string   `json:"image_id,omitempty"`
	Platform              string   `json:"platform,omitempty"`
	User                  string   `json:"user,omitempty"`
	LockFormats           []string `json:"lock_formats"`
}

// Comparison summarizes changes against the newest previous completed run.
type Comparison struct {
	PreviousRunID string   `json:"previous_run_id,omitempty"`
	NewFailures   []string `json:"new_failures"`
	Fixed         []string `json:"fixed"`
	Unchanged     []string `json:"unchanged"`
	Slower        []string `json:"slower"`
}

type rawEnvelope struct {
	Format   int             `json:"format"`
	Command  string          `json:"command"`
	Results  []rawScanResult `json:"results"`
	Warnings []string        `json:"warnings"`
	Errors   []ObservedError `json:"errors"`
	Config   *struct {
		DetectedStacks []string `json:"detected_stacks"`
	} `json:"config"`
}

type rawScanResult struct {
	Status         string               `json:"status"`
	Stages         []ObservedStage      `json:"stages"`
	Diagnostics    []rawDiagnostic      `json:"diagnostics"`
	Warnings       []string             `json:"warnings"`
	Error          *ObservedError       `json:"error"`
	Capabilities   []ObservedCapability `json:"capabilities"`
	PackageUpdates *struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	} `json:"package_updates"`
	Toolchain *rawToolchain `json:"toolchain"`
}

type rawDiagnostic struct {
	Category string `json:"category"`
	Message  string `json:"message"`
	Reason   string `json:"reason"`
}

type rawToolchain struct {
	AdapterID             string   `json:"adapter_id"`
	AdapterVersion        string   `json:"adapter_version"`
	Source                string   `json:"source"`
	ProfileID             string   `json:"profile_id"`
	Hash                  string   `json:"hash"`
	Runtime               string   `json:"runtime"`
	PackageManager        string   `json:"package_manager"`
	PackageManagerVersion string   `json:"package_manager_version"`
	Scanner               string   `json:"scanner"`
	ScannerVersion        string   `json:"scanner_version"`
	Image                 string   `json:"image"`
	ImageID               string   `json:"image_id"`
	Platform              string   `json:"platform"`
	User                  string   `json:"user"`
	LockFormats           []string `json:"lock_formats"`
}

// ParseObservedEnvelope rejects malformed or trailing JSON and retains only
// bounded, sanitized contract fields.
func ParseObservedEnvelope(data []byte) (ObservedEnvelope, error) {
	var raw rawEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&raw); err != nil {
		return ObservedEnvelope{}, fmt.Errorf("decode Vuelta JSON envelope: %w", err)
	}
	var trailer any
	if err := decoder.Decode(&trailer); !errors.Is(err, io.EOF) {
		return ObservedEnvelope{}, errors.New("vuelta JSON envelope contains trailing data")
	}
	if raw.Format != 1 || raw.Command != "scan" || len(raw.Results) == 0 {
		return ObservedEnvelope{}, errors.New("vuelta JSON envelope has an invalid scan shape")
	}
	observed := ObservedEnvelope{
		Format: raw.Format, Command: raw.Command,
		DetectedStacks: []string{}, PackageManagers: []string{}, LockFormats: []string{},
		Statuses: []string{}, Stages: []ObservedStage{}, Diagnostics: []string{},
		Warnings: []string{}, Errors: []ObservedError{}, Capabilities: []ObservedCapability{},
		Toolchains: []ObservedToolchain{},
	}
	if raw.Config != nil {
		observed.DetectedStacks = sanitizeList(raw.Config.DetectedStacks, 8)
	}
	observed.Warnings = sanitizeList(raw.Warnings, 64)
	for _, item := range raw.Errors {
		observed.Errors = appendBounded(observed.Errors, 64, sanitizeObservedError(item))
	}
	for _, result := range raw.Results {
		observed.Statuses = appendBounded(observed.Statuses, 64, SanitizeMessage(result.Status))
		for _, stage := range result.Stages {
			observed.Stages = appendBounded(observed.Stages, 64, ObservedStage{
				Name: SanitizeMessage(stage.Name), Status: SanitizeMessage(stage.Status), Reason: SanitizeMessage(stage.Reason),
			})
		}
		for _, diagnostic := range result.Diagnostics {
			message := diagnostic.Message
			if message == "" {
				message = diagnostic.Reason
			}
			if diagnostic.Category != "" {
				message = diagnostic.Category + ": " + message
			}
			observed.Diagnostics = appendBounded(observed.Diagnostics, 64, SanitizeMessage(message))
		}
		observed.Warnings = appendBounded(observed.Warnings, 64, sanitizeList(result.Warnings, 64)...)
		if result.Error != nil {
			observed.Errors = appendBounded(observed.Errors, 64, sanitizeObservedError(*result.Error))
		}
		for _, capability := range result.Capabilities {
			observed.Capabilities = appendBounded(observed.Capabilities, 64, ObservedCapability{
				Name: SanitizeMessage(capability.Name), Status: SanitizeMessage(capability.Status), Reason: SanitizeMessage(capability.Reason),
			})
		}
		if result.PackageUpdates != nil {
			observed.Capabilities = appendBounded(observed.Capabilities, 64, ObservedCapability{
				Name: "package_updates", Status: SanitizeMessage(result.PackageUpdates.Status),
				Reason: SanitizeMessage(result.PackageUpdates.Reason),
			})
		}
		if result.Toolchain != nil {
			toolchain := sanitizeObservedToolchain(*result.Toolchain)
			observed.Toolchains = appendBounded(observed.Toolchains, 8, toolchain)
			observed.PackageManagers = appendBounded(
				observed.PackageManagers, 8, toolchain.PackageManager,
			)
			observed.LockFormats = appendBounded(
				observed.LockFormats, 16, toolchain.LockFormats...,
			)
		}
	}
	observed.DetectedStacks = uniqueSorted(observed.DetectedStacks)
	observed.PackageManagers = uniqueSorted(observed.PackageManagers)
	observed.LockFormats = uniqueSorted(observed.LockFormats)
	return observed, nil
}

// ValidateObservedContract ensures the source was detected as the reviewed
// stack, manager, and lock format rather than merely completing a scan.
func ValidateObservedContract(corpusCase Case, envelope ObservedEnvelope) error {
	if !slicesContains(envelope.DetectedStacks, corpusCase.ExpectedStack) &&
		!managerImpliesStack(envelope.PackageManagers, corpusCase.ExpectedStack) {
		return fmt.Errorf("expected detected stack %q, observed %v", corpusCase.ExpectedStack, envelope.DetectedStacks)
	}
	if !slicesContains(envelope.PackageManagers, corpusCase.ExpectedPackageManager) {
		return fmt.Errorf(
			"expected package manager %q, observed %v",
			corpusCase.ExpectedPackageManager,
			envelope.PackageManagers,
		)
	}
	switch {
	case corpusCase.ExpectedLockFormat == "absent":
	case slicesContains(corpusCase.Features, "discovery") &&
		strings.HasSuffix(corpusCase.ExpectedLockFormat, "-detected"):
		if len(envelope.LockFormats) == 0 {
			return fmt.Errorf("expected a detected lock format, observed %v", envelope.LockFormats)
		}
	case !slicesContains(envelope.LockFormats, corpusCase.ExpectedLockFormat):
		return fmt.Errorf(
			"expected lock format %q, observed %v",
			corpusCase.ExpectedLockFormat,
			envelope.LockFormats,
		)
	}
	return nil
}

func managerImpliesStack(managers []string, stack string) bool {
	for _, manager := range managers {
		switch stack {
		case "node":
			if slicesContains([]string{"npm", "pnpm", "bun"}, manager) {
				return true
			}
		case "python":
			if slicesContains([]string{"poetry", "uv", "pip-tools", "requirements"}, manager) {
				return true
			}
		}
	}
	return false
}

func sanitizeObservedToolchain(value rawToolchain) ObservedToolchain {
	return ObservedToolchain{
		AdapterID:             SanitizeMessage(value.AdapterID),
		AdapterVersion:        SanitizeMessage(value.AdapterVersion),
		Source:                SanitizeMessage(value.Source),
		ProfileID:             SanitizeMessage(value.ProfileID),
		Hash:                  SanitizeMessage(value.Hash),
		Runtime:               SanitizeMessage(value.Runtime),
		PackageManager:        SanitizeMessage(value.PackageManager),
		PackageManagerVersion: SanitizeMessage(value.PackageManagerVersion),
		Scanner:               SanitizeMessage(value.Scanner),
		ScannerVersion:        SanitizeMessage(value.ScannerVersion),
		Image:                 SanitizeMessage(value.Image),
		ImageID:               SanitizeMessage(value.ImageID),
		Platform:              SanitizeMessage(value.Platform),
		User:                  SanitizeMessage(value.User),
		LockFormats:           sanitizeList(value.LockFormats, 16),
	}
}

func sanitizeObservedError(value ObservedError) ObservedError {
	return ObservedError{
		Code: SanitizeMessage(value.Code), Message: SanitizeMessage(value.Message),
		Stage: SanitizeMessage(value.Stage), Category: SanitizeMessage(value.Category),
	}
}

func sanitizeList(values []string, limit int) []string {
	result := make([]string, 0, min(len(values), limit))
	for _, value := range values {
		result = appendBounded(result, limit, SanitizeMessage(value))
	}
	return result
}

func appendBounded[S ~[]E, E any](target S, limit int, values ...E) S {
	remaining := limit - len(target)
	if remaining <= 0 {
		return target
	}
	if len(values) > remaining {
		values = values[:remaining]
	}
	return append(target, values...)
}

// Classify converts process and structured results into an observed category
// and a stable/discovery verdict.
func Classify(source string, exitCode int, envelope ObservedEnvelope, expectation Expectation, runErr error) (string, string, string) {
	category, reason, accepted := classifyObserved(exitCode, envelope, expectation, runErr)
	if source == "discovery" {
		if accepted {
			return category, "pass", reason
		}
		return category, "finding", reason
	}
	if accepted {
		return category, "pass", reason
	}
	return category, "fail", reason
}

func classifyObserved(exitCode int, envelope ObservedEnvelope, expectation Expectation, runErr error) (string, string, bool) {
	if runErr != nil {
		if errors.Is(runErr, ErrOutputTooLarge) {
			return "output-too-large", "Vuelta output exceeded 5 MiB", false
		}
		if errors.Is(runErr, ErrTimeout) {
			return "timeout", "scan exceeded 5 minutes", false
		}
		if errors.Is(runErr, ErrInvalidJSON) {
			return "invalid-json", "Vuelta returned invalid JSON", false
		}
		return "process-error", SanitizeMessage(runErr.Error()), false
	}
	if len(expectation.AllowedExits) > 0 && !slicesContainInt(expectation.AllowedExits, exitCode) {
		return exitCategory(exitCode), fmt.Sprintf("Vuelta exit code %d did not match the expected contract", exitCode), false
	}
	if len(expectation.AllowedExits) == 0 && exitCode != 0 && exitCode != 5 {
		if exitCode == 6 {
			if !expectation.AllowPartial || !matchesExpectation(envelope, expectation) {
				return "partial", "unexpected partial scan result", false
			}
		} else {
			return exitCategory(exitCode), fmt.Sprintf("unexpected Vuelta exit code %d", exitCode), false
		}
	}
	for _, stage := range envelope.Stages {
		if stage.Status == "failed" {
			return "failed-stage", nonEmpty(stage.Reason, "Vuelta reported a failed stage"), false
		}
	}
	if len(envelope.Errors) > 0 {
		return "structured-error", nonEmpty(envelope.Errors[0].Message, "Vuelta reported a structured error"), false
	}
	if len(envelope.Statuses) == 0 {
		return "status-mismatch", "Vuelta scan result omitted status", false
	}
	for _, status := range envelope.Statuses {
		switch status {
		case "clean", "ready", "findings", "scan-only":
		case "partial":
			if !expectation.AllowPartial || !matchesExpectation(envelope, expectation) {
				return "partial", "unexpected partial scan result", false
			}
		default:
			return "status-mismatch", "Vuelta reported an unexpected scan status", false
		}
	}
	if len(envelope.Diagnostics) > 0 {
		return "diagnostic", envelope.Diagnostics[0], false
	}
	if len(expectation.AllowedStatuses) > 0 {
		for _, status := range envelope.Statuses {
			if !slicesContains(expectation.AllowedStatuses, status) {
				return "status-mismatch", "scan status did not match the expected contract", false
			}
		}
	}
	if len(expectation.Capabilities) > 0 && !matchesExpectation(envelope, expectation) {
		return "capability-mismatch", "structured capability contract did not match", false
	}
	if exitCode == 5 {
		return "findings", "scan completed with vulnerability findings", true
	}
	if exitCode == 6 {
		return "expected-partial", "scan matched the explicit fail-open capability contract", true
	}
	return "success", "scan contract passed", true
}

func exitCategory(code int) string {
	switch code {
	case 4:
		return "case-config-failure"
	case 7:
		return "image-scan-required"
	default:
		return "unexpected-exit"
	}
}

func matchesExpectation(envelope ObservedEnvelope, expectation Expectation) bool {
	for _, expected := range expectation.Capabilities {
		found := false
		for _, observed := range envelope.Capabilities {
			if observed.Name == expected.Name && observed.Status == expected.Status &&
				(expected.ReasonContains == "" || strings.Contains(observed.Reason, expected.ReasonContains)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return len(expectation.Capabilities) > 0
}

func slicesContainInt(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func slicesContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func nonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// SanitizeMessage removes controls and bounds report/log-derived text.
func SanitizeMessage(value string) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	var output strings.Builder
	for _, current := range value {
		if current == '\n' || current == '\t' {
			output.WriteRune(' ')
			continue
		}
		if unicode.IsControl(current) || current == '\u007f' {
			continue
		}
		output.WriteRune(current)
		if output.Len() >= maxMessageRunes*4 {
			break
		}
	}
	runes := []rune(strings.Join(strings.Fields(output.String()), " "))
	if len(runes) > maxMessageRunes {
		return string(runes[:maxMessageRunes]) + "…"
	}
	return string(runes)
}

// BuildComparison compares stable scenario-pass keys and duration against a
// previous report. Discovery never affects regression state.
func BuildComparison(current, previous Report) Comparison {
	comparison := Comparison{
		PreviousRunID: previous.RunID,
		NewFailures:   []string{}, Fixed: []string{}, Unchanged: []string{}, Slower: []string{},
	}
	old := stableResultMap(previous.Results)
	now := stableResultMap(current.Results)
	keys := make([]string, 0, len(now))
	for key := range now {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		currentResult := now[key]
		oldResult, exists := old[key]
		switch {
		case currentResult.Verdict == "fail" && (!exists || oldResult.Verdict != "fail"):
			comparison.NewFailures = append(comparison.NewFailures, key)
		case currentResult.Verdict != "fail" && exists && oldResult.Verdict == "fail":
			comparison.Fixed = append(comparison.Fixed, key)
		default:
			comparison.Unchanged = append(comparison.Unchanged, key)
		}
		if exists && oldResult.DurationMS > 0 && currentResult.DurationMS > oldResult.DurationMS*2 {
			comparison.Slower = append(comparison.Slower, key)
		}
	}
	return comparison
}

func stableResultMap(results []Result) map[string]Result {
	values := make(map[string]Result)
	for _, result := range results {
		if result.Source != "stable" {
			continue
		}
		values[resultKey(result)] = result
	}
	return values
}

func resultKey(result Result) string {
	return fmt.Sprintf("%s/%s/%d", result.Name, result.Scenario, result.Pass)
}

// RenderMarkdown creates a bounded, escaped human report.
func RenderMarkdown(report Report) string {
	var output strings.Builder
	fmt.Fprintf(&output, "# Vuelta Corpus Run %s\n\n", markdown(report.RunID))
	fmt.Fprintf(&output, "- Stable: %d passed, %d failed\n", report.Summary.StablePassed, report.Summary.StableFailed)
	fmt.Fprintf(&output, "- Discovery: %d passed, %d findings\n\n", report.Summary.DiscoveryPassed, report.Summary.DiscoveryFindings)
	output.WriteString("## Warnings\n\n")
	if len(report.Warnings) == 0 {
		output.WriteString("None.\n")
	} else {
		for _, warning := range report.Warnings {
			fmt.Fprintf(&output, "- %s\n", markdown(warning))
		}
	}
	output.WriteString("\n")
	output.WriteString("## Stable\n\n")
	output.WriteString("| Case | Scenario | Exit | Verdict | Duration | Reason | Reproduce | Log |\n")
	output.WriteString("|---|---|---:|---|---:|---|---|---|\n")
	for _, result := range report.Results {
		if result.Source != "stable" {
			continue
		}
		writeMarkdownResult(&output, result)
	}
	output.WriteString("\n## Stable failures and partials\n\n")
	details := 0
	for _, result := range report.Results {
		if result.Source == "stable" &&
			(result.Verdict == "fail" || strings.Contains(result.ObservedCategory, "partial")) {
			details++
			if result.ProjectURL == "" {
				fmt.Fprintf(&output, "- %s, `%s` pass %d: %s\n",
					markdown(result.Name), markdown(result.Scenario), result.Pass, markdown(result.Reason))
			} else {
				fmt.Fprintf(&output, "- %s at %s, `%s` pass %d: %s\n",
					markdownLink(result.Name, result.ProjectURL), markdownLink(result.Commit, result.CommitURL),
					markdown(result.Scenario), result.Pass, markdown(result.Reason))
			}
		}
	}
	if details == 0 {
		output.WriteString("None.\n")
	}
	output.WriteString("\n## Discovery\n\n")
	output.WriteString("| Case | Scenario | Exit | Verdict | Duration | Reason | Reproduce | Log |\n")
	output.WriteString("|---|---|---:|---|---:|---|---|---|\n")
	discovery := 0
	for _, result := range report.Results {
		if result.Source == "discovery" {
			discovery++
			writeMarkdownResult(&output, result)
		}
	}
	if discovery == 0 {
		output.WriteString("| None | - | - | - | - | - | - | - |\n")
	}
	output.WriteString("\n## Comparison\n\n")
	if report.Comparison.PreviousRunID == "" {
		output.WriteString("No previous completed stable report was available.\n")
	} else {
		fmt.Fprintf(&output, "- Previous run: `%s`\n", markdown(report.Comparison.PreviousRunID))
		fmt.Fprintf(&output, "- New failures: %s\n", markdown(strings.Join(report.Comparison.NewFailures, ", ")))
		fmt.Fprintf(&output, "- Fixed: %s\n", markdown(strings.Join(report.Comparison.Fixed, ", ")))
		fmt.Fprintf(&output, "- Unchanged: %s\n", markdown(strings.Join(report.Comparison.Unchanged, ", ")))
		fmt.Fprintf(&output, "- More than 2× slower: %s\n", markdown(strings.Join(report.Comparison.Slower, ", ")))
	}
	return output.String()
}

func writeMarkdownResult(output *strings.Builder, result Result) {
	exit := "-"
	if result.ExitCode != nil {
		exit = fmt.Sprintf("%d", *result.ExitCode)
	}
	fmt.Fprintf(output, "| %s | %s/%d | %s | %s | %d ms | %s | `%s` | `%s` |\n",
		markdownLink(result.Name, result.ProjectURL), markdown(result.Scenario), result.Pass,
		exit, markdown(result.Verdict), result.DurationMS, markdown(result.Reason),
		markdown(strings.Join(result.ReproduceCommand, " ")), markdown(result.LogPath))
}

func markdownLink(label, target string) string {
	if target == "" {
		return markdown(label)
	}
	return fmt.Sprintf("[%s](%s)", markdown(label), target)
}

func markdown(value string) string {
	value = SanitizeMessage(value)
	value = html.EscapeString(value)
	replacer := strings.NewReplacer(
		"\\", "\\\\", "|", "\\|", "`", "\\`", "[", "\\[", "]", "\\]",
		"*", "\\*", "_", "\\_", "<", "&lt;", ">", "&gt;",
	)
	return replacer.Replace(value)
}
