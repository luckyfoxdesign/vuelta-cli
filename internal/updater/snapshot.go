package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems/catalog"
	"github.com/luckyfoxdesign/vuelta/internal/scaninput"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"github.com/luckyfoxdesign/vuelta/internal/updatesnapshot"
)

// CandidateScanner discovers available package versions without modifying the
// project. Implementations must return structured candidates, never command
// output that would be persisted in a snapshot.
type CandidateScanner interface {
	Scan(ctx context.Context, projectPath string) ([]updatesnapshot.Candidate, error)
}

// ProgressFunc synchronously reports the current candidate sub-scanner.
// Callers must return quickly; a nil callback disables progress entirely.
type ProgressFunc func(detail string, done, total int)

// ScanDiagnostic is one bounded, path-safe problem with an individual
// dependency record. Diagnostics never become update-plan input.
type ScanDiagnostic struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// CandidateReport keeps valid candidates independent from unsupported input
// records so one bad line cannot hide findings from other reviewed pins.
type CandidateReport struct {
	Candidates  []updatesnapshot.Candidate `json:"candidates"`
	Diagnostics []ScanDiagnostic           `json:"diagnostics"`
}

type candidateReportScanner interface {
	ScanReport(ctx context.Context, projectPath string) (CandidateReport, error)
}

// ScanCandidateReport preserves the original CandidateScanner API for update
// rechecks while exposing structured diagnostics to the scan command.
func ScanCandidateReport(ctx context.Context, scanner CandidateScanner, projectPath string) (CandidateReport, error) {
	if reporter, ok := scanner.(candidateReportScanner); ok {
		return reporter.ScanReport(ctx, projectPath)
	}
	candidates, err := scanner.Scan(ctx, projectPath)
	return CandidateReport{Candidates: candidates, Diagnostics: []ScanDiagnostic{}}, err
}

// ResolveCandidateScanner selects the read-only discovery command for a
// workspace. Package manager discovery always uses a read-only container; the
// Docker implementation only reads registry manifests and explicit files.
func ResolveCandidateScanner(ws config.Workspace, cfg config.Config) (CandidateScanner, error) {
	return ResolveCandidateScannerWithOptions(ws, cfg, CandidateScannerOptions{RequireTracked: true})
}

// CandidateScannerOptions binds package discovery to the registered Git
// worktree or to an explicit adhoc input contract.
type CandidateScannerOptions struct {
	AllowProjectConfig bool
	RequireTracked     bool
	Progress           ProgressFunc
	// ToolchainProfile is a scan-prepared embedded default or override. Update
	// callers leave it nil and retain the existing fail-closed resolution path.
	ToolchainProfile *config.ToolchainProfile
}

// ResolveCandidateScannerWithOptions selects scanners with exact input
// contracts. Snapshot/update callers require tracked inputs; the read-only
// scan command may defer that integrity check until snapshot creation.
func ResolveCandidateScannerWithOptions(ws config.Workspace, cfg config.Config, options CandidateScannerOptions) (CandidateScanner, error) {
	if ws.PackageManager != "" {
		if err := toolchain.ValidateManagerSupport(ws.Stack, ws.PackageManager); err != nil {
			return nil, err
		}
	}
	var scanners []CandidateScanner
	packageContract, err := scaninput.PackageContract(ws, options.AllowProjectConfig)
	if err != nil {
		return nil, err
	}
	adapter, scannerProvider, err := candidateScannerProvider(ws)
	if err != nil && ws.PackageManager != "" {
		return nil, err
	}
	if ws.PackageManager != "" && options.ToolchainProfile != nil {
		scanner, err := profilePackageScanner(*options.ToolchainProfile, cfg, ws, packageContract, options)
		if err != nil {
			return nil, err
		}
		scanners = append(scanners, scanner)
	} else if ws.PackageManager != "" && len(cfg.Update.ToolchainProfiles) > 0 {
		profile, _, _, err := toolchain.Resolve(ws, cfg)
		if err != nil {
			return nil, fmt.Errorf("resolve toolchain profile: %w", err)
		}
		scanner, err := profilePackageScanner(profile, cfg, ws, packageContract, options)
		if err != nil {
			return nil, err
		}
		scanners = append(scanners, scanner)
	} else {
		run := NewReadOnlyDockerRunner(cfg.Update.Egress)
		if ws.PackageManager != "" {
			request := ecosystem.ScannerRequest{MinReleaseAgeDays: cfg.Update.MinReleaseAgeDays}
			policy := adapter.(ecosystem.ProfilePolicyProvider).ProfilePolicy()
			request.ProfileScanner = policy.ExpectedScanner
			preview, err := scannerProvider.Scanner(request)
			if err != nil {
				return nil, err
			}
			if preview.LegacyToolKey != "" {
				request.ScannerVersion, err = requireTool(cfg, preview.LegacyToolKey)
				if err != nil {
					return nil, err
				}
			}
			spec, err := scannerProvider.Scanner(request)
			if err != nil {
				return nil, err
			}
			image, err := requireImage(cfg, spec.LegacyImageKey)
			if err != nil {
				return nil, err
			}
			scanners = append(scanners, packageScanner{
				Kind: spec.Kind, Image: image, Args: spec.Args, AcceptedExitCodes: spec.AcceptedExitCodes,
				Decode: adapter.(ecosystem.CandidateDecoder),
				Run:    run, Contract: packageContract, RepositoryRoot: ws.Path, RequireTracked: options.RequireTracked,
			})
		}
	}
	if ws.DockerImages != nil {
		scanners = append(scanners, dockerCandidateScanner{
			Files: ws.DockerImages.Files, Resolve: ResolveDigestViaManifest,
			Contract: scaninput.DockerContract(ws), RepositoryRoot: ws.Path, RequireTracked: options.RequireTracked,
		})
	}
	return combinedScanner{scanners: scanners, progress: options.Progress}, nil
}

// ResolveToolchainProfile returns the exact profile used by production scan
// and update paths. A nil profile indicates a legacy config without a catalog.
func ResolveToolchainProfile(ws config.Workspace, cfg config.Config) (*config.ToolchainProfile, *toolchain.Identity, error) {
	if ws.PackageManager == "" || len(cfg.Update.ToolchainProfiles) == 0 {
		return nil, nil, nil
	}
	profile, identity, _, err := toolchain.Resolve(ws, cfg)
	if err != nil {
		return nil, nil, err
	}
	return &profile, &identity, nil
}

func profilePackageScanner(profile config.ToolchainProfile, cfg config.Config, ws config.Workspace, contract scaninput.Contract, options CandidateScannerOptions) (packageScanner, error) {
	adapter, provider, err := candidateScannerProvider(ws)
	if err != nil {
		return packageScanner{}, err
	}
	if cfg.Update.MinReleaseAgeDays > 0 && !profile.Capabilities.ReleaseAge {
		return packageScanner{}, fmt.Errorf("toolchain profile %q cannot enforce the configured release-age gate", profile.ID)
	}
	spec, err := provider.Scanner(ecosystem.ScannerRequest{
		ProfileScanner: profile.Scanner, ScannerVersion: profile.ScannerVersion,
		InstalledTool: true, MinReleaseAgeDays: cfg.Update.MinReleaseAgeDays,
	})
	if err != nil {
		return packageScanner{}, fmt.Errorf("toolchain profile %q: %w", profile.ID, err)
	}
	return packageScanner{
		Kind: spec.Kind, Image: profile.Image, Args: spec.Args, AcceptedExitCodes: spec.AcceptedExitCodes,
		Decode: adapter.(ecosystem.CandidateDecoder),
		Run:    NewReadOnlyDockerRunnerForProfile(cfg.Update.Egress, profile.User, profile.Platform), Contract: contract,
		RepositoryRoot: ws.Path, RequireTracked: options.RequireTracked,
	}, nil
}

func candidateScannerProvider(ws config.Workspace) (ecosystem.Adapter, ecosystem.ScannerProvider, error) {
	registry, err := catalog.New()
	if err != nil {
		return nil, nil, fmt.Errorf("construct built-in ecosystem catalog: %w", err)
	}
	adapter, err := registry.Lookup(ws.Stack, ws.PackageManager)
	if err != nil {
		return nil, nil, err
	}
	provider, ok := adapter.(ecosystem.ScannerProvider)
	if !ok {
		return nil, nil, &ecosystem.CapabilityError{
			Key: adapter.Key(), Capability: "candidate-scanner",
			Reason: adapter.Metadata().UnsupportedReason,
		}
	}
	if _, ok := adapter.(ecosystem.CandidateDecoder); !ok {
		return nil, nil, &ecosystem.CapabilityError{Key: adapter.Key(), Capability: "candidate-decoder"}
	}
	return adapter, provider, nil
}

type combinedScanner struct {
	scanners []CandidateScanner
	progress ProgressFunc
}

func (s combinedScanner) Scan(ctx context.Context, projectPath string) ([]updatesnapshot.Candidate, error) {
	report, err := s.ScanReport(ctx, projectPath)
	return report.Candidates, err
}

func (s combinedScanner) ScanReport(ctx context.Context, projectPath string) (CandidateReport, error) {
	var candidates []updatesnapshot.Candidate
	var diagnostics []ScanDiagnostic
	for index, scanner := range s.scanners {
		if s.progress != nil {
			s.progress(candidateScannerKind(scanner), index+1, len(s.scanners))
		}
		report, err := ScanCandidateReport(ctx, scanner, projectPath)
		if err != nil {
			return CandidateReport{}, err
		}
		candidates = append(candidates, report.Candidates...)
		diagnostics = append(diagnostics, report.Diagnostics...)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Kind+"/"+candidates[i].Name < candidates[j].Kind+"/"+candidates[j].Name
	})
	sort.Slice(diagnostics, func(i, j int) bool {
		if diagnostics[i].File != diagnostics[j].File {
			return diagnostics[i].File < diagnostics[j].File
		}
		if diagnostics[i].Line != diagnostics[j].Line {
			return diagnostics[i].Line < diagnostics[j].Line
		}
		return diagnostics[i].Code < diagnostics[j].Code
	})
	return CandidateReport{Candidates: candidates, Diagnostics: diagnostics}, nil
}

type kindedCandidateScanner interface {
	candidateScannerKind() string
}

func candidateScannerKind(scanner CandidateScanner) string {
	if kinded, ok := scanner.(kindedCandidateScanner); ok {
		return kinded.candidateScannerKind()
	}
	return "packages"
}

type packageScanner struct {
	Kind, Image       string
	Args              []string
	AcceptedExitCodes []int
	Decode            ecosystem.CandidateDecoder
	Run               ReadOnlyDockerRunner
	Contract          scaninput.Contract
	RepositoryRoot    string
	RequireTracked    bool
}

func (s packageScanner) candidateScannerKind() string {
	return s.Kind
}

func (s packageScanner) Scan(ctx context.Context, projectPath string) ([]updatesnapshot.Candidate, error) {
	report, err := s.ScanReport(ctx, projectPath)
	return report.Candidates, err
}

func (s packageScanner) ScanReport(ctx context.Context, projectPath string) (CandidateReport, error) {
	bundle, err := scaninput.Build(ctx, projectPath, s.RepositoryRoot, scaninput.Options{RequireTracked: s.RequireTracked}, s.Contract)
	if err != nil {
		return CandidateReport{}, err
	}
	defer bundle.Destroy()
	out, err := s.Run(ctx, s.Image, s.Args, bundle)
	if err != nil && !acceptedDiscoveryExit(s.AcceptedExitCodes, err) {
		return CandidateReport{}, err
	}
	decoder := s.Decode
	if decoder == nil {
		decoder, err = decoderForKind(s.Kind)
		if err != nil {
			return CandidateReport{}, err
		}
	}
	inputs := make(map[string][]byte, len(s.Contract.Files))
	for _, file := range s.Contract.Files {
		if content, ok := bundle.Content(file.Path); ok {
			inputs[file.Path] = content
		}
	}
	decoded, err := decoder.DecodeCandidates([]byte(out), inputs)
	if err != nil {
		return CandidateReport{}, fmt.Errorf("parse %s update candidates: %w", s.Kind, err)
	}
	report := CandidateReport{
		Candidates:  make([]updatesnapshot.Candidate, len(decoded.Candidates)),
		Diagnostics: make([]ScanDiagnostic, len(decoded.Diagnostics)),
	}
	for index, candidate := range decoded.Candidates {
		report.Candidates[index] = updatesnapshot.Candidate{
			Kind: candidate.Kind, Name: candidate.Name, Current: candidate.Current,
			Target: candidate.Target, File: candidate.File,
		}
	}
	for index, diagnostic := range decoded.Diagnostics {
		report.Diagnostics[index] = ScanDiagnostic{
			File: diagnostic.File, Line: diagnostic.Line, Code: diagnostic.Code,
			Severity: diagnostic.Severity, Message: diagnostic.Message,
		}
	}
	return report, nil
}

type exitCoder interface {
	ExitCode() int
}

// pnpm outdated deliberately exits 1 when it successfully finds outdated
// dependencies. The output is still treated as untrusted and must pass the
// same strict JSON/candidate validation before it can become a plan.
func acceptedDiscoveryExit(allowed []int, err error) bool {
	var exit exitCoder
	if !errors.As(err, &exit) {
		return false
	}
	for _, code := range allowed {
		if exit.ExitCode() == code {
			return true
		}
	}
	return false
}

// parsePackageCandidates accepts the JSON shapes emitted by Poetry, the
// pip-tools metadata scanner, pnpm, uv, and npm-check-updates. Unknown or
// malformed records are rejected so
// untrusted registry metadata can never become an executable update plan.
func parsePackageCandidates(kind string, data []byte) ([]updatesnapshot.Candidate, error) {
	report, err := parsePackageReport(kind, data)
	return report.Candidates, err
}

func parsePackageReport(kind string, data []byte) (CandidateReport, error) {
	decoder, err := decoderForKind(kind)
	if err != nil {
		return CandidateReport{}, err
	}
	inputs := make(map[string][]byte)
	registry, err := catalog.New()
	if err != nil {
		return CandidateReport{}, err
	}
	for _, adapter := range registry.Adapters() {
		if adapter.Key().PackageManager != kind {
			continue
		}
		if provider, ok := adapter.(ecosystem.InputProvider); ok {
			for _, file := range provider.PackageInput(false).Files {
				if file.Category == ecosystem.InputCategoryLock ||
					kind == "requirements" || kind == "pip-tools" {
					inputs[file.Path] = []byte("{}")
				}
			}
		}
	}
	decoded, err := decoder.DecodeCandidates(data, inputs)
	if err != nil {
		return CandidateReport{}, err
	}
	report := CandidateReport{
		Candidates:  make([]updatesnapshot.Candidate, len(decoded.Candidates)),
		Diagnostics: make([]ScanDiagnostic, len(decoded.Diagnostics)),
	}
	for index, candidate := range decoded.Candidates {
		report.Candidates[index] = updatesnapshot.Candidate{
			Kind: candidate.Kind, Name: candidate.Name, Current: candidate.Current,
			Target: candidate.Target, File: candidate.File,
		}
	}
	for index, diagnostic := range decoded.Diagnostics {
		report.Diagnostics[index] = ScanDiagnostic{
			File: diagnostic.File, Line: diagnostic.Line, Code: diagnostic.Code,
			Severity: diagnostic.Severity, Message: diagnostic.Message,
		}
	}
	return report, nil
}

var candidatePartPattern = regexp.MustCompile(`^[A-Za-z0-9@._+!/-]+$`)

func validCandidate(candidate updatesnapshot.Candidate) bool {
	return candidatePartPattern.MatchString(candidate.Name) && candidatePartPattern.MatchString(candidate.Target) && (candidate.Current == "" || candidatePartPattern.MatchString(candidate.Current))
}

func decoderForKind(kind string) (ecosystem.CandidateDecoder, error) {
	registry, err := catalog.New()
	if err != nil {
		return nil, fmt.Errorf("construct built-in ecosystem catalog: %w", err)
	}
	var decoder ecosystem.CandidateDecoder
	for _, adapter := range registry.Adapters() {
		if adapter.Key().PackageManager != kind {
			continue
		}
		candidateDecoder, ok := adapter.(ecosystem.CandidateDecoder)
		if !ok || decoder != nil {
			return nil, fmt.Errorf("candidate decoder %q is unavailable or ambiguous", kind)
		}
		decoder = candidateDecoder
	}
	if decoder == nil {
		return nil, fmt.Errorf("candidate decoder %q is unavailable or ambiguous", kind)
	}
	return decoder, nil
}

type dockerCandidateScanner struct {
	Files          []string
	Resolve        DigestResolver
	Contract       scaninput.Contract
	RepositoryRoot string
	RequireTracked bool
}

func (dockerCandidateScanner) candidateScannerKind() string {
	return "docker"
}

func (s dockerCandidateScanner) Scan(ctx context.Context, projectPath string) ([]updatesnapshot.Candidate, error) {
	bundle, err := scaninput.Build(ctx, projectPath, s.RepositoryRoot, scaninput.Options{RequireTracked: s.RequireTracked}, s.Contract)
	if err != nil {
		return nil, err
	}
	defer bundle.Destroy()
	var candidates []updatesnapshot.Candidate
	for _, rel := range s.Files {
		data, ok := bundle.Content(rel)
		if !ok {
			return nil, fmt.Errorf("validated Docker scan input %s is unavailable", rel)
		}
		for _, match := range imageReferences(string(data)) {
			digest, err := s.Resolve(ctx, match.ref)
			if err != nil {
				return nil, fmt.Errorf("resolve digest for %s: %w", match.ref, err)
			}
			if digest != match.digest {
				candidates = append(candidates, updatesnapshot.Candidate{Kind: "docker", Name: match.ref, Current: match.digest, Target: digest, File: rel})
			}
		}
	}
	return candidates, nil
}

type imageReference struct{ ref, digest string }

func imageReferences(content string) []imageReference {
	var refs []imageReference
	for _, line := range strings.Split(content, "\n") {
		match := fromLinePattern.FindStringSubmatch(line)
		if match == nil {
			match = imageLinePattern.FindStringSubmatch(line)
		}
		if match != nil && match[3] != "" {
			refs = append(refs, imageReference{ref: match[2], digest: strings.TrimPrefix(match[3], "@")})
		}
	}
	return refs
}

// PlannedUpdater executes only the candidate names and target versions stored
// in a validated snapshot. Validate and Recheck are run before the first
// mutable command; a failed check therefore leaves the sandbox untouched.
type PlannedUpdater struct {
	Candidates   []updatesnapshot.Candidate
	Workspace    config.Workspace
	Config       config.Config
	AllowScripts bool
	Validate     func(context.Context) error
	Recheck      CandidateScanner
	Run          DockerRunner
}

func (u PlannedUpdater) Update(ctx context.Context, projectPath string) (bool, error) {
	if u.Validate == nil || u.Recheck == nil {
		return false, errors.New("snapshot updater is missing validation")
	}
	if err := u.Validate(ctx); err != nil {
		return false, err
	}
	current, err := u.Recheck.Scan(ctx, u.Workspace.Path)
	if err != nil {
		return false, fmt.Errorf("recheck snapshot candidates: %w", err)
	}
	if !containsAll(current, u.Candidates) {
		return false, fmt.Errorf("snapshot candidate no longer exists")
	}
	return u.apply(ctx, projectPath)
}

func containsAll(current, planned []updatesnapshot.Candidate) bool {
	seen := make(map[string]bool, len(current))
	for _, candidate := range current {
		seen[candidate.Kind+"\x00"+candidate.Name+"\x00"+candidate.Target+"\x00"+candidate.File] = true
	}
	for _, candidate := range planned {
		if !seen[candidate.Kind+"\x00"+candidate.Name+"\x00"+candidate.Target+"\x00"+candidate.File] {
			return false
		}
	}
	return true
}

func (u PlannedUpdater) apply(ctx context.Context, projectPath string) (bool, error) {
	if len(u.Candidates) == 0 {
		return false, nil
	}
	changed := false
	if hasDockerCandidates(u.Candidates) {
		dockerChanged, err := plannedDockerUpdater{Candidates: u.Candidates}.Update(ctx, projectPath)
		if err != nil || onlyDocker(u.Candidates) {
			return dockerChanged, err
		}
		changed = dockerChanged
	}
	profile, _, err := ResolveToolchainProfile(u.Workspace, u.Config)
	if err != nil {
		return false, fmt.Errorf("resolve toolchain profile: %w", err)
	}
	user := ""
	platform := ""
	if profile != nil {
		user = profile.User
		platform = profile.Platform
	}
	runner := u.Run
	if runner == nil {
		runner = NewDockerRunnerForProfile(u.Config.Update.Egress, user, platform)
	}
	packageCandidates := nonDockerCandidates(u.Candidates)
	spec, err := resolvePlannedMutationSpec(u.Workspace, u.Config, profile, packageCandidates, u.AllowScripts)
	if err != nil {
		return false, err
	}
	image := ""
	if profile != nil {
		image = profile.Image
	} else {
		image, err = requireImage(u.Config, spec.LegacyImageKey)
		if err != nil {
			return false, err
		}
	}
	if err := validatePlannedMutationSpec(spec, packageCandidates); err != nil {
		return false, err
	}
	before, err := lockDigest(projectPath, spec.LockFile)
	if err != nil {
		return false, err
	}
	for _, mutation := range spec.Mutations {
		candidate := updatesnapshot.Candidate{
			Kind: mutation.Candidate.Kind, Name: mutation.Candidate.Name,
			Current: mutation.Candidate.Current, Target: mutation.Candidate.Target, File: mutation.Candidate.File,
		}
		switch mutation.Rewrite {
		case "":
		case "python-requirement-exact-pin":
			if err := rewritePipToolsPin(projectPath, candidate); err != nil {
				return false, err
			}
		default:
			return false, fmt.Errorf("adapter returned unsupported manifest rewrite %q", mutation.Rewrite)
		}
		for _, args := range mutation.Commands {
			if _, err := runner(ctx, image, args, projectPath); err != nil {
				return false, err
			}
		}
	}
	for _, args := range spec.FinalCommands {
		if _, err := runner(ctx, image, args, projectPath); err != nil {
			return false, err
		}
	}
	switch spec.Validation {
	case "":
	case "npm-exact-targets":
		if err := validateNPMCandidateTargets(projectPath, packageCandidates); err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("adapter returned unsupported mutation validation %q", spec.Validation)
	}
	after, err := lockDigest(projectPath, spec.LockFile)
	if err != nil {
		return false, err
	}
	return changed || before != after, nil
}

func resolvePlannedMutationSpec(
	workspace config.Workspace,
	cfg config.Config,
	profile *config.ToolchainProfile,
	candidates []updatesnapshot.Candidate,
	allowScripts bool,
) (ecosystem.PlannedMutationSpec, error) {
	registry, err := catalog.New()
	if err != nil {
		return ecosystem.PlannedMutationSpec{}, fmt.Errorf("construct built-in ecosystem catalog: %w", err)
	}
	adapter, err := registry.Lookup(workspace.Stack, workspace.PackageManager)
	if err != nil {
		return ecosystem.PlannedMutationSpec{}, err
	}
	provider, ok := adapter.(ecosystem.PlannedMutationProvider)
	if !ok {
		return ecosystem.PlannedMutationSpec{}, &ecosystem.CapabilityError{
			Key: adapter.Key(), Capability: "planned-mutation",
			ScanOnly: adapter.Metadata().UnsupportedReason == "", Reason: adapter.Metadata().UnsupportedReason,
		}
	}
	request := ecosystem.PlannedMutationRequest{
		Root: workspace.Path, Candidates: make([]ecosystem.Candidate, len(candidates)),
		AllowScripts: allowScripts, MinReleaseAgeDays: cfg.Update.MinReleaseAgeDays,
	}
	for index, candidate := range candidates {
		if !validCandidate(candidate) {
			return ecosystem.PlannedMutationSpec{}, errors.New("invalid snapshot candidate")
		}
		request.Candidates[index] = ecosystem.Candidate{
			Kind: candidate.Kind, Name: candidate.Name, Current: candidate.Current,
			Target: candidate.Target, File: candidate.File,
		}
	}
	if profile != nil {
		request.ProfileScanner = profile.Scanner
		request.ScannerVersion = profile.ScannerVersion
		request.InstalledTool = true
	} else if policy, ok := adapter.(ecosystem.ProfilePolicyProvider); ok {
		request.ProfileScanner = policy.ProfilePolicy().ExpectedScanner
	}
	spec, err := provider.PlannedMutation(request)
	if err != nil {
		return ecosystem.PlannedMutationSpec{}, err
	}
	if profile == nil && spec.LegacyToolKey != "" {
		request.ScannerVersion, err = requireTool(cfg, spec.LegacyToolKey)
		if err != nil {
			return ecosystem.PlannedMutationSpec{}, err
		}
		spec, err = provider.PlannedMutation(request)
	}
	return spec, err
}

func validatePlannedMutationSpec(spec ecosystem.PlannedMutationSpec, candidates []updatesnapshot.Candidate) error {
	if spec.LockFile == "" || filepath.Base(spec.LockFile) != spec.LockFile || strings.ContainsAny(spec.LockFile, `/\`+"\x00") {
		return fmt.Errorf("adapter returned invalid mutation lock file %q", spec.LockFile)
	}
	if len(spec.Mutations) != len(candidates) {
		return errors.New("adapter mutation plan does not bind every candidate exactly once")
	}
	expected := make(map[string]int, len(candidates))
	for _, candidate := range candidates {
		expected[candidateKey(candidate)]++
	}
	for _, mutation := range spec.Mutations {
		candidate := updatesnapshot.Candidate{
			Kind: mutation.Candidate.Kind, Name: mutation.Candidate.Name,
			Current: mutation.Candidate.Current, Target: mutation.Candidate.Target, File: mutation.Candidate.File,
		}
		key := candidateKey(candidate)
		if expected[key] == 0 {
			return errors.New("adapter mutation plan introduced an unreviewed candidate")
		}
		expected[key]--
		if err := validateAdapterCommands(mutation.Commands); err != nil {
			return err
		}
	}
	return validateAdapterCommands(spec.FinalCommands)
}

func validateAdapterCommands(commands [][]string) error {
	for commandIndex, command := range commands {
		if len(command) == 0 {
			return fmt.Errorf("adapter mutation command %d is empty", commandIndex)
		}
		for argumentIndex, argument := range command {
			if argument == "" || strings.ContainsRune(argument, '\x00') {
				return fmt.Errorf("adapter mutation command %d argument %d is invalid", commandIndex, argumentIndex)
			}
		}
	}
	return nil
}

func candidateKey(candidate updatesnapshot.Candidate) string {
	return candidate.Kind + "\x00" + candidate.Name + "\x00" + candidate.Current + "\x00" + candidate.Target + "\x00" + candidate.File
}

func validateNPMCandidateTargets(root string, candidates []updatesnapshot.Candidate) error {
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return fmt.Errorf("read updated package.json: %w", err)
	}
	var manifest struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parse updated package.json: %w", err)
	}
	sections := []map[string]string{manifest.Dependencies, manifest.DevDependencies, manifest.OptionalDependencies, manifest.PeerDependencies}
	for _, candidate := range candidates {
		if candidate.Kind != "npm" {
			continue
		}
		matches := 0
		spec := ""
		for _, section := range sections {
			if value, ok := section[candidate.Name]; ok {
				matches++
				spec = value
			}
		}
		if matches != 1 || !npmSpecTargets(spec, candidate.Target) {
			return fmt.Errorf("npm candidate %q was not pinned to reviewed target %q", candidate.Name, candidate.Target)
		}
	}
	return nil
}

func npmSpecTargets(spec, target string) bool {
	value := strings.TrimSpace(spec)
	for _, prefix := range []string{">=", "<=", "^", "~", ">", "<", "="} {
		if strings.HasPrefix(value, prefix) {
			value = strings.TrimSpace(strings.TrimPrefix(value, prefix))
			break
		}
	}
	value = strings.TrimPrefix(value, "v")
	return value == target
}

func nonDockerCandidates(candidates []updatesnapshot.Candidate) []updatesnapshot.Candidate {
	result := make([]updatesnapshot.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Kind != "docker" {
			result = append(result, candidate)
		}
	}
	return result
}

var pipToolsPinPattern = regexp.MustCompile(`^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^]\r\n]+\])?(\s*==\s*)([A-Za-z0-9][A-Za-z0-9.!+_-]*)(\s*(?:#.*)?)$`)
var pythonNameSeparatorPattern = regexp.MustCompile(`[-_.]+`)

func rewritePipToolsPin(projectPath string, candidate updatesnapshot.Candidate) error {
	if candidate.Current == "" {
		return fmt.Errorf("pip-tools candidate %q has no current exact pin", candidate.Name)
	}
	path := filepath.Join(projectPath, "requirements.in")
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect requirements.in: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("requirements.in must be a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read requirements.in: %w", err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	wanted := normalizePythonPackage(candidate.Name)
	matches := 0
	for index, lineWithEnding := range lines {
		line := strings.TrimSuffix(lineWithEnding, "\n")
		ending := strings.TrimPrefix(lineWithEnding, line)
		parts := pipToolsPinPattern.FindStringSubmatch(strings.TrimSuffix(line, "\r"))
		if parts == nil || normalizePythonPackage(parts[2]) != wanted {
			continue
		}
		matches++
		if parts[5] != candidate.Current {
			return fmt.Errorf("pip-tools pin for %q changed from snapshot version %q", candidate.Name, candidate.Current)
		}
		carriageReturn := ""
		if strings.HasSuffix(line, "\r") {
			carriageReturn = "\r"
		}
		lines[index] = parts[1] + parts[2] + parts[3] + parts[4] + candidate.Target + parts[6] + carriageReturn + ending
	}
	if matches != 1 {
		return fmt.Errorf("requirements.in must contain exactly one direct exact pin for %q", candidate.Name)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")), info.Mode().Perm()); err != nil {
		return fmt.Errorf("write requirements.in: %w", err)
	}
	return nil
}

func normalizePythonPackage(name string) string {
	return strings.ToLower(pythonNameSeparatorPattern.ReplaceAllString(name, "-"))
}

func hasDockerCandidates(candidates []updatesnapshot.Candidate) bool {
	for _, candidate := range candidates {
		if candidate.Kind == "docker" {
			return true
		}
	}
	return false
}
func onlyDocker(candidates []updatesnapshot.Candidate) bool {
	for _, candidate := range candidates {
		if candidate.Kind != "docker" {
			return false
		}
	}
	return true
}

type plannedDockerUpdater struct{ Candidates []updatesnapshot.Candidate }

func (u plannedDockerUpdater) Update(_ context.Context, projectPath string) (bool, error) {
	changed := false
	for _, candidate := range u.Candidates {
		if candidate.Kind != "docker" {
			continue
		}
		if filepath.IsAbs(candidate.File) || candidate.File == "" || candidate.File == ".." || strings.HasPrefix(filepath.Clean(candidate.File), ".."+string(filepath.Separator)) {
			return changed, errors.New("invalid docker snapshot file")
		}
		path := filepath.Join(projectPath, candidate.File)
		data, err := os.ReadFile(path)
		if err != nil {
			return changed, err
		}
		old := candidate.Name + "@" + candidate.Current
		newRef := candidate.Name + "@" + candidate.Target
		if !strings.Contains(string(data), old) {
			return changed, fmt.Errorf("docker candidate %s is no longer present", candidate.Name)
		}
		if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(data), old, newRef)), 0o644); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}
