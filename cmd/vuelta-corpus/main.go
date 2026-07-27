// Command vuelta-corpus is the container-only entrypoint for the manual
// real-world corpus scan and refresh workflows.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/corpus"
)

const defaultManifestPath = "/src/acceptance/corpus.example.yaml"

type scanOptions struct {
	root       string
	manifest   string
	stableOnly bool
	caseName   string
	onlyFailed string
}

func main() {
	code, err := run(context.Background(), os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "vuelta-corpus:", err)
	}
	os.Exit(code)
}

func run(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		return 2, errors.New("usage: vuelta-corpus scan ROOT [--stable-only | --case NAME | --only-failed REPORT] | refresh ROOT")
	}
	switch args[0] {
	case "scan":
		options, err := parseScanOptions(args[1:])
		if err != nil {
			return 2, err
		}
		return runScan(ctx, options)
	case "refresh":
		options, err := parseRefreshOptions(args[1:])
		if err != nil {
			return 2, err
		}
		return runRefresh(ctx, options)
	default:
		return 2, errors.New("first argument must be scan or refresh")
	}
}

func parseScanOptions(args []string) (scanOptions, error) {
	options := scanOptions{manifest: defaultManifestPath}
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--stable-only":
			options.stableOnly = true
		case "--case":
			index++
			if index >= len(args) || args[index] == "" {
				return options, errors.New("--case requires NAME")
			}
			options.caseName = args[index]
		case "--only-failed":
			index++
			if index >= len(args) || args[index] == "" {
				return options, errors.New("--only-failed requires an absolute report path")
			}
			options.onlyFailed = args[index]
		case "--manifest":
			index++
			if index >= len(args) || args[index] == "" {
				return options, errors.New("--manifest requires PATH")
			}
			options.manifest = args[index]
		default:
			if len(args[index]) > 0 && args[index][0] == '-' {
				return options, fmt.Errorf("unknown option %q", args[index])
			}
			if options.root != "" {
				return options, errors.New("exactly one corpus ROOT is required")
			}
			options.root = args[index]
		}
	}
	if options.root == "" {
		return options, errors.New("corpus ROOT is required")
	}
	if !filepath.IsAbs(options.root) || !filepath.IsAbs(options.manifest) {
		return options, errors.New("corpus ROOT and manifest path must be absolute")
	}
	if options.caseName != "" && options.onlyFailed != "" {
		return options, errors.New("--case and --only-failed are mutually exclusive")
	}
	if options.stableOnly && (options.caseName != "" || options.onlyFailed != "") {
		return options, errors.New("--stable-only cannot be combined with a case filter")
	}
	return options, nil
}

func parseRefreshOptions(args []string) (scanOptions, error) {
	options := scanOptions{manifest: defaultManifestPath}
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--manifest":
			index++
			if index >= len(args) {
				return options, errors.New("--manifest requires PATH")
			}
			options.manifest = args[index]
		default:
			if len(args[index]) > 0 && args[index][0] == '-' {
				return options, fmt.Errorf("unknown option %q", args[index])
			}
			if options.root != "" {
				return options, errors.New("exactly one corpus ROOT is required")
			}
			options.root = args[index]
		}
	}
	if options.root == "" || !filepath.IsAbs(options.root) || !filepath.IsAbs(options.manifest) {
		return options, errors.New("absolute corpus ROOT and manifest path are required")
	}
	return options, nil
}

func runScan(ctx context.Context, options scanOptions) (int, error) {
	sourceRoot, err := filepath.Abs(".")
	if err != nil {
		return 2, err
	}
	if err := validateRoot(options.root, sourceRoot); err != nil {
		return 2, err
	}
	manifestBytes, manifest, err := loadStableManifest(options.manifest)
	if err != nil {
		return 2, err
	}
	var failed map[string]bool
	if options.onlyFailed != "" {
		if !filepath.IsAbs(options.onlyFailed) {
			return 2, errors.New("--only-failed report path must be absolute")
		}
		previous, loadErr := corpus.LoadReport(options.onlyFailed)
		if loadErr != nil {
			return 2, loadErr
		}
		failed = corpus.FailedStableCases(previous)
		if len(failed) == 0 {
			return 2, errors.New("selected report contains no stable failures")
		}
	}
	stable, selectErr := corpus.SelectStableCases(manifest.Cases, options.caseName, failed)
	var discovery []corpus.Case
	if selectErr != nil && options.caseName != "" {
		recorded, ok, findErr := corpus.DiscoveryCaseFromReports(options.root, options.caseName)
		if findErr != nil {
			return 2, findErr
		}
		if !ok {
			return 2, selectErr
		}
		stable = nil
		discovery = []corpus.Case{recorded}
	} else if selectErr != nil {
		return 2, selectErr
	}
	var warnings []string
	if !options.stableOnly && options.caseName == "" && options.onlyFailed == "" {
		discovery, warnings = (corpus.GitHubClient{}).Discover(ctx)
	}
	return executeHarness(ctx, sourceRoot, options.root, manifestBytes, stable, discovery, warnings)
}

func runRefresh(ctx context.Context, options scanOptions) (int, error) {
	sourceRoot, err := filepath.Abs(".")
	if err != nil {
		return 2, err
	}
	if err := validateRoot(options.root, sourceRoot); err != nil {
		return 2, err
	}
	manifestBytes, manifest, err := loadStableManifest(options.manifest)
	if err != nil {
		return 2, err
	}
	refreshed, diff, err := (corpus.GitHubClient{}).RefreshCases(ctx, manifest.Cases)
	if err != nil {
		return 1, err
	}
	candidate, err := corpus.MarshalCandidateManifest(refreshed)
	if err != nil {
		return 1, err
	}
	exit, reportDir, err := executeHarnessWithDir(ctx, sourceRoot, options.root, manifestBytes, refreshed, nil, nil)
	if err != nil {
		return exit, err
	}
	if exit != 0 {
		return exit, nil
	}
	if err := corpus.WriteCandidateFiles(reportDir, candidate, diff); err != nil {
		return 1, err
	}
	fmt.Printf("candidate manifest: %s\ncandidate diff: %s\n",
		filepath.Join(reportDir, "candidate-manifest.yaml"), filepath.Join(reportDir, "candidate.diff"))
	return exit, nil
}

func executeHarness(
	ctx context.Context,
	sourceRoot, root string,
	manifest []byte,
	stable, discovery []corpus.Case,
	warnings []string,
) (int, error) {
	exit, _, err := executeHarnessWithDir(ctx, sourceRoot, root, manifest, stable, discovery, warnings)
	return exit, err
}

func executeHarnessWithDir(
	ctx context.Context,
	sourceRoot, root string,
	manifest []byte,
	stable, discovery []corpus.Case,
	warnings []string,
) (int, string, error) {
	socket := os.Getenv("VUELTA_CORPUS_DOCKER_SOCKET")
	if socket == "" {
		socket = "/var/run/docker.sock"
	}
	scanner := &corpus.ProductionScanner{SourceRoot: sourceRoot, DockerSocket: socket}
	report, reportDir, exit, err := (corpus.Harness{
		Sources: corpus.SourceStore{}, Scanner: scanner,
	}).Execute(ctx, corpus.HarnessInput{
		Root: root, ManifestBytes: manifest, Stable: stable, Discovery: discovery,
		AppRevision: corpus.SourceRevision(ctx, sourceRoot), Now: time.Now(), Warnings: warnings,
	})
	if err != nil {
		return exit, reportDir, err
	}
	fmt.Printf("report JSON: %s\nreport Markdown: %s\nstable: %d passed, %d failed; discovery: %d passed, %d findings\n",
		filepath.Join(reportDir, "report.json"), filepath.Join(reportDir, "report.md"),
		report.Summary.StablePassed, report.Summary.StableFailed,
		report.Summary.DiscoveryPassed, report.Summary.DiscoveryFindings)
	return exit, reportDir, nil
}

func loadStableManifest(filename string) ([]byte, corpus.Manifest, error) {
	manifest, err := corpus.LoadManifest(filename, false)
	if err != nil {
		return nil, corpus.Manifest{}, err
	}
	if err := manifest.ValidateStableCoverage(); err != nil {
		return nil, corpus.Manifest{}, err
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, corpus.Manifest{}, err
	}
	return data, manifest, nil
}

func validateRoot(root, sourceRoot string) error {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return errors.New("corpus ROOT must be an existing directory")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return errors.New("corpus ROOT cannot be resolved")
	}
	resolvedSource, err := filepath.EvalSymlinks(sourceRoot)
	if err != nil {
		return errors.New("app source root cannot be resolved")
	}
	resolvedRoot = filepath.Clean(resolvedRoot)
	resolvedSource = filepath.Clean(resolvedSource)
	if resolvedRoot == string(filepath.Separator) || resolvedRoot == resolvedSource ||
		isWithin(resolvedRoot, resolvedSource) || isWithin(resolvedSource, resolvedRoot) {
		return errors.New("corpus ROOT must be outside the app/workspace source tree")
	}
	return nil
}

func isWithin(candidate, parent string) bool {
	relative, err := filepath.Rel(parent, candidate)
	return err == nil && relative != "." && relative != ".." &&
		!filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
