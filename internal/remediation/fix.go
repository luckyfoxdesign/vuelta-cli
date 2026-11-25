// Package remediation repairs vulnerability findings through reviewed adapter
// commands in minimal private copies. It owns no commits, pushes or project tests.
package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/adhoc"
	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/dockerexec"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"github.com/luckyfoxdesign/vuelta/internal/ecosystems/catalog"
	"github.com/luckyfoxdesign/vuelta/internal/githubalerts"
	"github.com/luckyfoxdesign/vuelta/internal/toolchain"
	"github.com/luckyfoxdesign/vuelta/internal/updater"
	"github.com/luckyfoxdesign/vuelta/internal/vulnscan"
)

// ErrPartial means a required scan or mutation could not be completed.
var ErrPartial = errors.New("vulnerability repair returned partial results")

var errNeedsParentUpgrade = errors.New("original transitive finding remains after candidate mutation")

// Options selects findings without broadening the admitted input files.
type Options struct {
	FindingIDs  []string
	MinSeverity string
	Diagnostic  func(error)
}

// Repair is one deterministic decision before mutation.
type Repair struct {
	Finding       vulnscan.Finding
	TargetVersion string
	Reason        string
	Dependency    ecosystem.FixDependency
}

// Skipped preserves the finding and a stable reason for not changing it.
// TargetVersion is the last version a candidate was built for, empty when no
// candidate was attempted.
type Skipped struct {
	Finding       vulnscan.JSONFinding `json:"finding"`
	Reason        string               `json:"reason"`
	TargetVersion string               `json:"target_version,omitempty"`
}

// FixedFinding is a repaired finding with the dependency version written to
// the project. TargetVersion is empty for repairs that do not pin a version.
type FixedFinding struct {
	vulnscan.JSONFinding
	TargetVersion string `json:"target_version,omitempty"`
}

// Result distinguishes a complete clean rescan from unavailable coverage.
type Result struct {
	Fixed        []FixedFinding         `json:"fixed"`
	Skipped      []Skipped              `json:"skipped"`
	ChangedFiles []string               `json:"changed_files"`
	Rescan       []vulnscan.JSONFinding `json:"rescan"`
	Complete     bool                   `json:"complete"`
}

// Engine supplies narrow execution boundaries for network-free behavioral tests.
// Nil functions select the production Docker-backed implementations.
type Engine struct {
	Scan    func(context.Context, string, config.Workspace, config.Config, bool) (vulnscan.Report, error)
	Prepare func(context.Context, config.Workspace, config.Config) (config.ToolchainProfile, error)
	Command func(context.Context, config.ToolchainProfile, []string, string) (string, error)
}

var versionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}$`)
var packagePattern = regexp.MustCompile(`^(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func severity(value string) int {
	switch vulnscan.NormalizeSeverity(value) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func numericVersion(value string) ([4]uint64, bool) {
	var v [4]uint64
	if len(value) > 80 || !versionPattern.MatchString(value) {
		return v, false
	}
	for i, part := range strings.Split(value, ".") {
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func compare(a, b [4]uint64) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func selected(f vulnscan.Finding, options Options) bool {
	if severity(f.Severity) < severity(options.MinSeverity) {
		return false
	}
	if len(options.FindingIDs) == 0 {
		return true
	}
	for _, id := range options.FindingIDs {
		if f.ID == id {
			return true
		}
	}
	return false
}

// Plan selects the lowest reported stable fixed version above the installed
// version within its current major. Unsupported version grammars fail closed.
// The metadata map is keyed by the source's package name.
func Plan(findings []vulnscan.Finding, metadata map[string]ecosystem.FixDependency, options Options) ([]Repair, error) {
	if options.MinSeverity != "" && options.MinSeverity != "critical" && options.MinSeverity != "high" && options.MinSeverity != "medium" && options.MinSeverity != "low" && options.MinSeverity != "unknown" {
		return nil, errors.New("invalid minimum severity")
	}
	ordered := append([]vulnscan.Finding(nil), findings...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Key() < ordered[j].Key() })
	plan := make([]Repair, 0, len(ordered))
	for _, f := range ordered {
		r := Repair{Finding: f, Dependency: metadata[f.Package]}
		switch {
		case !selected(f, options):
			r.Reason = "filtered"
		case f.Kind == "image": // Image targets require candidate scans, not OS package bumps.
		case strings.TrimSpace(f.FixedVersion) == "":
			r.Reason = "no_fix"
		case !packagePattern.MatchString(f.Package):
			r.Reason = "invalid_package"
		default:
			installed := f.InstalledVersion
			if installed == "" && len(r.Dependency.Versions) == 1 {
				installed = r.Dependency.Versions[0]
			}
			current, ok := numericVersion(installed)
			if !ok {
				r.Reason = "unsupported_installed_version"
				break
			}
			var best [4]uint64
			hasBest, hasMajor := false, false
			for _, fixed := range strings.Split(f.FixedVersion, ",") {
				fixed = strings.TrimSpace(fixed)
				v, ok := numericVersion(fixed)
				if !ok || compare(v, current) <= 0 {
					continue
				}
				if v[0] != current[0] {
					hasMajor = true
					continue
				}
				if !hasBest || compare(v, best) < 0 {
					best = v
					r.TargetVersion = fixed
					hasBest = true
				}
			}
			if !hasBest {
				r.Reason = "no_compatible_fix"
				if hasMajor {
					r.Reason = "needs_major"
				}
			}
		}
		plan = append(plan, r)
	}
	return plan, nil
}

func scan(ctx context.Context, root string, ws config.Workspace, cfg config.Config, tracked bool) (vulnscan.Report, error) {
	ws.Path = root
	s := vulnscan.NewReadOnlyScanner()
	if tracked {
		s = vulnscan.NewTrackedScanner()
	}
	if ws.PackageManager == "" {
		return s.ScanImages(ctx, root, ws, cfg)
	}
	if cfg.VulnScan.DependencySource != "github-dependabot" {
		return s.Scan(ctx, root, ws, cfg)
	}
	r, err := s.ScanImages(ctx, root, ws, cfg)
	if err != nil {
		return r, err
	}
	findings, err := (githubalerts.Client{}).Scan(ctx, ws, cfg.GithubAdvisories)
	r.Findings = append(r.Findings, findings...)
	return r, err
}

func mutationUser() string {
	uid, gid := os.Geteuid(), os.Getegid()
	if uid == 0 {
		uid, gid = 65532, 65532
	}
	return fmt.Sprintf("%d:%d", uid, gid)
}

func preparePrivate(root string, files []string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	for _, name := range append([]string{"."}, files...) {
		if err := os.Chown(filepath.Join(root, name), 65532, 65532); err != nil {
			return errors.New("cannot assign private copy to non-root mutation user")
		}
	}
	return nil
}

func packageFiles(ws config.Workspace, adapter ecosystem.Adapter) ([]string, string, error) {
	provider, ok := adapter.(ecosystem.InputProvider)
	if !ok {
		return nil, "", errors.New("adapter has no package input contract")
	}
	contract := provider.PackageInput(false)
	if resolver, ok := adapter.(ecosystem.RootInputProvider); ok {
		var err error
		contract, err = resolver.PackageInputForRoot(ws.Path, false)
		if err != nil {
			return nil, "", err
		}
	}
	files := []string{}
	manifest, lock := "", ""
	for _, file := range contract.Files {
		if file.Category != ecosystem.InputCategoryManifest && file.Category != ecosystem.InputCategoryLock {
			continue
		}
		if _, err := os.Lstat(filepath.Join(ws.Path, file.Path)); errors.Is(err, os.ErrNotExist) && file.Optional {
			continue
		}
		files = append(files, file.Path)
		if file.Category == ecosystem.InputCategoryManifest {
			manifest = file.Path
		}
		if file.Category == ecosystem.InputCategoryLock {
			lock = file.Path
		}
	}
	if manifest == "" || lock == "" {
		return nil, "", errors.New("repair needs a manifest and lockfile")
	}
	return files, manifest, nil
}

func sameFinding(a, b vulnscan.Finding) bool {
	kindA, kindB := a.Kind, b.Kind
	if kindA == "" {
		kindA = "package"
	}
	if kindB == "" {
		kindB = "package"
	}
	return a.ID == b.ID && a.Package == b.Package && kindA == kindB && a.Image == b.Image
}

func remains(f vulnscan.Finding, findings []vulnscan.Finding) bool {
	for _, other := range findings {
		if sameFinding(f, other) {
			return true
		}
	}
	return false
}

// introducedError reports a candidate that closed the original findings but
// carries findings absent from the baseline scan.
type introducedError struct{ findings []vulnscan.Finding }

func (*introducedError) Error() string { return "candidate introduced a new vulnerability" }

// nextTarget picks the lowest version above current, inside current's major,
// that the scanner reports as fixed for the new findings. It fails closed when
// any new finding belongs to another package or has no such version, because
// moving this package cannot repair it. Every call returns a strictly higher
// version, so a retry chain within one major always terminates.
func nextTarget(name, current string, introduced []vulnscan.Finding) (string, bool) {
	cur, ok := numericVersion(current)
	if !ok || len(introduced) == 0 {
		return "", false
	}
	var best [4]uint64
	next, found := "", false
	for _, f := range introduced {
		if f.Package != name || f.Kind == "image" {
			return "", false
		}
		fixable := false
		for _, fixed := range strings.Split(f.FixedVersion, ",") {
			fixed = strings.TrimSpace(fixed)
			v, ok := numericVersion(fixed)
			if !ok || v[0] != cur[0] || compare(v, cur) <= 0 {
				continue
			}
			fixable = true
			if !found || compare(v, best) < 0 {
				best, next, found = v, fixed, true
			}
		}
		if !fixable {
			return "", false
		}
	}
	return next, found
}

func rewriteJSON(root, manifest, name, version string) error {
	data, err := ecosystem.ReadRootFile(root, manifest, 16<<20)
	if err != nil {
		return err
	}
	var doc map[string]json.RawMessage
	if err = json.Unmarshal(data, &doc); err != nil {
		return errors.New("invalid JSON manifest")
	}
	found := false
	for _, group := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		if doc[group] == nil {
			continue
		}
		var deps map[string]json.RawMessage
		if json.Unmarshal(doc[group], &deps) != nil {
			return errors.New("invalid dependency declarations")
		}
		if _, ok := deps[name]; ok {
			deps[name], _ = json.Marshal(version)
			doc[group], err = json.Marshal(deps)
			if err != nil {
				return err
			}
			found = true
		}
	}
	if !found {
		return errors.New("dependency is not directly declared")
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	info, err := os.Stat(filepath.Join(root, manifest))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, manifest), append(encoded, '\n'), info.Mode().Perm())
}

// Run scans, plans, repairs admitted files in private copies and rescans. Each
// attempted package mutation is verified before any of its files return.
func (e Engine) Run(ctx context.Context, ws config.Workspace, cfg config.Config, options Options) (Result, error) {
	result := Result{Fixed: []FixedFinding{}, Skipped: []Skipped{}, ChangedFiles: []string{}, Rescan: []vulnscan.JSONFinding{}}
	if _, err := Plan(nil, nil, options); err != nil {
		return result, err
	}
	if e.Scan == nil {
		e.Scan = scan
	}
	if e.Prepare == nil {
		e.Prepare = func(ctx context.Context, ws config.Workspace, cfg config.Config) (config.ToolchainProfile, error) {
			p, err := toolchain.PrepareForFix(ctx, ws, cfg, dockerexec.Default(), nil)
			return p.Profile, err
		}
	}
	if e.Command == nil {
		e.Command = func(ctx context.Context, p config.ToolchainProfile, args []string, root string) (string, error) {
			return updater.NewDockerRunnerForProfile(cfg.Update.Egress, mutationUser(), p.Platform)(ctx, p.Image, args, root)
		}
	}
	baseline, err := e.Scan(ctx, ws.Path, ws, cfg, true)
	if err != nil {
		return result, err
	}
	metadata := map[string]ecosystem.FixDependency{}
	var provider ecosystem.FixProvider
	var profile config.ToolchainProfile
	files := []string{}
	manifest := ""
	var packageErr error
	needsPackages := false
	preliminary, _ := Plan(baseline.Findings, nil, options)
	for _, r := range preliminary {
		if r.Finding.Kind != "image" && r.Finding.Source != "github-dependabot" && (r.Reason == "" || r.Reason == "unsupported_installed_version") {
			needsPackages = true
		}
	}
	if needsPackages {
		registry, registryErr := catalog.New()
		packageErr = registryErr
		if packageErr == nil {
			adapter, lookupErr := registry.Lookup(ws.Stack, ws.PackageManager)
			packageErr = lookupErr
			if packageErr == nil {
				var ok bool
				provider, ok = adapter.(ecosystem.FixProvider)
				if !ok {
					packageErr = errors.New("adapter has no vulnerability repair")
				}
				if packageErr == nil {
					files, manifest, packageErr = packageFiles(ws, adapter)
				}
			}
		}
		if packageErr == nil {
			profile, packageErr = e.Prepare(ctx, ws, cfg)
		}
		if packageErr == nil {
			_, packageErr = adhoc.InPrivateFiles(ws.Path, files, false, func(root string) error {
				if err := preparePrivate(root, files); err != nil {
					return err
				}
				output, err := e.Command(ctx, profile, provider.FixInspect(), root)
				if err != nil {
					return err
				}
				var inspected map[string]ecosystem.FixDependency
				if len(output) > 1<<20 || json.Unmarshal([]byte(output), &inspected) != nil {
					return errors.New("invalid bounded dependency inspection JSON")
				}
				for _, f := range baseline.Findings {
					metadata[f.Package] = inspected[provider.FixName(f.Package)]
				}
				return nil
			})
		}
	}
	plan, err := Plan(baseline.Findings, metadata, options)
	if err != nil {
		return result, err
	}
	groups := map[string][]int{}
	imageGroups := map[string][]int{}
	for i := range plan {
		r := &plan[i]
		if r.Finding.Source == "github-dependabot" && r.Reason != "filtered" && r.Reason != "no_fix" {
			r.Reason = "source_requires_local_verification"
		}
		if r.Reason != "" {
			continue
		}
		if r.Finding.Kind == "image" {
			imageGroups[r.Finding.Image] = append(imageGroups[r.Finding.Image], i)
			continue
		}
		if r.Finding.Source == "github-dependabot" {
			r.Reason = "source_requires_local_verification"
			continue
		}
		if packageErr != nil {
			r.Reason = "package_environment_unavailable"
			continue
		}
		groups[r.Finding.Package] = append(groups[r.Finding.Package], i)
	}
	partial := packageErr != nil || len(baseline.ImageSkips) > 0
	if packageErr != nil && options.Diagnostic != nil {
		options.Diagnostic(packageErr)
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		indexes := groups[name]
		target := plan[indexes[0]].TargetVersion
		for _, i := range indexes {
			a, _ := numericVersion(plan[i].TargetVersion)
			b, _ := numericVersion(target)
			if compare(a, b) > 0 {
				target = plan[i].TargetVersion
			}
		}
		spec, specErr := provider.Fix(ecosystem.FixRequest{Name: name, Version: target, Dependency: plan[indexes[0]].Dependency})
		reason := ""
		if spec.Unsupported != "" {
			reason = spec.Unsupported
		}
		if specErr != nil {
			reason = "invalid_repair_plan"
			partial = true
		}
		attempted := false
		if reason == "" {
			// attempt builds one candidate for version in a fresh private copy of the
			// untouched project. Files return to the host only when it succeeds.
			attempt := func(version string, spec ecosystem.FixSpec) ([]string, error) {
				return adhoc.InPrivateFiles(ws.Path, files, true, func(root string) error {
					if err := preparePrivate(root, files); err != nil {
						return err
					}
					before, err := ecosystem.ReadRootFile(root, manifest, 16<<20)
					if err != nil {
						return err
					}
					manifestInfo, err := os.Stat(filepath.Join(root, manifest))
					if err != nil {
						return err
					}
					if spec.RewriteJSON {
						if err = rewriteJSON(root, manifest, name, version); err != nil {
							return err
						}
					}
					if len(spec.PrepareCommands) > 0 {
						for _, args := range spec.PrepareCommands {
							if _, err = e.Command(ctx, profile, args, root); err != nil {
								return err
							}
						}
						// Validate the private manifest again before restoring it: a
						// subprocess must not replace it with a symlink or special file.
						if _, err = ecosystem.ReadRootFile(root, manifest, 16<<20); err != nil {
							return err
						}
						if err = os.WriteFile(filepath.Join(root, manifest), before, 0600); err != nil {
							return err
						}
					}
					for _, args := range spec.Commands {
						if _, err = e.Command(ctx, profile, args, root); err != nil {
							return err
						}
					}
					output, err := e.Command(ctx, profile, provider.FixInspect(), root)
					if err != nil {
						return err
					}
					var installed map[string]ecosystem.FixDependency
					if len(output) > 1<<20 || json.Unmarshal([]byte(output), &installed) != nil {
						return errors.New("invalid bounded dependency inspection JSON")
					}
					if spec.LockOnly {
						after, err := ecosystem.ReadRootFile(root, manifest, 16<<20)
						if err != nil {
							return err
						}
						if !bytes.Equal(before, after) {
							return errors.New("transitive repair changed the manifest")
						}
						if len(spec.PrepareCommands) > 0 {
							// npm may replace the temporary manifest with a new mode.
							path := filepath.Join(root, manifest)
							if err := os.Chmod(path, manifestInfo.Mode().Perm()); err != nil {
								return err
							}
						}
					}
					copyWS := ws
					copyWS.Path = root
					copyWS.DockerImages = nil
					report, err := e.Scan(ctx, root, copyWS, cfg, false)
					if err != nil {
						return err
					}
					for _, i := range indexes {
						if remains(plan[i].Finding, report.Findings) {
							if spec.LockOnly && !plan[i].Dependency.Direct {
								return errNeedsParentUpgrade
							}
							return errors.New("original finding remains after candidate mutation")
						}
					}
					if !slices.Contains(installed[provider.FixName(name)].Versions, version) {
						return errors.New("candidate lockfile does not contain the exact fix version")
					}
					var introduced []vulnscan.Finding
					for _, newFinding := range report.Findings {
						if !remains(newFinding, baseline.Findings) {
							introduced = append(introduced, newFinding)
						}
					}
					if len(introduced) > 0 {
						return &introducedError{findings: introduced}
					}
					return ctx.Err()
				})
			}
			var changed []string
			for {
				attempted = true
				changed, specErr = attempt(target, spec)
				var introduced *introducedError
				if specErr == nil || !errors.As(specErr, &introduced) || ctx.Err() != nil {
					break
				}
				// The candidate fixed the original findings but is itself vulnerable:
				// move to the next version its own findings report as fixed.
				next, ok := nextTarget(name, target, introduced.findings)
				if !ok {
					break
				}
				nextSpec, nextErr := provider.Fix(ecosystem.FixRequest{Name: name, Version: next, Dependency: plan[indexes[0]].Dependency})
				if nextErr != nil || nextSpec.Unsupported != "" {
					break
				}
				target, spec = next, nextSpec
			}
			if specErr != nil {
				specErr = fmt.Errorf("target %s: %w", target, specErr)
				reason = "candidate_rejected"
				if errors.Is(specErr, errNeedsParentUpgrade) {
					reason = "needs_parent_upgrade"
				} else {
					partial = true
				}
			} else {
				result.ChangedFiles = append(result.ChangedFiles, changed...)
			}
		}
		if specErr != nil && options.Diagnostic != nil {
			options.Diagnostic(specErr)
		}
		for _, i := range indexes {
			plan[i].Reason = reason
			if attempted {
				plan[i].TargetVersion = target
			} else {
				plan[i].TargetVersion = ""
			}
		}
	}
	images := make([]string, 0, len(imageGroups))
	for image := range imageGroups {
		images = append(images, image)
	}
	sort.Strings(images)
	for _, image := range images {
		indexes := imageGroups[image]
		changed, replacement, imageErr := e.repairImage(ctx, ws, cfg, image, indexes, plan)
		reason := ""
		if imageErr != nil {
			reason = "no_verified_image_fix"
			if options.Diagnostic != nil {
				options.Diagnostic(imageErr)
			}
		}
		result.ChangedFiles = append(result.ChangedFiles, changed...)
		if replacement != "" && ws.DockerImages != nil {
			copyImages := *ws.DockerImages
			copyImages.RuntimeImages = append([]string(nil), ws.DockerImages.RuntimeImages...)
			for i, old := range copyImages.RuntimeImages {
				if old == image {
					copyImages.RuntimeImages[i] = replacement
				}
			}
			ws.DockerImages = &copyImages
		}
		for _, i := range indexes {
			plan[i].Reason = reason
		}
	}
	post, scanErr := e.Scan(ctx, ws.Path, ws, cfg, true)
	if scanErr != nil {
		if options.Diagnostic != nil {
			options.Diagnostic(scanErr)
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, ErrPartial
	}
	result.Complete = len(post.ImageSkips) == 0
	partial = partial || !result.Complete
	result.Rescan = vulnscan.StructuredFindings(post.Findings)
	for _, r := range plan {
		finding := vulnscan.StructuredFindings([]vulnscan.Finding{r.Finding})[0]
		if r.Reason == "" && (r.Finding.Kind != "image" || result.Complete) && !remains(r.Finding, post.Findings) {
			result.Fixed = append(result.Fixed, FixedFinding{JSONFinding: finding, TargetVersion: r.TargetVersion})
		} else {
			reason := r.Reason
			if reason == "" {
				reason = "finding_remains"
			}
			result.Skipped = append(result.Skipped, Skipped{Finding: finding, Reason: reason, TargetVersion: r.TargetVersion})
		}
	}
	sort.Strings(result.ChangedFiles)
	result.ChangedFiles = compact(result.ChangedFiles)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if partial {
		return result, ErrPartial
	}
	return result, nil
}

func compact(files []string) []string {
	out := files[:0]
	for _, file := range files {
		if len(out) == 0 || out[len(out)-1] != file {
			out = append(out, file)
		}
	}
	return out
}

var imageLine = regexp.MustCompile(`(?im)^(\s*(?:FROM(?:\s+--[^\s]+)*\s+|image:\s*["']?))([^\s"'#]+)`)
var imageTag = regexp.MustCompile(`^([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(-[A-Za-z0-9_.-]+)?$`)

func imageCandidates(image string) []string {
	base := strings.SplitN(image, "@", 2)[0]
	slash, colon := strings.LastIndex(base, "/"), strings.LastIndex(base, ":")
	if colon <= slash {
		return nil
	}
	tag := base[colon+1:]
	candidates := []string{base}
	m := imageTag.FindStringSubmatch(tag)
	if m == nil {
		return candidates
	}
	patch := uint64(0)
	if m[3] != "" {
		var err error
		patch, err = strconv.ParseUint(m[3], 10, 32)
		if err != nil {
			return candidates
		}
	}
	for step := uint64(1); step <= 16; step++ {
		candidates = append(candidates, base[:colon+1]+m[1]+"."+m[2]+"."+strconv.FormatUint(patch+step, 10)+m[4])
	}
	return candidates
}

func (e Engine) repairImage(ctx context.Context, ws config.Workspace, cfg config.Config, image string, indexes []int, plan []Repair) ([]string, string, error) {
	if ws.DockerImages == nil || image == "" {
		return nil, "", errors.New("image has no source file")
	}
	if len(ws.DockerImages.RuntimeImages) > 0 {
		// Persisted runtime pins may be independent of Dockerfile/Compose.
		// They cannot be silently invalidated by changing a source reference.
		for _, pin := range ws.DockerImages.RuntimeImages {
			if pin == image {
				return nil, "", errors.New("explicit runtime image policy requires a separate reviewed change")
			}
		}
	}
	files := append([]string(nil), ws.DockerImages.Files...)
	for _, candidate := range imageCandidates(image) {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		replacement := ""
		_, err := adhoc.InPrivateFiles(ws.Path, files, false, func(root string) error {
			if err := replaceImageReference(root, files, image, candidate); err != nil {
				return err
			}
			candidateWS := config.Workspace{Path: root, Stack: config.StackDocker, DockerImages: &config.DockerImagesSpec{Files: files, RuntimeImages: []string{candidate}, Platforms: append([]string(nil), ws.DockerImages.Platforms...)}}
			r, err := e.Scan(ctx, root, candidateWS, cfg, false)
			if err != nil {
				return err
			}
			if len(r.ImageSkips) > 0 || len(r.ImageResolutions) == 0 {
				return errors.New("candidate image could not be completely scanned")
			}
			for _, i := range indexes {
				for _, f := range r.Findings {
					if f.ID == plan[i].Finding.ID && f.Package == plan[i].Finding.Package {
						return errors.New("candidate image still contains the finding")
					}
				}
			}
			replacement = candidate
			if strings.Contains(image, "@") {
				digest := r.ImageResolutions[0].ResolvedDigest
				if !digestPattern.MatchString(digest) {
					return errors.New("candidate image digest is unavailable")
				}
				for _, resolution := range r.ImageResolutions {
					if resolution.ResolvedDigest != digest {
						return errors.New("candidate platform digests differ; an index digest is required")
					}
				}
				replacement = candidate + "@" + digest
			}
			return nil
		})
		if err != nil {
			continue
		}
		changed, err := adhoc.InPrivateFiles(ws.Path, files, true, func(root string) error {
			if err := replaceImageReference(root, files, image, replacement); err != nil {
				return err
			}
			copyWS := ws
			copyWS.Path = root
			copyWS.PackageManager = ""
			copyWS.DockerImages = &config.DockerImagesSpec{Files: files, Platforms: append([]string(nil), ws.DockerImages.Platforms...)}
			r, err := e.Scan(ctx, root, copyWS, cfg, false)
			if err != nil {
				return err
			}
			if len(r.ImageSkips) > 0 {
				return errors.New("updated image reference could not be verified")
			}
			for _, i := range indexes {
				for _, f := range r.Findings {
					if f.ID == plan[i].Finding.ID && f.Package == plan[i].Finding.Package {
						return errors.New("updated image still contains the finding")
					}
				}
			}
			return ctx.Err()
		})
		if err == nil {
			return changed, replacement, nil
		}
	}
	return nil, "", errors.New("no scanned candidate on the same image tag line removes the findings")
}

func replaceImageReference(root string, files []string, image, replacement string) error {
	found := false
	for _, file := range files {
		data, err := ecosystem.ReadRootFile(root, file, 16<<20)
		if err != nil {
			return err
		}
		updated := imageLine.ReplaceAllStringFunc(string(data), func(line string) string {
			parts := imageLine.FindStringSubmatch(line)
			if len(parts) == 3 && parts[2] == image {
				found = true
				return parts[1] + replacement
			}
			return line
		})
		info, err := os.Stat(filepath.Join(root, file))
		if err != nil {
			return err
		}
		if updated != string(data) {
			if err = os.WriteFile(filepath.Join(root, file), []byte(updated), info.Mode().Perm()); err != nil {
				return err
			}
		}
	}
	if !found {
		return errors.New("image reference is not a literal Dockerfile or Compose field")
	}
	return nil
}
