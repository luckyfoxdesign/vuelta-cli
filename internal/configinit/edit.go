package configinit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/testrunner"
	"gopkg.in/yaml.v3"
)

// EditPlan is an immutable, reviewable config mutation. Apply verifies that
// the source has not changed since planning before replacing it atomically.
type EditPlan struct {
	Original       []byte
	Updated        []byte
	Mode           os.FileMode
	Exists         bool
	Changed        bool
	Review         []string
	RepositoryFile bool
}

var atomicRename = os.Rename

// PlanConfigWrite prepares creation or full replacement of a config file.
func PlanConfigWrite(cfg *config.Config, path string, replace bool) (EditPlan, error) {
	if err := cfg.Validate(); err != nil {
		return EditPlan{}, fmt.Errorf("validate generated config: %w", err)
	}
	updated, err := yaml.Marshal(cfg)
	if err != nil {
		return EditPlan{}, fmt.Errorf("serialize config: %w", err)
	}
	plan := EditPlan{Updated: updated, Mode: 0o600, Changed: true}
	original, mode, exists, err := readConfigForWrite(path)
	if err != nil {
		return EditPlan{}, err
	}
	plan.Original, plan.Mode, plan.Exists = original, mode, exists
	if exists && !replace {
		return EditPlan{}, fmt.Errorf("config %s already exists (use --replace to replace it)", path)
	}
	if exists && bytes.Equal(original, updated) {
		plan.Changed = false
	}
	return plan, nil
}

// PlanSchemaMigration prepares the only supported in-place machine-config
// migration: a legacy config with no schema_version to the current schema.
// It preserves the YAML tree and validates the complete migrated config before
// returning an atomic edit plan. Explicit unsupported versions fail closed.
func PlanSchemaMigration(path string) (EditPlan, error) {
	original, mode, exists, err := readConfigForWrite(path)
	if err != nil {
		return EditPlan{}, err
	}
	if !exists {
		return EditPlan{}, fmt.Errorf("config %s does not exist", path)
	}

	var header struct {
		SchemaVersion *int `yaml:"schema_version"`
	}
	if err := yaml.Unmarshal(original, &header); err != nil {
		return EditPlan{}, fmt.Errorf("parse config schema header: %w", err)
	}
	if header.SchemaVersion != nil && *header.SchemaVersion != config.CurrentSchemaVersion {
		return EditPlan{}, fmt.Errorf(
			"config schema_version %d cannot be migrated by this build (supported: %d)",
			*header.SchemaVersion, config.CurrentSchemaVersion,
		)
	}

	var document yaml.Node
	if err := yaml.Unmarshal(original, &document); err != nil {
		return EditPlan{}, fmt.Errorf("parse legacy config YAML tree: %w", err)
	}
	root, err := documentMapping(&document)
	if err != nil {
		return EditPlan{}, err
	}
	var review []string
	if header.SchemaVersion == nil {
		review = append(review, fmt.Sprintf("add schema_version: %d", config.CurrentSchemaVersion))
		legacyReview, migrateErr := migrateLegacyMachineConfig(root)
		if migrateErr != nil {
			return EditPlan{}, migrateErr
		}
		review = append(review, legacyReview...)
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "schema_version"}
		value := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprintf("%d", config.CurrentSchemaVersion)}
		root.Content = append([]*yaml.Node{key, value}, root.Content...)
	}
	update := mappingValue(root, "update")
	if update != nil {
		if update.Kind != yaml.MappingNode {
			return EditPlan{}, errors.New("update must be a YAML mapping")
		}
		if deleteMappingNode(update, "snapshot_state_dir") {
			review = append(review, "remove retired "+config.RetiredMachineConfigFields()[0]+" (project-local state is selected from the exact target)")
		}
	}
	if deleteMappingNode(root, "notify") {
		review = append(review, "remove retired "+config.RetiredMachineConfigFields()[1]+" (the separate bridge owns transport configuration)")
	}
	if len(review) == 0 {
		return EditPlan{
			Original: original, Updated: original, Mode: mode, Exists: true, Changed: false,
		}, nil
	}

	updated, err := encodeDocument(&document, original)
	if err != nil {
		return EditPlan{}, err
	}
	migrated, err := config.Parse(updated)
	if err != nil {
		return EditPlan{}, fmt.Errorf("validate migrated config schema: %w", err)
	}
	if err := migrated.Validate(); err != nil {
		return EditPlan{}, fmt.Errorf("validate migrated config: %w", err)
	}
	return EditPlan{
		Original: original, Updated: updated, Mode: mode, Exists: true, Changed: !bytes.Equal(original, updated),
		Review: review,
	}, nil
}

func migrateLegacyMachineConfig(root *yaml.Node) ([]string, error) {
	var review []string
	vulnerability := mappingValue(root, "vuln_scan")
	github := mappingValue(root, "github_advisories")
	if vulnerability != nil {
		if vulnerability.Kind != yaml.MappingNode {
			return nil, errors.New("vuln_scan must be a YAML mapping")
		}
		enabled, present, err := optionalBool(vulnerability, "enabled")
		if err != nil {
			return nil, err
		}
		if present {
			if !enabled {
				return nil, errors.New("legacy vuln_scan.enabled is false; migration cannot enable a security gate without a separate policy decision")
			}
			deleteMappingNode(vulnerability, "enabled")
			review = append(review, "remove legacy vuln_scan.enabled (current dependency scanning is always enabled)")
		}
		tool := mappingValue(vulnerability, "tool")
		if tool != nil {
			if tool.Kind != yaml.ScalarNode || (tool.Value != "trivy" && tool.Value != "osv-scanner") {
				return nil, errors.New("legacy vuln_scan.tool must be trivy or osv-scanner")
			}
			if selected := mappingValue(vulnerability, "dependency_source"); selected != nil && selected.Value != tool.Value {
				return nil, errors.New("legacy vuln_scan.tool conflicts with vuln_scan.dependency_source")
			}
			setMappingString(vulnerability, "dependency_source", tool.Value)
			deleteMappingNode(vulnerability, "tool")
			review = append(review, "move legacy vuln_scan.tool to vuln_scan.dependency_source")
		}
	}
	if github != nil {
		if github.Kind != yaml.MappingNode {
			return nil, errors.New("github_advisories must be a YAML mapping")
		}
		githubEnabled, present, err := optionalBool(github, "enabled")
		if err != nil {
			return nil, err
		}
		if present {
			deleteMappingNode(github, "enabled")
			review = append(review, "remove legacy github_advisories.enabled")
			if vulnerability != nil && mappingValue(vulnerability, "dependency_source") == nil && githubEnabled {
				setMappingString(vulnerability, "dependency_source", "github-dependabot")
				review = append(review, "select github-dependabot as vuln_scan.dependency_source")
			}
		}
		if deleteMappingNode(github, "required_for_github_remotes") {
			review = append(review, "remove legacy github_advisories.required_for_github_remotes")
		}
	}

	for _, key := range []string{"autofix", "deploy_task", "production_worker"} {
		if deleteMappingNode(root, key) {
			review = append(review, fmt.Sprintf("remove parked %s section", key))
		}
	}

	workspaces := mappingValue(root, "workspaces")
	if workspaces != nil {
		if workspaces.Kind != yaml.SequenceNode {
			return nil, errors.New("workspaces must be a YAML sequence")
		}
		for index, workspace := range workspaces.Content {
			if workspace.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("workspaces[%d] must be a YAML mapping", index)
			}
			if mappingValue(workspace, "test") == nil {
				continue
			}
			if mappingValue(workspace, "verification") != nil {
				return nil, fmt.Errorf("workspaces[%d] contains both legacy test and verification", index)
			}
			deleteMappingNode(workspace, "test")
			verification, err := encodeNode(config.VerificationProfile{
				Version: config.VerificationVersion,
				State:   config.VerificationScanOnly,
			})
			if err != nil {
				return nil, fmt.Errorf("encode scan-only verification: %w", err)
			}
			setMappingNode(workspace, "verification", verification)
			review = append(review, fmt.Sprintf(
				"replace workspaces[%d].test with verification.state=scan_only", index,
			))
		}
	}
	return review, nil
}

func optionalBool(mapping *yaml.Node, key string) (bool, bool, error) {
	value := mappingValue(mapping, key)
	if value == nil {
		return false, false, nil
	}
	var decoded bool
	if err := value.Decode(&decoded); err != nil {
		return false, true, fmt.Errorf("%s must be a boolean", key)
	}
	return decoded, true, nil
}

// PlanProjectConfigWrite prepares an atomic no-overwrite write for the narrow
// project-local schema.
func PlanProjectConfigWrite(project *config.ProjectConfig, path string) (EditPlan, error) {
	workspace, err := project.ResolvedWorkspace(path)
	if err != nil {
		return EditPlan{}, err
	}
	if err := config.ValidateWorkspace(workspace); err != nil {
		return EditPlan{}, fmt.Errorf("validate generated project config: %w", err)
	}
	updated, err := yaml.Marshal(project)
	if err != nil {
		return EditPlan{}, fmt.Errorf("serialize project config: %w", err)
	}
	original, mode, exists, err := readConfigForWrite(path)
	if err != nil {
		return EditPlan{}, err
	}
	if exists {
		return EditPlan{}, fmt.Errorf("config %s already exists", path)
	}
	return EditPlan{Original: original, Updated: updated, Mode: mode, Exists: false, Changed: true}, nil
}

// PlanProjectStackUpdate prepares an atomic repair of the stack-dependent
// fields in an existing project-local config. Callers must supply a complete,
// freshly detected workspace; unrelated project policy remains untouched.
func PlanProjectStackUpdate(path string, desired config.Workspace) (EditPlan, error) {
	original, mode, exists, err := readEditSource(path, true)
	if err != nil {
		return EditPlan{}, err
	}
	if !exists {
		return EditPlan{}, fmt.Errorf("project config %s does not exist; run 'vuelta scan --directory .' first", path)
	}
	if _, err := config.ParseProject(original, path); err != nil {
		return EditPlan{}, err
	}

	desired.Path = "."
	repaired := &config.ProjectConfig{SchemaVersion: config.CurrentSchemaVersion, Workspace: desired}
	resolved, err := repaired.ResolvedWorkspace(path)
	if err != nil {
		return EditPlan{}, err
	}
	if err := config.ValidateWorkspace(resolved); err != nil {
		return EditPlan{}, fmt.Errorf("validate repaired project workspace: %w", err)
	}

	var document yaml.Node
	if err := yaml.Unmarshal(original, &document); err != nil {
		return EditPlan{}, fmt.Errorf("parse project config YAML tree: %w", err)
	}
	root, err := documentMapping(&document)
	if err != nil {
		return EditPlan{}, err
	}
	workspaceNode := mappingValue(root, "workspace")
	if workspaceNode == nil || workspaceNode.Kind != yaml.MappingNode {
		return EditPlan{}, errors.New("workspace must be a YAML mapping")
	}
	setMappingString(workspaceNode, "stack", desired.Stack)
	setMappingString(workspaceNode, "package_manager", desired.PackageManager)
	verification, err := encodeNode(desired.Verification)
	if err != nil {
		return EditPlan{}, fmt.Errorf("encode repaired verification profile: %w", err)
	}
	setMappingNode(workspaceNode, "verification", verification)
	allowed, err := encodeNode(desired.AllowedChangedPaths)
	if err != nil {
		return EditPlan{}, fmt.Errorf("encode repaired changed-path allowlist: %w", err)
	}
	setMappingNode(workspaceNode, "allowed_changed_paths", allowed)
	if desired.DockerImages == nil {
		deleteMappingNode(workspaceNode, "docker_images")
	} else {
		dockerImages, encodeErr := encodeNode(desired.DockerImages)
		if encodeErr != nil {
			return EditPlan{}, fmt.Errorf("encode repaired Docker image policy: %w", encodeErr)
		}
		setMappingNode(workspaceNode, "docker_images", dockerImages)
	}

	updated, err := encodeDocument(&document, original)
	if err != nil {
		return EditPlan{}, err
	}
	if _, err := config.ParseProject(updated, path); err != nil {
		return EditPlan{}, fmt.Errorf("validate repaired project config: %w", err)
	}
	return EditPlan{
		Original: original, Updated: updated, Mode: mode, Exists: true, Changed: !bytes.Equal(original, updated),
		Review: []string{
			fmt.Sprintf("replace workspace.stack with freshly detected %s", desired.Stack),
			"regenerate stack-dependent package manager, verification, changed-path, and Docker image policy",
		},
		RepositoryFile: true,
	}, nil
}

// PlanProjectVerificationUpdate prepares the one supported in-place edit of a
// project-local config. It replaces only workspace.verification, preserving
// every byte outside that YAML node, and retains the atomic source check used
// by other reviewed config edits.
func PlanProjectVerificationUpdate(path string, profile config.VerificationProfile) (EditPlan, error) {
	original, mode, exists, err := readEditSource(path, true)
	if err != nil {
		return EditPlan{}, err
	}
	if !exists {
		return EditPlan{}, fmt.Errorf("project config %s does not exist; run 'vuelta scan --directory .' first", path)
	}
	project, err := config.ParseProjectForVerificationApproval(original, path)
	if err != nil {
		return EditPlan{}, err
	}
	if project.Workspace.Verification.State != config.VerificationScanOnly && project.Workspace.Verification.State != config.VerificationReady {
		return EditPlan{}, errors.New("project verification profile must be scan_only or ready")
	}
	project.Workspace.Verification = profile
	workspace, err := project.ResolvedWorkspace(path)
	if err != nil {
		return EditPlan{}, err
	}
	if err := config.ValidateWorkspace(workspace); err != nil {
		return EditPlan{}, fmt.Errorf("validate approved project config: %w", err)
	}
	if err := testrunner.ValidateProfile(workspace.Path, profile); err != nil {
		return EditPlan{}, fmt.Errorf("verification profile is not allowed by the Compose policy: %w", err)
	}

	var document yaml.Node
	if err := yaml.Unmarshal(original, &document); err != nil {
		return EditPlan{}, fmt.Errorf("parse project config YAML tree: %w", err)
	}
	root, err := documentMapping(&document)
	if err != nil {
		return EditPlan{}, err
	}
	workspaceNode := mappingValue(root, "workspace")
	if workspaceNode == nil || workspaceNode.Kind != yaml.MappingNode {
		return EditPlan{}, errors.New("workspace must be a YAML mapping")
	}
	start, end, indent, err := mappingFieldByteRange(original, workspaceNode, "verification")
	if err != nil {
		return EditPlan{}, err
	}
	replacement, err := renderVerificationField(profile, indent, detectIndent(original), usesCRLF(original))
	if err != nil {
		return EditPlan{}, err
	}
	if end == len(original) && !bytes.HasSuffix(original, []byte("\n")) {
		replacement = bytes.TrimSuffix(replacement, []byte("\n"))
		if bytes.HasSuffix(replacement, []byte("\r")) {
			replacement = bytes.TrimSuffix(replacement, []byte("\r"))
		}
	}
	updated := make([]byte, 0, len(original)-(end-start)+len(replacement))
	updated = append(updated, original[:start]...)
	updated = append(updated, replacement...)
	updated = append(updated, original[end:]...)
	if _, err := config.ParseProject(updated, path); err != nil {
		return EditPlan{}, fmt.Errorf("validate edited project config: %w", err)
	}
	return EditPlan{
		Original: original, Updated: updated, Mode: mode, Exists: true, Changed: !bytes.Equal(original, updated),
		Review: []string{"replace workspace.verification scan_only profile with reviewed ready profile"}, RepositoryFile: true,
	}, nil
}

// PlanDockerBootstrap creates a default config when none exists or updates
// only docker.developer in an existing config. Existing comments, key order,
// unrelated settings, and protected file mode are preserved.
func PlanDockerBootstrap(path string, endpoint config.DockerEndpointConfig) (EditPlan, error) {
	original, mode, exists, err := readConfigForWrite(path)
	if err != nil {
		return EditPlan{}, err
	}
	if !exists {
		cfg := NewConfig()
		cfg.Docker = &config.DockerConfig{Developer: &endpoint}
		return PlanConfigWrite(cfg, path, false)
	}
	cfg, err := config.Parse(original)
	if err != nil {
		return EditPlan{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return EditPlan{}, fmt.Errorf("validate config before Docker bootstrap: %w", err)
	}
	if cfg.Docker != nil && cfg.Docker.Developer != nil && reflect.DeepEqual(*cfg.Docker.Developer, endpoint) {
		return EditPlan{Original: original, Updated: original, Mode: mode, Exists: true}, nil
	}
	cfg.Docker = &config.DockerConfig{Developer: &endpoint}
	if err := cfg.Validate(); err != nil {
		return EditPlan{}, fmt.Errorf("validate bootstrapped config: %w", err)
	}

	var document yaml.Node
	if err := yaml.Unmarshal(original, &document); err != nil {
		return EditPlan{}, fmt.Errorf("parse config YAML tree: %w", err)
	}
	root, err := documentMapping(&document)
	if err != nil {
		return EditPlan{}, err
	}
	endpointNode, err := encodeNode(endpoint)
	if err != nil {
		return EditPlan{}, fmt.Errorf("encode Docker endpoint: %w", err)
	}
	dockerNode := mappingValue(root, "docker")
	if dockerNode == nil {
		dockerNode = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setMappingNode(root, "docker", dockerNode)
	} else if dockerNode.Kind != yaml.MappingNode {
		return EditPlan{}, errors.New("docker must be a YAML mapping")
	}
	setMappingNode(dockerNode, "developer", endpointNode)
	updated, err := encodeDocument(&document, original)
	if err != nil {
		return EditPlan{}, err
	}
	return EditPlan{Original: original, Updated: updated, Mode: mode, Exists: true, Changed: !bytes.Equal(original, updated)}, nil
}

// PlanWorkspaceAdd appends a workspace or persists the name of a matching
// legacy workspace while retaining unrelated YAML comments and key order.
func PlanWorkspaceAdd(path string, desired config.Workspace) (EditPlan, error) {
	original, mode, exists, err := readConfigForWrite(path)
	if err != nil {
		return EditPlan{}, err
	}
	if !exists {
		return EditPlan{}, fmt.Errorf("config %s does not exist; run 'vuelta config init' first", path)
	}
	cfg, err := config.Parse(original)
	if err != nil {
		return EditPlan{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return EditPlan{}, fmt.Errorf("validate config before project add: %w", err)
	}

	desiredPath, err := canonicalPath(desired.Path)
	if err != nil {
		return EditPlan{}, fmt.Errorf("canonicalize project path: %w", err)
	}
	desired.Path = desiredPath

	var document yaml.Node
	if err := yaml.Unmarshal(original, &document); err != nil {
		return EditPlan{}, fmt.Errorf("parse config YAML tree: %w", err)
	}
	workspaces, err := workspaceSequence(&document)
	if err != nil {
		return EditPlan{}, err
	}

	for index, existing := range cfg.Workspaces {
		existingPath, pathErr := canonicalPath(existing.Path)
		if pathErr != nil {
			return EditPlan{}, fmt.Errorf("canonicalize configured workspace %q: %w", existing.Path, pathErr)
		}
		existingName := config.WorkspaceName(existing)
		if existingName == desired.Name && existingPath != desiredPath {
			return EditPlan{}, fmt.Errorf("project name %q is already configured for %s", desired.Name, existingPath)
		}
		if existingPath != desiredPath {
			continue
		}
		if existing.Name != "" && existing.Name != desired.Name {
			return EditPlan{}, fmt.Errorf("project path %s is already configured as %q", desiredPath, existing.Name)
		}
		if !sameWorkspaceSettings(*cfg, existing, desired) {
			return EditPlan{}, fmt.Errorf("project %q at %s is already configured with different settings", desired.Name, desiredPath)
		}
		if existing.Name != "" {
			return EditPlan{Original: original, Updated: original, Mode: mode, Exists: true}, nil
		}
		if index >= len(workspaces.Content) {
			return EditPlan{}, errors.New("workspaces YAML does not match the decoded configuration")
		}
		setMappingString(workspaces.Content[index], "name", desired.Name)
		cfg.Workspaces[index].Name = desired.Name
		if err := cfg.Validate(); err != nil {
			return EditPlan{}, fmt.Errorf("validate migrated config: %w", err)
		}
		updated, err := encodeDocument(&document, original)
		if err != nil {
			return EditPlan{}, err
		}
		return EditPlan{Original: original, Updated: updated, Mode: mode, Exists: true, Changed: true}, nil
	}

	cfg.Workspaces = append(cfg.Workspaces, desired)
	if err := cfg.Validate(); err != nil {
		return EditPlan{}, fmt.Errorf("validate project addition: %w", err)
	}
	workspaceNode, err := encodeNode(desired)
	if err != nil {
		return EditPlan{}, fmt.Errorf("encode workspace: %w", err)
	}
	workspaces.Style &^= yaml.FlowStyle
	workspaces.Content = append(workspaces.Content, workspaceNode)
	updated, err := encodeDocument(&document, original)
	if err != nil {
		return EditPlan{}, err
	}
	return EditPlan{Original: original, Updated: updated, Mode: mode, Exists: true, Changed: true}, nil
}

// Apply commits a previously reviewed edit with atomic replacement semantics.
func (p EditPlan) Apply(path string) error {
	if !p.Changed {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	current, currentMode, exists, err := readEditSource(path, p.RepositoryFile)
	if err != nil {
		return err
	}
	if exists != p.Exists || currentMode != p.Mode || !bytes.Equal(current, p.Original) {
		return errors.New("config changed after the displayed diff; refusing to write")
	}
	if !p.Exists {
		return writeNewAtomic(path, p.Updated, p.Mode)
	}
	return replaceAtomic(path, p.Updated, p.Mode)
}

func readEditSource(path string, repositoryFile bool) ([]byte, os.FileMode, bool, error) {
	if !repositoryFile {
		return readConfigForWrite(path)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0o644, false, nil
	}
	if err != nil {
		return nil, 0, false, fmt.Errorf("inspect repository file: %w", err)
	}
	data, err := config.ReadProjectFile(path)
	if err != nil {
		return nil, 0, false, err
	}
	return data, info.Mode().Perm(), true, nil
}

// Diff returns a compact line-oriented representation suitable for review
// before confirmation.
func (p EditPlan) Diff(path string) string {
	if !p.Changed {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n+++ %s\n", path, path)
	before := splitLines(p.Original)
	after := splitLines(p.Updated)
	prefix := 0
	for prefix < len(before) && prefix < len(after) && before[prefix] == after[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(before)-prefix && suffix < len(after)-prefix && before[len(before)-1-suffix] == after[len(after)-1-suffix] {
		suffix++
	}
	if prefix > 0 {
		fmt.Fprintf(&b, " %s\n", before[prefix-1])
	}
	for _, line := range before[prefix : len(before)-suffix] {
		fmt.Fprintf(&b, "-%s\n", line)
	}
	for _, line := range after[prefix : len(after)-suffix] {
		fmt.Fprintf(&b, "+%s\n", line)
	}
	if suffix > 0 {
		fmt.Fprintf(&b, " %s\n", before[len(before)-suffix])
	}
	return b.String()
}

func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func sameWorkspaceSettings(cfg config.Config, existing, desired config.Workspace) bool {
	existing.Name = desired.Name
	existing.Path = desired.Path
	existing.AllowedChangedPaths = append([]string(nil), cfg.AllowedChangedPaths(existing)...)
	return reflect.DeepEqual(existing, desired)
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

func readConfigForWrite(path string) ([]byte, os.FileMode, bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0o600, false, nil
	}
	if err != nil {
		return nil, 0, false, fmt.Errorf("inspect config path: %w", err)
	}
	data, mode, err := config.ReadSecureFile(path)
	if err != nil {
		return nil, 0, false, err
	}
	return data, mode, true, nil
}

func workspaceSequence(document *yaml.Node) (*yaml.Node, error) {
	root, err := documentMapping(document)
	if err != nil {
		return nil, err
	}
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value != "workspaces" {
			continue
		}
		sequence := root.Content[index+1]
		if sequence.Kind != yaml.SequenceNode {
			return nil, errors.New("workspaces must be a YAML sequence")
		}
		return sequence, nil
	}
	key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "workspaces"}
	sequence := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	root.Content = append(root.Content, key, sequence)
	return sequence, nil
}

func documentMapping(document *yaml.Node) (*yaml.Node, error) {
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("config must be a YAML mapping")
	}
	return document.Content[0], nil
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func setMappingNode(mapping *yaml.Node, key string, value *yaml.Node) {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			mapping.Content[index+1] = value
			return
		}
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value,
	)
}

func deleteMappingNode(mapping *yaml.Node, key string) bool {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value != key {
			continue
		}
		mapping.Content = append(mapping.Content[:index], mapping.Content[index+2:]...)
		return true
	}
	return false
}

func setMappingString(mapping *yaml.Node, key, value string) {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			mapping.Content[index+1].Value = value
			return
		}
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value},
	)
}

func encodeNode(value any) (*yaml.Node, error) {
	data, err := yaml.Marshal(value)
	if err != nil {
		return nil, err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	return document.Content[0], nil
}

func encodeDocument(document *yaml.Node, original []byte) ([]byte, error) {
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(detectIndent(original))
	if err := encoder.Encode(document); err != nil {
		return nil, fmt.Errorf("serialize edited config: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("close YAML encoder: %w", err)
	}
	return output.Bytes(), nil
}

func mappingFieldByteRange(data []byte, mapping *yaml.Node, key string) (int, int, int, error) {
	var keyNode, valueNode *yaml.Node
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			keyNode, valueNode = mapping.Content[index], mapping.Content[index+1]
			break
		}
	}
	if keyNode == nil {
		return 0, 0, 0, fmt.Errorf("workspace.%s is missing", key)
	}
	lineOffsets := []int{0}
	for index, b := range data {
		if b == '\n' {
			lineOffsets = append(lineOffsets, index+1)
		}
	}
	if keyNode.Line < 1 || keyNode.Line > len(lineOffsets) || keyNode.Column < 1 {
		return 0, 0, 0, fmt.Errorf("workspace.%s has invalid YAML source coordinates", key)
	}
	start := lineOffsets[keyNode.Line-1]
	lineEnd := len(data)
	if keyNode.Line < len(lineOffsets) {
		lineEnd = lineOffsets[keyNode.Line]
	}
	keyOffset := start + keyNode.Column - 1
	if keyOffset > lineEnd || !onlySpaces(data[start:keyOffset]) {
		return 0, 0, 0, fmt.Errorf("workspace.%s must use a block-style YAML key", key)
	}
	keyText := []byte(key + ":")
	if keyOffset+len(keyText) > lineEnd || !bytes.Equal(data[keyOffset:keyOffset+len(keyText)], keyText) {
		return 0, 0, 0, fmt.Errorf("workspace.%s must use an unquoted block-style YAML key", key)
	}
	lastLine := maxNodeLine(valueNode)
	if lastLine < keyNode.Line || lastLine > len(lineOffsets) {
		return 0, 0, 0, fmt.Errorf("workspace.%s has invalid YAML node boundaries", key)
	}
	end := len(data)
	if lastLine < len(lineOffsets) {
		end = lineOffsets[lastLine]
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		sibling := mapping.Content[index]
		if sibling != keyNode && sibling.Line >= keyNode.Line && sibling.Line <= lastLine {
			return 0, 0, 0, fmt.Errorf("workspace.%s must not share a line with another workspace field", key)
		}
	}
	return start, end, keyNode.Column - 1, nil
}

func maxNodeLine(node *yaml.Node) int {
	maximum := node.Line
	for _, child := range node.Content {
		if line := maxNodeLine(child); line > maximum {
			maximum = line
		}
	}
	return maximum
}

func onlySpaces(data []byte) bool {
	for _, b := range data {
		if b != ' ' {
			return false
		}
	}
	return true
}

func renderVerificationField(profile config.VerificationProfile, indent, width int, crlf bool) ([]byte, error) {
	wrapper := struct {
		Verification config.VerificationProfile `yaml:"verification"`
	}{Verification: profile}
	var encoded bytes.Buffer
	encoder := yaml.NewEncoder(&encoded)
	encoder.SetIndent(width)
	if err := encoder.Encode(wrapper); err != nil {
		return nil, fmt.Errorf("serialize verification profile: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("close verification profile encoder: %w", err)
	}
	prefix := bytes.Repeat([]byte(" "), indent)
	var output bytes.Buffer
	for _, line := range bytes.SplitAfter(encoded.Bytes(), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		output.Write(prefix)
		output.Write(line)
	}
	result := output.Bytes()
	if crlf {
		result = bytes.ReplaceAll(result, []byte("\n"), []byte("\r\n"))
	}
	return result, nil
}

func usesCRLF(data []byte) bool {
	return bytes.Contains(data, []byte("\r\n")) && !bytes.Contains(bytes.ReplaceAll(data, []byte("\r\n"), nil), []byte("\n"))
}

func detectIndent(data []byte) int {
	indent := 0
	for _, line := range splitLines(data) {
		spaces := len(line) - len(strings.TrimLeft(line, " "))
		if spaces > 0 && (indent == 0 || spaces < indent) {
			indent = spaces
		}
	}
	if indent < 2 {
		return 2
	}
	return indent
}

func writeNewAtomic(path string, data []byte, mode os.FileMode) error {
	temp, err := writeTemp(path, data, mode)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temp) }()
	if err := os.Link(temp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("config %s already exists", path)
		}
		return fmt.Errorf("publish new config: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func replaceAtomic(path string, data []byte, mode os.FileMode) error {
	temp, err := writeTemp(path, data, mode)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temp) }()
	if err := atomicRename(temp, path); err != nil {
		return fmt.Errorf("replace config atomically: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func writeTemp(path string, data []byte, mode os.FileMode) (string, error) {
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temporary config: %w", err)
	}
	name := temp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = temp.Close()
			_ = os.Remove(name)
		}
	}()
	if err := temp.Chmod(mode); err != nil {
		return "", fmt.Errorf("set temporary config permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return "", fmt.Errorf("write temporary config: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return "", fmt.Errorf("sync temporary config: %w", err)
	}
	if err := temp.Close(); err != nil {
		return "", fmt.Errorf("close temporary config: %w", err)
	}
	ok = true
	return name, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config directory: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("sync config directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close config directory: %w", err)
	}
	return nil
}
