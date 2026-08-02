package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ProjectConfig is the deliberately narrow, repository-controlled policy
// stored in .vuelta.yaml. Machine authority (Docker endpoints, executable
// selection, credentials, scanner defaults, and snapshot state) is not part
// of this schema and is rejected by KnownFields decoding.
type ProjectConfig struct {
	SchemaVersion int       `yaml:"schema_version"`
	Workspace     Workspace `yaml:"workspace"`
}

// IsProjectConfigFile reports whether path declares the project-local schema
// by using the singular top-level workspace key.
func IsProjectConfigFile(path string) (bool, error) {
	data, err := ReadProjectFile(path)
	if err != nil {
		return false, err
	}
	var document map[string]yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return false, fmt.Errorf("parse selected config %s: %w", path, err)
	}
	_, project := document["workspace"]
	return project, nil
}

// LoadProject reads a protected project config and resolves its workspace
// relative to the config directory, never relative to the process CWD.
func LoadProject(path string) (*ProjectConfig, error) {
	data, err := ReadProjectFile(path)
	if err != nil {
		return nil, err
	}
	return ParseProject(data, path)
}

// LoadProjectForVerificationApproval applies every project-policy check except
// the script-body equality check which the approval flow exists to refresh.
// Unsafe, missing, or malformed scripts and malformed stored hashes still fail.
func LoadProjectForVerificationApproval(path string) (*ProjectConfig, error) {
	data, err := ReadProjectFile(path)
	if err != nil {
		return nil, err
	}
	return ParseProjectForVerificationApproval(data, path)
}

// ParseProject decodes and validates project policy bytes as if they were
// loaded from path. Callers that plan an atomic edit use this to validate the
// exact source bytes captured by the edit plan.
func ParseProject(data []byte, path string) (*ProjectConfig, error) {
	return parseProject(data, path, false)
}

// ParseProjectForVerificationApproval is the byte-oriented counterpart of
// LoadProjectForVerificationApproval for atomic edit planning.
func ParseProjectForVerificationApproval(data []byte, path string) (*ProjectConfig, error) {
	return parseProject(data, path, true)
}

func parseProject(data []byte, path string, allowScriptDrift bool) (*ProjectConfig, error) {
	var project ProjectConfig
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&project); err != nil {
		return nil, fmt.Errorf("parse project config %s: %w", path, err)
	}
	if project.SchemaVersion != CurrentSchemaVersion {
		return nil, fmt.Errorf("project config schema_version %d is unsupported (supported: %d)", project.SchemaVersion, CurrentSchemaVersion)
	}
	if project.Workspace.Path != "." {
		return nil, errors.New("project config workspace.path must equal dot")
	}
	if project.Workspace.ToolchainProfile != "" {
		return nil, errors.New("project config cannot select a machine-owned toolchain_profile")
	}
	resolved, err := project.ResolvedWorkspace(path)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(validateWorkspaceWithOptions(0, resolved, allowScriptDrift)...); err != nil {
		return nil, fmt.Errorf("validate project config %s: %w", path, err)
	}
	return &project, nil
}

// ResolvedWorkspace returns the project workspace with "." bound to the
// canonical directory containing the selected config.
func (p ProjectConfig) ResolvedWorkspace(configPath string) (Workspace, error) {
	if p.SchemaVersion != CurrentSchemaVersion {
		return Workspace{}, fmt.Errorf("project config schema_version must be %d", CurrentSchemaVersion)
	}
	if p.Workspace.Path != "." {
		return Workspace{}, errors.New("project config workspace.path must equal dot")
	}
	absolute, err := filepath.Abs(configPath)
	if err != nil {
		return Workspace{}, fmt.Errorf("resolve project config path: %w", err)
	}
	root, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return Workspace{}, fmt.Errorf("resolve project config directory: %w", err)
	}
	workspace := p.Workspace
	workspace.Path = root
	return workspace, nil
}

// ValidateWorkspace exposes workspace validation for the narrow project
// schema without requiring a machine Config container.
func ValidateWorkspace(workspace Workspace) error {
	return errors.Join(validateWorkspace(0, workspace)...)
}
