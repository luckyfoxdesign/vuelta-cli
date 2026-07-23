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
	"gopkg.in/yaml.v3"
)

// EditPlan is an immutable, reviewable config mutation. Apply verifies that
// the source has not changed since planning before replacing it atomically.
type EditPlan struct {
	Original []byte
	Updated  []byte
	Mode     os.FileMode
	Exists   bool
	Changed  bool
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
	current, currentMode, exists, err := readConfigForWrite(path)
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
