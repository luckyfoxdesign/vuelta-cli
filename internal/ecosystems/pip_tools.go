package ecosystems

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
)

const (
	pipToolsSourceFile    = "requirements.in"
	pipToolsCompiledFile  = "requirements.txt"
	pipToolsMetadataFile  = "pyproject.toml"
	maxRequirementsFiles  = 32
	maxRequirementRecords = 32_768
)

func (a pipToolsAdapter) PackageInputForRoot(root string, allowManagerConfig bool) (ecosystem.InputContract, error) {
	return a.inputForRoot(root, allowManagerConfig, ecosystem.InputStagePackageCandidates)
}

func (a pipToolsAdapter) DependencyInputForRoot(root string) (ecosystem.InputContract, error) {
	return a.inputForRoot(root, false, ecosystem.InputStageDependencyCVE)
}

func (a pipToolsAdapter) inputForRoot(
	root string,
	allowManagerConfig bool,
	stage ecosystem.InputStage,
) (ecosystem.InputContract, error) {
	graph, err := resolveRequirementsGraph(root, pipToolsSourceFile, pipToolsCompiledFile)
	if err != nil {
		return ecosystem.InputContract{}, err
	}
	files := []ecosystem.InputFile{
		{Path: pipToolsSourceFile, Category: ecosystem.InputCategoryManifest},
		{Path: pipToolsCompiledFile, Category: ecosystem.InputCategoryLock},
		{Path: pipToolsMetadataFile, Category: ecosystem.InputCategoryManifest, Optional: true},
	}
	for _, name := range graph {
		if name == pipToolsSourceFile || name == pipToolsCompiledFile {
			continue
		}
		files = append(files, ecosystem.InputFile{
			Path: name, Category: ecosystem.InputCategoryDependency,
		})
	}
	if allowManagerConfig {
		files = append(files, ecosystem.InputFile{
			Path: "pip.conf", Category: ecosystem.InputCategoryManagerConfig,
			Optional: true, ReviewedManagerConfig: true,
		})
	}
	return ecosystem.InputContract{Stage: stage, Files: files}, nil
}

func detectPipToolsConstraints(root string, key ecosystem.Key, platform string) (ecosystem.Constraints, error) {
	if _, err := ecosystem.ReadRootFile(root, pipToolsCompiledFile, ecosystem.DefaultManifestLimit); err != nil {
		return ecosystem.Constraints{}, err
	}
	constraints := ecosystem.Constraints{
		Key: key, Platform: platform, LockFormat: "requirements",
		RuntimeConstraintSource: ecosystem.RuntimeConstraintSourceDefault,
	}
	data, present, err := readOptionalRootFile(root, pipToolsMetadataFile)
	if err != nil {
		return ecosystem.Constraints{}, err
	}
	if !present {
		return constraints, nil
	}
	constraints.Runtime, err = parsePipToolsRuntimeMetadata(data)
	if err != nil {
		return ecosystem.Constraints{}, err
	}
	constraints.RuntimeConstraintSource = runtimeConstraintSource(constraints.Runtime)
	return constraints, nil
}

func readOptionalRootFile(root, name string) ([]byte, bool, error) {
	_, err := os.Lstat(filepath.Join(root, name))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("inspect optional ecosystem metadata %s: %w", name, err)
	}
	data, err := ecosystem.ReadRootFile(root, name, ecosystem.DefaultManifestLimit)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func parsePipToolsRuntimeMetadata(data []byte) (string, error) {
	if !utf8.Valid(data) {
		return "", invalidPipToolsRuntimeMetadata("pyproject.toml must be UTF-8")
	}
	section := ""
	found := false
	runtimeConstraint := ""
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), int(ecosystem.DefaultManifestLimit))
	for scanner.Scan() {
		line := strings.TrimSpace(stripTOMLComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if strings.HasPrefix(line, "[[") || !strings.HasSuffix(line, "]") {
				section = ""
				continue
			}
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section != "project" || strings.TrimSpace(key) != "requires-python" {
			continue
		}
		if found {
			return "", invalidPipToolsRuntimeMetadata("pyproject.toml declares project.requires-python more than once")
		}
		found = true
		parsed, ok := parseTOMLString(strings.TrimSpace(value))
		if !ok || strings.TrimSpace(parsed) == "" {
			return "", invalidPipToolsRuntimeMetadata("pyproject.toml project.requires-python must be one non-empty quoted string")
		}
		runtimeConstraint = strings.TrimSpace(parsed)
	}
	if err := scanner.Err(); err != nil {
		return "", invalidPipToolsRuntimeMetadata("pyproject.toml runtime metadata could not be parsed")
	}
	return runtimeConstraint, nil
}

func stripTOMLComment(line string) string {
	var quote rune
	escaped := false
	for index, value := range line {
		if quote == '"' && escaped {
			escaped = false
			continue
		}
		if quote == '"' && value == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if value == quote {
				quote = 0
			}
			continue
		}
		switch value {
		case '\'', '"':
			quote = value
		case '#':
			return line[:index]
		}
	}
	return line
}

func parseTOMLString(value string) (string, bool) {
	if len(value) < 2 {
		return "", false
	}
	if value[0] == '\'' && value[len(value)-1] == '\'' {
		return value[1 : len(value)-1], !strings.ContainsRune(value[1:len(value)-1], '\'')
	}
	if value[0] != '"' || value[len(value)-1] != '"' {
		return "", false
	}
	parsed, err := strconv.Unquote(value)
	return parsed, err == nil
}

func invalidPipToolsRuntimeMetadata(detail string) error {
	return &ecosystem.RuntimeConstraintError{
		ReasonCode: ecosystem.RuntimeConstraintInvalid,
		Stack:      "python",
		Constraint: "pyproject.toml project.requires-python",
		Detail:     detail,
	}
}

func resolveRequirementsGraph(root string, initial ...string) ([]string, error) {
	queue := append([]string(nil), initial...)
	seen := make(map[string]bool, len(queue))
	var resolved []string
	records := 0
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		if len(seen) >= maxRequirementsFiles {
			return nil, fmt.Errorf("pip-tools requirements graph exceeds %d files", maxRequirementsFiles)
		}
		data, err := readRequirementsGraphFile(root, name)
		if err != nil {
			return nil, err
		}
		seen[name] = true
		resolved = append(resolved, name)
		for _, line := range strings.Split(string(data), "\n") {
			records++
			if records > maxRequirementRecords {
				return nil, fmt.Errorf("pip-tools requirements graph exceeds %d records", maxRequirementRecords)
			}
			target, selected, err := requirementDirectiveTarget(line)
			if err != nil {
				return nil, fmt.Errorf("parse pip-tools directive in %s: %w", name, err)
			}
			if !selected {
				continue
			}
			next, local, err := resolveRequirementReference(name, target)
			if err != nil {
				return nil, err
			}
			if local && !seen[next] {
				queue = append(queue, next)
			}
		}
	}
	sort.Strings(resolved)
	return resolved, nil
}

func readRequirementsGraphFile(root, name string) ([]byte, error) {
	if name == "" || path.IsAbs(name) || path.Clean(name) != name || name == "." ||
		strings.Contains(name, `\`) {
		return nil, fmt.Errorf("pip-tools requirements path %q is not a safe project-relative path", name)
	}
	if ecosystem.IsSecretLikePath(name) {
		return nil, errors.New("pip-tools requirements graph selected a disallowed secret-like path")
	}
	if strings.Count(name, "/")+1 > 8 {
		return nil, errors.New("pip-tools requirements path exceeds maximum depth")
	}
	current := root
	parts := strings.Split(name, "/")
	for index, part := range parts {
		current = filepath.Join(current, filepath.FromSlash(part))
		info, err := os.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("inspect selected pip-tools input %s: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("selected pip-tools input %s traverses a symbolic link", name)
		}
		if index < len(parts)-1 && !info.IsDir() {
			return nil, fmt.Errorf("selected pip-tools input %s has a non-directory parent", name)
		}
		if index == len(parts)-1 && (!info.Mode().IsRegular() || info.Size() > ecosystem.DefaultManifestLimit) {
			return nil, fmt.Errorf(
				"selected pip-tools input %s must be a regular file no larger than %d bytes",
				name,
				ecosystem.DefaultManifestLimit,
			)
		}
	}
	data, err := os.ReadFile(current)
	if err != nil {
		return nil, fmt.Errorf("read selected pip-tools input %s: %w", name, err)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("selected pip-tools input %s must be UTF-8", name)
	}
	return data, nil
}

func requirementDirectiveTarget(line string) (string, bool, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false, nil
	}
	if comment := strings.Index(line, " #"); comment >= 0 {
		line = strings.TrimSpace(line[:comment])
	}
	var value string
	switch {
	case strings.HasPrefix(line, "--requirement="):
		value = strings.TrimSpace(strings.TrimPrefix(line, "--requirement="))
	case strings.HasPrefix(line, "--constraint="):
		value = strings.TrimSpace(strings.TrimPrefix(line, "--constraint="))
	case strings.HasPrefix(line, "--requirement "):
		value = strings.TrimSpace(strings.TrimPrefix(line, "--requirement "))
	case strings.HasPrefix(line, "--constraint "):
		value = strings.TrimSpace(strings.TrimPrefix(line, "--constraint "))
	case strings.HasPrefix(line, "-r "):
		value = strings.TrimSpace(strings.TrimPrefix(line, "-r "))
	case strings.HasPrefix(line, "-c "):
		value = strings.TrimSpace(strings.TrimPrefix(line, "-c "))
	case strings.HasPrefix(line, "-r") && len(line) > 2:
		value = strings.TrimSpace(line[2:])
	case strings.HasPrefix(line, "-c") && len(line) > 2:
		value = strings.TrimSpace(line[2:])
	default:
		return "", false, nil
	}
	if value == "" {
		return "", false, errors.New("requirements include or constraint directive has no target")
	}
	if strings.ContainsAny(value, " \t\"'") {
		return "", false, nil
	}
	return value, true, nil
}

func resolveRequirementReference(parent, target string) (string, bool, error) {
	lower := strings.ToLower(target)
	if strings.Contains(target, "://") || strings.HasPrefix(lower, "git+") {
		return "", false, nil
	}
	if path.IsAbs(target) || strings.Contains(target, `\`) {
		return "", false, fmt.Errorf("pip-tools directive target %q must be project-relative", target)
	}
	resolved := path.Clean(path.Join(path.Dir(parent), target))
	if resolved == "." || resolved == ".." || strings.HasPrefix(resolved, "../") {
		return "", false, fmt.Errorf("pip-tools directive target %q escapes the selected project", target)
	}
	return resolved, true, nil
}
