package ecosystems

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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
	maxRequirementsDepth  = 8
	maxRequirementsBytes  = 8 << 20
)

var errRequirementsInputUnavailable = errors.New("requirements input unavailable")

func (a requirementsAdapter) PackageInputForRoot(root string, _ bool) (ecosystem.InputContract, error) {
	return a.inputForRoot(root, ecosystem.InputStagePackageCandidates)
}

func (a requirementsAdapter) DependencyInputForRoot(root string) (ecosystem.InputContract, error) {
	return a.inputForRoot(root, ecosystem.InputStageDependencyCVE)
}

func (a requirementsAdapter) inputForRoot(root string, stage ecosystem.InputStage) (ecosystem.InputContract, error) {
	graph, err := resolveRequirementsGraph(root, "requirements.txt")
	if err != nil {
		return ecosystem.InputContract{}, err
	}
	files := make([]ecosystem.InputFile, 0, len(graph))
	for _, name := range graph {
		files = append(files, ecosystem.InputFile{
			Path: name, Category: ecosystem.InputCategoryDependency,
		})
	}
	return ecosystem.InputContract{Stage: stage, Files: files}, nil
}

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
	canonicalRoot, err := canonicalRequirementsRoot(root)
	if err != nil {
		return nil, err
	}
	type pendingFile struct {
		name  string
		depth int
	}
	queue := make([]pendingFile, 0, len(initial))
	for _, name := range initial {
		queue = append(queue, pendingFile{name: name})
	}
	seen := make(map[string]bool, len(queue))
	var resolved []string
	records := 0
	totalBytes := 0
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if seen[current.name] {
			continue
		}
		if current.depth > maxRequirementsDepth {
			return nil, fmt.Errorf("requirements graph exceeds maximum depth of %d", maxRequirementsDepth)
		}
		if len(seen) >= maxRequirementsFiles {
			return nil, fmt.Errorf("requirements graph exceeds maximum file count of %d", maxRequirementsFiles)
		}
		data, err := readRequirementsGraphFile(canonicalRoot, current.name)
		if err != nil {
			if current.depth > 0 && errors.Is(err, errRequirementsInputUnavailable) {
				continue
			}
			return nil, err
		}
		totalBytes += len(data)
		if totalBytes > maxRequirementsBytes {
			return nil, fmt.Errorf("requirements graph exceeds maximum aggregate size of %d bytes", maxRequirementsBytes)
		}
		seen[current.name] = true
		resolved = append(resolved, current.name)
		for _, line := range strings.Split(string(data), "\n") {
			records++
			if records > maxRequirementRecords {
				return nil, fmt.Errorf("requirements graph exceeds maximum record count of %d", maxRequirementRecords)
			}
			target, selected, err := requirementDirectiveTarget(line)
			if err != nil {
				return nil, fmt.Errorf("parse requirements directive in %s: %w", current.name, err)
			}
			if !selected {
				continue
			}
			next, local, err := resolveRequirementReference(current.name, target)
			if err != nil {
				return nil, err
			}
			if local && !seen[next] {
				queue = append(queue, pendingFile{name: next, depth: current.depth + 1})
			}
		}
	}
	sort.Strings(resolved)
	return resolved, nil
}

func canonicalRequirementsRoot(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve selected requirements root: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve selected requirements root: %w", err)
	}
	info, err := os.Lstat(canonical)
	if err != nil {
		return "", fmt.Errorf("inspect selected requirements root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("selected requirements root is not a canonical directory")
	}
	return canonical, nil
}

func readRequirementsGraphFile(root, name string) ([]byte, error) {
	if name == "" || path.IsAbs(name) || path.Clean(name) != name || name == "." ||
		strings.Contains(name, `\`) {
		return nil, fmt.Errorf("requirements path %q is not a safe project-relative path", name)
	}
	if ecosystem.IsSecretLikePath(name) {
		return nil, errors.New("requirements graph selected a disallowed secret-like path")
	}
	if strings.Count(name, "/")+1 > maxRequirementsDepth {
		return nil, errors.New("requirements path exceeds maximum depth")
	}
	current := root
	parts := strings.Split(name, "/")
	var selectedInfo os.FileInfo
	for index, part := range parts {
		current = filepath.Join(current, filepath.FromSlash(part))
		info, err := os.Lstat(current)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, errRequirementsInputUnavailable
			}
			return nil, fmt.Errorf("inspect selected requirements input %s: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("selected requirements input %s traverses a symbolic link", name)
		}
		if index < len(parts)-1 && !info.IsDir() {
			return nil, fmt.Errorf("selected requirements input %s has a non-directory parent", name)
		}
		if index == len(parts)-1 && (!info.Mode().IsRegular() || info.Size() > ecosystem.DefaultManifestLimit) {
			return nil, fmt.Errorf(
				"selected requirements input %s must be a regular file no larger than %d bytes",
				name,
				ecosystem.DefaultManifestLimit,
			)
		}
		if index == len(parts)-1 {
			selectedInfo = info
		}
	}
	file, err := os.Open(current)
	if err != nil {
		return nil, fmt.Errorf("open selected requirements input %s: %w", name, err)
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(selectedInfo, openedInfo) {
		_ = file.Close()
		return nil, fmt.Errorf("selected requirements input %s changed during validation", name)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, ecosystem.DefaultManifestLimit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, fmt.Errorf("read selected requirements input %s: %w", name, errors.Join(readErr, closeErr))
	}
	if int64(len(data)) > ecosystem.DefaultManifestLimit {
		return nil, fmt.Errorf(
			"selected requirements input %s must be a regular file no larger than %d bytes",
			name,
			ecosystem.DefaultManifestLimit,
		)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("selected requirements input %s must be UTF-8", name)
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
		return "", false, nil
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
		return "", false, fmt.Errorf("requirements directive target %q must be project-relative", target)
	}
	resolved := path.Clean(path.Join(path.Dir(parent), target))
	if resolved == "." || resolved == ".." || strings.HasPrefix(resolved, "../") {
		return "", false, fmt.Errorf("requirements directive target %q escapes the selected project", target)
	}
	return resolved, true, nil
}
