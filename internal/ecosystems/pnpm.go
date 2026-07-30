package ecosystems

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
	"gopkg.in/yaml.v3"
)

var (
	pnpmExactVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$`)
	pnpmIntegritySuffix     = regexp.MustCompile(`\+sha512\.[A-Za-z0-9_+/=-]+$`)
)

// normalizePNPMVersion removes only Corepack's integrity annotation. It does
// not relax or substitute the semantic version used to install pnpm.
func normalizePNPMVersion(declared string) (string, int, error) {
	version := pnpmIntegritySuffix.ReplaceAllString(strings.TrimSpace(declared), "")
	if !pnpmExactVersionPattern.MatchString(version) {
		return "", 0, &ecosystem.ToolchainVersionError{
			Manager: "pnpm", Version: declared,
			Reason: "declare an exact semantic version; an optional Corepack +sha512 integrity annotation is accepted",
		}
	}
	majorText, _, _ := strings.Cut(version, ".")
	major, err := strconv.Atoi(majorText)
	if err != nil {
		return "", 0, &ecosystem.ToolchainVersionError{
			Manager: "pnpm", Version: declared, Reason: "version major is invalid",
		}
	}
	return version, major, nil
}

func approvedPNPMVersion(declared, lockFormat string) (string, int, error) {
	version, major, err := normalizePNPMVersion(declared)
	if err != nil {
		return "", 0, err
	}
	switch major {
	case 8:
		if lockFormat != "pnpm-v6" {
			return "", 0, &ecosystem.ToolchainVersionError{
				Manager: "pnpm", Version: declared,
				Reason: "pnpm 8 embedded scanners require a v6 lockfile",
			}
		}
	case 9, 10, 11:
		if lockFormat != "pnpm-v9" {
			return "", 0, &ecosystem.ToolchainVersionError{
				Manager: "pnpm", Version: declared,
				Reason: fmt.Sprintf("pnpm %d embedded scanners require a v9 lockfile", major),
			}
		}
	default:
		return "", 0, &ecosystem.ToolchainVersionError{
			Manager: "pnpm", Version: declared,
			Reason: "supported embedded scanner families are pnpm 8, 9, 10, and 11",
		}
	}
	return version, major, nil
}

func decodePNPMReport(data []byte, inputs map[string][]byte) (ecosystem.CandidateReport, error) {
	family, err := pnpmInputFamily(inputs)
	if err != nil {
		return ecosystem.CandidateReport{}, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return ecosystem.CandidateReport{}, pnpmCandidateError(ecosystem.CandidateFailureNonJSON, nil)
	}
	if bytes.HasPrefix(trimmed, []byte("[ERR_PNPM_")) {
		return ecosystem.CandidateReport{}, pnpmCandidateError(
			ecosystem.CandidateFailureManager,
			errors.New("pnpm emitted a bracketed package-manager error"),
		)
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	var root any
	if err := decoder.Decode(&root); err != nil {
		kind := ecosystem.CandidateFailureSchemaMismatch
		if errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "unexpected end of JSON input") ||
			strings.Contains(err.Error(), "unexpected EOF") {
			kind = ecosystem.CandidateFailureTruncatedJSON
		}
		return ecosystem.CandidateReport{}, pnpmCandidateError(kind, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ecosystem.CandidateReport{}, pnpmCandidateError(ecosystem.CandidateFailureSchemaMismatch, errors.New("multiple JSON values"))
	}

	records, ok := root.(map[string]any)
	if !ok {
		return ecosystem.CandidateReport{}, pnpmCandidateError(ecosystem.CandidateFailureSchemaMismatch, errors.New("root must be an object"))
	}
	candidates := make([]ecosystem.Candidate, 0, len(records))
	for name, value := range records {
		record, ok := value.(map[string]any)
		if !ok {
			return ecosystem.CandidateReport{}, pnpmCandidateError(ecosystem.CandidateFailureSchemaMismatch, errors.New("package entry must be an object"))
		}
		if err := validatePNPMRecord(family, record); err != nil {
			return ecosystem.CandidateReport{}, pnpmCandidateError(ecosystem.CandidateFailureSchemaMismatch, err)
		}
		latest, _ := record["latest"].(string)
		current, _ := record["current"].(string)
		candidates = append(candidates, ecosystem.Candidate{
			Kind: "pnpm", Name: name, Current: current, Target: latest, Ownership: "direct",
		})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
	return ecosystem.CandidateReport{Candidates: candidates, Diagnostics: []ecosystem.Diagnostic{}}, nil
}

func pnpmInputFamily(inputs map[string][]byte) (int, error) {
	if manifestData, ok := inputs["package.json"]; ok {
		var manifest struct {
			PackageManager string `json:"packageManager"`
		}
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			return 0, pnpmCandidateError(ecosystem.CandidateFailureSchemaMismatch, errors.New("package.json manager metadata is invalid"))
		}
		if strings.HasPrefix(manifest.PackageManager, "pnpm@") {
			_, family, err := normalizePNPMVersion(strings.TrimPrefix(manifest.PackageManager, "pnpm@"))
			return family, err
		}
	}
	var lock struct {
		LockfileVersion any `yaml:"lockfileVersion"`
	}
	if err := yaml.Unmarshal(inputs["pnpm-lock.yaml"], &lock); err != nil {
		return 0, pnpmCandidateError(ecosystem.CandidateFailureSchemaMismatch, errors.New("pnpm lock metadata is invalid"))
	}
	lockMajor := strings.Split(strings.Trim(fmt.Sprint(lock.LockfileVersion), "'\""), ".")[0]
	switch lockMajor {
	case "6":
		return 8, nil
	case "9":
		return 9, nil
	default:
		return 0, pnpmCandidateError(ecosystem.CandidateFailureSchemaMismatch, errors.New("pnpm lock family is unsupported"))
	}
}

func validatePNPMRecord(family int, record map[string]any) error {
	var allowed map[string]string
	switch family {
	case 8, 9, 10, 11:
		// current and latest become normalized update-plan input. wanted,
		// isDeprecated, and dependencyType are reviewed pnpm metadata: they are
		// type-checked but deliberately do not influence the selected target.
		allowed = map[string]string{
			"current": "string", "latest": "string", "wanted": "string",
			"isDeprecated": "bool", "dependencyType": "string",
		}
	default:
		return fmt.Errorf("pnpm %d output family is unsupported", family)
	}
	for field, value := range record {
		want, ok := allowed[field]
		if !ok {
			return fmt.Errorf("field %q is not supported by pnpm %d output", field, family)
		}
		switch want {
		case "string":
			if text, ok := value.(string); !ok || strings.TrimSpace(text) == "" {
				return fmt.Errorf("field %q must be a non-empty string", field)
			} else if (field == "current" || field == "latest" || field == "wanted") &&
				!candidatePartPattern.MatchString(text) {
				return fmt.Errorf("field %q must be a valid candidate version", field)
			} else if field == "dependencyType" &&
				text != "dependencies" && text != "devDependencies" &&
				text != "optionalDependencies" && text != "peerDependencies" {
				return fmt.Errorf("field %q has unsupported value", field)
			}
		case "bool":
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("field %q must be a boolean", field)
			}
		}
	}
	if latest, ok := record["latest"].(string); !ok || latest == "" {
		return errors.New("field \"latest\" is required")
	}
	return nil
}

func pnpmCandidateError(kind ecosystem.CandidateFailureKind, err error) error {
	return &ecosystem.CandidateError{Kind: kind, Manager: "pnpm", ExitCode: -1, Err: err}
}
