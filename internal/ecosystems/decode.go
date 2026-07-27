package ecosystems

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/luckyfoxdesign/vuelta/internal/ecosystem"
)

type decoderCapability struct {
	kind string
}

func (c decoderCapability) DecodeCandidates(output []byte, inputs map[string][]byte) (ecosystem.CandidateReport, error) {
	if c.kind == "pnpm" {
		return decodePNPMReport(output, inputs)
	}
	report, err := decodePackageReport(c.kind, output, inputs)
	if err != nil {
		return ecosystem.CandidateReport{}, err
	}
	if c.kind == "npm" {
		var lock []byte
		var lockName string
		for _, name := range []string{npmPackageLock, npmShrinkwrapLock} {
			if data, ok := inputs[name]; ok {
				if lock != nil {
					return ecosystem.CandidateReport{}, errors.New("npm candidate scan input contains multiple lockfiles")
				}
				lock, lockName = data, name
			}
		}
		if lock == nil {
			return ecosystem.CandidateReport{}, errors.New("npm candidate scan input omitted a supported lockfile")
		}
		if err := addNPMCurrentVersions(report.Candidates, lockName, lock); err != nil {
			return ecosystem.CandidateReport{}, err
		}
	}
	return report, nil
}

func decodePackageReport(kind string, data []byte, inputs map[string][]byte) (ecosystem.CandidateReport, error) {
	start := bytes.IndexAny(data, "{[")
	if start < 0 {
		return ecosystem.CandidateReport{}, errors.New("scanner output contains no JSON value")
	}
	var value any
	if err := json.NewDecoder(bytes.NewReader(data[start:])).Decode(&value); err != nil {
		return ecosystem.CandidateReport{}, err
	}
	diagnostics := []ecosystem.Diagnostic{}
	if kind == "requirements" || kind == "pip-tools" {
		root, ok := value.(map[string]any)
		if !ok {
			return ecosystem.CandidateReport{}, errors.New("requirements scanner report must be an object")
		}
		if err := decodeRequirementsDiagnostics(root["diagnostics"], inputs, &diagnostics); err != nil {
			return ecosystem.CandidateReport{}, err
		}
		value = root["candidates"]
		if value == nil {
			return ecosystem.CandidateReport{}, errors.New("requirements scanner report has no candidates array")
		}
	}
	var candidates []ecosystem.Candidate
	collectCandidates(kind, value, &candidates)
	if candidates == nil {
		candidates = []ecosystem.Candidate{}
	}
	for _, candidate := range candidates {
		if !validDecodedCandidate(candidate) {
			return ecosystem.CandidateReport{}, fmt.Errorf("invalid candidate %q", candidate.Name)
		}
		if kind == "requirements" || kind == "pip-tools" {
			if !requirementsNamePattern.MatchString(candidate.Name) {
				return ecosystem.CandidateReport{}, fmt.Errorf("requirements candidate name %q is not canonical", candidate.Name)
			}
			if (candidate.File == "") != (candidate.Line == 0) ||
				(candidate.File != "" && (!requirementsReportFileAllowed(candidate.File, inputs) ||
					candidate.Line < 1 || candidate.Line > 1_000_000)) ||
				(candidate.Disposition != "" && candidate.Disposition != "scanned" &&
					candidate.Disposition != "constrained") ||
				(candidate.Disposition != "" && candidate.File == "") {
				return ecosystem.CandidateReport{}, errors.New("requirements candidate provenance is invalid")
			}
		}
	}
	return ecosystem.CandidateReport{Candidates: candidates, Diagnostics: diagnostics}, nil
}

var (
	diagnosticCodePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	requirementsNamePattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	candidatePartPattern    = regexp.MustCompile(`^[A-Za-z0-9@._+!/-]+$`)
)

func decodeRequirementsDiagnostics(
	value any,
	inputs map[string][]byte,
	diagnostics *[]ecosystem.Diagnostic,
) error {
	items, ok := value.([]any)
	if !ok {
		return errors.New("requirements scanner diagnostics must be an array")
	}
	if len(items) > 256 {
		return errors.New("requirements scanner diagnostics exceed 256 records")
	}
	for _, item := range items {
		record, ok := item.(map[string]any)
		if !ok {
			return errors.New("requirements scanner diagnostic is malformed")
		}
		file, _ := record["file"].(string)
		code, _ := record["code"].(string)
		severity, _ := record["severity"].(string)
		disposition, _ := record["disposition"].(string)
		message, _ := record["message"].(string)
		line, lineOK := record["line"].(float64)
		if !requirementsReportFileAllowed(file, inputs) ||
			!diagnosticCodePattern.MatchString(code) ||
			(severity != "info" && severity != "error") || message == "" || len(message) > 512 ||
			(disposition != "" && disposition != "constrained" &&
				disposition != "unsupported" && disposition != "invalid") ||
			strings.IndexFunc(message, unicode.IsControl) >= 0 || !lineOK || line < 1 || line > 1_000_000 || line != float64(int(line)) {
			return errors.New("requirements scanner diagnostic is invalid")
		}
		*diagnostics = append(*diagnostics, ecosystem.Diagnostic{
			File: file, Line: int(line), Code: code, Severity: severity,
			Disposition: disposition, Message: message,
		})
	}
	return nil
}

func requirementsReportFileAllowed(file string, inputs map[string][]byte) bool {
	if file == "" || strings.Contains(file, `\`) || filepath.IsAbs(file) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(file)))
	if clean != file || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return false
	}
	_, ok := inputs[clean]
	return ok
}

func collectCandidates(kind string, value any, candidates *[]ecosystem.Candidate) {
	if kind == "uv" {
		collectUVCandidates(value, candidates)
		return
	}
	switch value := value.(type) {
	case []any:
		for _, item := range value {
			collectCandidates(kind, item, candidates)
		}
	case map[string]any:
		name, _ := value["name"].(string)
		current, _ := firstString(value, "version", "current", "installed_version")
		target, _ := firstString(value, "latest", "latest_version", "wanted", "target")
		if name != "" && target != "" {
			file := ""
			if rawFile, present := value["file"]; present {
				var ok bool
				file, ok = rawFile.(string)
				if !ok {
					file = "\x00"
				}
			}
			disposition := ""
			if rawDisposition, present := value["disposition"]; present {
				var ok bool
				disposition, ok = rawDisposition.(string)
				if !ok {
					disposition = "\x00"
				}
			}
			line := 0
			if rawLine, present := value["line"]; present {
				number, ok := rawLine.(float64)
				if !ok || number < 1 || number > 1_000_000 ||
					number != float64(int(number)) {
					line = -1
				} else {
					line = int(number)
				}
			}
			*candidates = append(*candidates, ecosystem.Candidate{
				Kind: kind, Name: name, Current: current, Target: target,
				File: file, Line: line, Disposition: disposition,
			})
			return
		}
		for key, item := range value {
			if target, ok := item.(string); ok {
				*candidates = append(*candidates, ecosystem.Candidate{Kind: kind, Name: key, Target: target})
				continue
			}
			if record, ok := item.(map[string]any); ok {
				if latest, ok := firstString(record, "latest", "latest_version", "wanted"); ok {
					current, _ := firstString(record, "current", "version")
					*candidates = append(*candidates, ecosystem.Candidate{Kind: kind, Name: key, Current: current, Target: latest})
				}
			}
		}
	}
}

func collectUVCandidates(value any, candidates *[]ecosystem.Candidate) {
	root, ok := value.(map[string]any)
	if !ok {
		return
	}
	resolution, ok := root["resolution"].(map[string]any)
	if !ok {
		return
	}
	for _, item := range resolution {
		record, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := record["name"].(string)
		latest, hasLatest := firstString(record, "latest_version")
		if name == "" || !hasLatest {
			continue
		}
		current, _ := firstString(record, "version")
		*candidates = append(*candidates, ecosystem.Candidate{Kind: "uv", Name: name, Current: current, Target: latest})
	}
}

func firstString(record map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := record[key].(string); ok {
			return value, true
		}
	}
	return "", false
}

func addNPMCurrentVersions(candidates []ecosystem.Candidate, lockName string, lockData []byte) error {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(lockData, &lock); err != nil {
		return fmt.Errorf("parse %s for current candidate versions: %w", lockName, err)
	}
	for index := range candidates {
		if candidates[index].Current != "" {
			continue
		}
		current := lock.Packages["node_modules/"+candidates[index].Name].Version
		if current == "" {
			current = lock.Dependencies[candidates[index].Name].Version
		}
		if current != "" && candidatePartPattern.MatchString(current) {
			candidates[index].Current = current
		}
	}
	return nil
}

func validDecodedCandidate(candidate ecosystem.Candidate) bool {
	return candidatePartPattern.MatchString(candidate.Name) && candidatePartPattern.MatchString(candidate.Target) &&
		(candidate.Current == "" || candidatePartPattern.MatchString(candidate.Current))
}
