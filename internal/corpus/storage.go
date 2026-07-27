package corpus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxReportBytes = 16 << 20

// RunStorage owns one timestamped run and never removes cache or old runs.
type RunStorage struct {
	Root    string
	RunID   string
	RunDir  string
	LogDir  string
	TempDir string
}

// CreateRunStorage creates the required report/log layout plus a private
// temporary work directory removed at the end of the run.
func CreateRunStorage(root string, now time.Time) (RunStorage, error) {
	if err := validateManagedRoot(root); err != nil {
		return RunStorage{}, err
	}
	runs := filepath.Join(root, "runs")
	if err := os.MkdirAll(runs, 0o700); err != nil {
		return RunStorage{}, fmt.Errorf("create corpus runs directory: %w", err)
	}
	runID := now.Format("20060102-150405")
	runDir := filepath.Join(runs, runID)
	if err := os.Mkdir(runDir, 0o700); err != nil {
		if os.IsExist(err) {
			return RunStorage{}, errors.New("a corpus run already exists for this timestamp; retry in the next second")
		}
		return RunStorage{}, fmt.Errorf("create corpus run directory: %w", err)
	}
	logDir := filepath.Join(runDir, "logs")
	tempDir := filepath.Join(runDir, ".tmp")
	if err := os.Mkdir(logDir, 0o700); err != nil {
		return RunStorage{}, fmt.Errorf("create corpus log directory: %w", err)
	}
	if err := os.Mkdir(tempDir, 0o700); err != nil {
		return RunStorage{}, fmt.Errorf("create corpus temporary directory: %w", err)
	}
	return RunStorage{Root: root, RunID: runID, RunDir: runDir, LogDir: logDir, TempDir: tempDir}, nil
}

// CleanupTemp removes only the validated private temporary run directory.
func (s RunStorage) CleanupTemp() error {
	if filepath.Base(s.TempDir) != ".tmp" || filepath.Dir(s.TempDir) != s.RunDir ||
		!isStrictDescendant(s.Root, s.TempDir) {
		return errors.New("refuse to clean an unmanaged corpus temporary directory")
	}
	return os.RemoveAll(s.TempDir)
}

// WriteLog writes bounded scanner output without environment or argv.
func (s RunStorage) WriteLog(name string, observation ProcessObservation) (string, error) {
	if !slugPattern.MatchString(name) {
		return "", errors.New("corpus log name is unsafe")
	}
	filename := name + ".log"
	full := filepath.Join(s.LogDir, filename)
	var content strings.Builder
	content.WriteString("stdout:\n")
	content.WriteString(sanitizeLog(string(observation.Stdout)))
	content.WriteString("\n\nstderr:\n")
	content.WriteString(sanitizeLog(observation.Stderr))
	if content.Len() > scanOutputLimit+scanStderrLimit+128 {
		return "", errors.New("corpus log exceeded its storage bound")
	}
	if err := writeAtomic(full, []byte(content.String()), 0o600); err != nil {
		return "", err
	}
	return filepath.ToSlash(filepath.Join("logs", filename)), nil
}

// WriteReport atomically writes both report formats.
func (s RunStorage) WriteReport(report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode corpus report: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxReportBytes {
		return errors.New("corpus JSON report exceeded its storage bound")
	}
	if err := writeAtomic(filepath.Join(s.RunDir, "report.json"), data, 0o600); err != nil {
		return err
	}
	markdown := []byte(RenderMarkdown(report))
	if len(markdown) > maxReportBytes {
		return errors.New("corpus Markdown report exceeded its storage bound")
	}
	return writeAtomic(filepath.Join(s.RunDir, "report.md"), markdown, 0o600)
}

// WriteCandidateFiles stores refresh output beside reports without changing
// the committed stable manifest.
func WriteCandidateFiles(runDir string, manifest []byte, diff string) error {
	if !filepath.IsAbs(runDir) {
		return errors.New("candidate output directory must be absolute")
	}
	if len(manifest) > maxManifestBytes || len(diff) > maxReportBytes {
		return errors.New("candidate output exceeded its storage bound")
	}
	if err := writeAtomic(filepath.Join(runDir, "candidate-manifest.yaml"), manifest, 0o600); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(runDir, "candidate.diff"), []byte(sanitizeLog(diff)), 0o600)
}

func writeAtomic(filename string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(filename+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("create report temporary file: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(filename + ".tmp")
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write report temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync report temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close report temporary file: %w", err)
	}
	if err := os.Rename(filename+".tmp", filename); err != nil {
		return fmt.Errorf("publish report file: %w", err)
	}
	remove = false
	return nil
}

// LoadReport strictly reads one bounded report produced by this harness.
func LoadReport(filename string) (Report, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return Report{}, fmt.Errorf("inspect corpus report: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxReportBytes {
		return Report{}, errors.New("corpus report must be a bounded regular non-symlink file")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return Report{}, fmt.Errorf("read corpus report: %w", err)
	}
	var report Report
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return Report{}, fmt.Errorf("decode corpus report: %w", err)
	}
	var trailer any
	if err := decoder.Decode(&trailer); !errors.Is(err, io.EOF) {
		return Report{}, errors.New("corpus report contains trailing data")
	}
	if report.SchemaVersion != ReportSchemaVersion || report.RunID == "" || report.FinishedAt.IsZero() {
		return Report{}, errors.New("corpus report is incomplete or unsupported")
	}
	return report, nil
}

// PreviousReport loads the newest completed run before currentRunID.
func PreviousReport(root, currentRunID string) (Report, bool, error) {
	entries, err := os.ReadDir(filepath.Join(root, "runs"))
	if err != nil {
		if os.IsNotExist(err) {
			return Report{}, false, nil
		}
		return Report{}, false, err
	}
	var ids []string
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() < currentRunID {
			ids = append(ids, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	for _, id := range ids {
		report, loadErr := LoadReport(filepath.Join(root, "runs", id, "report.json"))
		if loadErr == nil {
			return report, true, nil
		}
	}
	return Report{}, false, nil
}

// PreviousComparableReport returns the newest complete stable report produced
// from the same manifest, plus explicit warnings for newer excluded runs.
func PreviousComparableReport(
	root, currentRunID string,
	stable []Case,
	manifestHash string,
) (Report, bool, []string, error) {
	entries, err := os.ReadDir(filepath.Join(root, "runs"))
	if err != nil {
		if os.IsNotExist(err) {
			return Report{}, false, nil, nil
		}
		return Report{}, false, nil, err
	}
	var ids []string
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() < currentRunID {
			ids = append(ids, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	var warnings []string
	for _, id := range ids {
		report, loadErr := LoadReport(filepath.Join(root, "runs", id, "report.json"))
		if loadErr != nil {
			warnings = append(warnings, fmt.Sprintf(
				"previous report %s excluded from comparison: %s",
				id, SanitizeMessage(loadErr.Error()),
			))
			continue
		}
		if reason := ComparisonIneligibility(report, stable, manifestHash); reason != "" {
			warnings = append(warnings, fmt.Sprintf(
				"previous report %s excluded from comparison: %s", id, reason,
			))
			continue
		}
		return report, true, warnings, nil
	}
	return Report{}, false, warnings, nil
}
