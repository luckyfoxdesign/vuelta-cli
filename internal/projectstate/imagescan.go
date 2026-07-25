package projectstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const (
	ImageScanStateName    = "last-image-scan.json"
	MaxImageScanStateBytes = 64 << 10
)

// ImageScanRecord is the resolved digest last observed for one image
// reference at one platform. Comparing the previous record for the same
// reference and platform against a new scan's resolution is how base-image
// drift is detected between two scans of the same project.
type ImageScanRecord struct {
	Reference string `json:"reference"`
	Platform  string `json:"platform"`
	Digest    string `json:"digest"`
}

func (t Target) ImageScanStatePath() string { return filepath.Join(t.StateDir(), ImageScanStateName) }

// ReadImageScanState returns the resolutions recorded by the previous scan,
// or nil if this project has never recorded one.
func (t Target) ReadImageScanState() ([]ImageScanRecord, error) {
	path := t.ImageScanStatePath()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect image scan state: %w", err)
	}
	if err := ValidatePrivateFile(info, "image scan state"); err != nil {
		return nil, err
	}
	data, err := ReadBoundedRegular(path, "image scan state", MaxImageScanStateBytes)
	if err != nil {
		return nil, err
	}
	var records []ImageScanRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parse image scan state: %w", err)
	}
	return records, nil
}

// WriteImageScanState atomically replaces the recorded resolutions with the
// outcome of the scan that just completed.
func (t Target) WriteImageScanState(records []ImageScanRecord) error {
	sorted := append([]ImageScanRecord(nil), records...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Reference != sorted[j].Reference {
			return sorted[i].Reference < sorted[j].Reference
		}
		return sorted[i].Platform < sorted[j].Platform
	})
	data, err := json.Marshal(sorted)
	if err != nil {
		return fmt.Errorf("encode image scan state: %w", err)
	}
	if len(data) > MaxImageScanStateBytes {
		return fmt.Errorf("image scan state exceeds %d bytes", MaxImageScanStateBytes)
	}
	if err := t.EnsureState(); err != nil {
		return err
	}
	return writeProtectedFile(t.StateDir(), ".last-image-scan-*", t.ImageScanStatePath(), data, "image scan state")
}
