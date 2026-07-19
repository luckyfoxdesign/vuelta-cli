// Package scannerimages exposes the reviewed scanner build inputs embedded in
// the vuelta binary. Runtime scans never read Dockerfiles from the project
// being scanned.
package scannerimages

import "embed"

// Files contains every scanner Dockerfile and the hermetic pip-tools helper
// used by python-pip-tools.Dockerfile.
//
//go:embed *.Dockerfile pip_tools_scan.py test_pip_tools_scan.py
var Files embed.FS
