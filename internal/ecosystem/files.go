package ecosystem

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultManifestLimit bounds adapter-owned manifest and lock metadata.
const DefaultManifestLimit int64 = 1 << 20

// IsRegularRootFile reports whether one literal root-relative path is a regular
// non-symlink file. Missing or unsafe entries are not detected.
func IsRegularRootFile(root, name string) bool {
	path, err := rootFilePath(root, name)
	if err != nil {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

// ReadRootFile reads one literal root-relative regular file under a hard size
// limit. It never searches parents or follows a final symlink.
func ReadRootFile(root, name string, limit int64) ([]byte, error) {
	path, err := rootFilePath(root, name)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read ecosystem metadata %s: %w", filepath.Base(name), err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return nil, fmt.Errorf("ecosystem metadata %s must be a regular file no larger than %d bytes", filepath.Base(name), limit)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ecosystem metadata %s: %w", filepath.Base(name), err)
	}
	return data, nil
}

// IsSecretLikePath reports repository-relative names that no dependency graph
// may select as ordinary scanner input. Reviewed manager configuration remains
// an explicit, separate capability.
func IsSecretLikePath(name string) bool {
	for _, component := range strings.Split(strings.ToLower(filepath.ToSlash(name)), "/") {
		if strings.HasPrefix(component, ".env") || strings.HasPrefix(component, ".git") ||
			component == ".vuelta" || component == ".npmrc" || component == ".netrc" ||
			component == "pip.conf" || component == "auth.json" || component == "id_rsa" ||
			component == "id_ed25519" || strings.HasSuffix(component, ".pem") ||
			strings.HasSuffix(component, ".key") || strings.Contains(component, "credential") ||
			strings.Contains(component, "password") || strings.Contains(component, "secret") ||
			strings.Contains(component, "token") {
			return true
		}
	}
	return false
}

func rootFilePath(root, name string) (string, error) {
	if root == "" || name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name ||
		name == "." || strings.Contains(name, "/") || strings.Contains(name, `\`) {
		return "", fmt.Errorf("ecosystem metadata path %q must name one root file", name)
	}
	return filepath.Join(root, name), nil
}
