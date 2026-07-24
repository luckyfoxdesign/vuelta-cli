package configinit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// PathEnvironment makes unsafe-root decisions deterministic in tests.
type PathEnvironment struct {
	GOOS       string
	HomeDir    string
	TempDir    string
	ConfigDir  string
	CacheDir   string
	SystemDirs []string
}

// CurrentPathEnvironment returns only path metadata; it never reads the
// contents of config, cache, or credential directories.
func CurrentPathEnvironment() PathEnvironment {
	home, _ := os.UserHomeDir()
	configDir, _ := os.UserConfigDir()
	cacheDir, _ := os.UserCacheDir()
	return PathEnvironment{
		GOOS: runtime.GOOS, HomeDir: home, TempDir: os.TempDir(),
		ConfigDir: configDir, CacheDir: cacheDir,
		SystemDirs: platformSystemDirs(runtime.GOOS),
	}
}

// ValidateAutoCreateRoot rejects symlink-selected and overly broad or
// sensitive roots before project marker detection or config creation.
func ValidateAutoCreateRoot(selectedPath, canonicalRoot string, environment PathEnvironment) error {
	absoluteSelected, err := filepath.Abs(selectedPath)
	if err != nil {
		return fmt.Errorf("resolve selected directory: %w", err)
	}
	info, err := os.Lstat(absoluteSelected)
	if err != nil {
		return fmt.Errorf("inspect selected directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("automatic project config creation is disabled for a symlink-selected directory")
	}
	if !info.IsDir() {
		return errors.New("selected project root is not a directory")
	}

	root := filepath.Clean(canonicalRoot)
	volumeRoot := filepath.Clean(filepath.VolumeName(root) + string(filepath.Separator))
	if samePath(root, volumeRoot, environment.GOOS) {
		return errors.New("automatic project config creation is disabled at the filesystem root")
	}
	for label, path := range map[string]string{
		"home":      environment.HomeDir,
		"temporary": environment.TempDir,
	} {
		if path != "" && samePath(root, canonicalOrClean(path), environment.GOOS) {
			return fmt.Errorf("automatic project config creation is disabled at the %s root", label)
		}
	}
	for label, path := range map[string]string{
		"OS config": environment.ConfigDir,
		"OS cache":  environment.CacheDir,
	} {
		if path != "" && pathWithin(canonicalOrClean(path), root) {
			return fmt.Errorf("automatic project config creation is disabled inside the %s root", label)
		}
	}
	for _, path := range environment.SystemDirs {
		if path != "" && pathWithin(canonicalOrClean(path), root) {
			return fmt.Errorf("automatic project config creation is disabled inside system root %s", filepath.Clean(path))
		}
	}
	if environment.HomeDir != "" {
		for _, name := range []string{".ssh", ".aws", ".kube", ".gnupg"} {
			path := filepath.Join(environment.HomeDir, name)
			if pathWithin(canonicalOrClean(path), root) {
				return errors.New("automatic project config creation is disabled inside a credential root")
			}
		}
	}
	return nil
}

func platformSystemDirs(goos string) []string {
	switch goos {
	case "darwin":
		return []string{"/System", "/Library", "/usr", "/etc", "/bin", "/sbin", "/private/etc"}
	case "linux":
		return []string{"/boot", "/dev", "/etc", "/proc", "/sys", "/usr", "/var/lib"}
	case "windows":
		return []string{`C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`}
	default:
		return nil
	}
}

func canonicalOrClean(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return canonical
	}
	return filepath.Clean(absolute)
}

func pathWithin(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func samePath(left, right, goos string) bool {
	if goos == "windows" {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return filepath.Clean(left) == filepath.Clean(right)
}
