// Package sandbox prepares a one-off, cleaned working copy (no .git, no
// .env, no untracked files) for running updates and tests in a container.
// See part F of the spec for the isolation model.
package sandbox

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Prepare creates a 0700 sandbox from exactly baseSHA. repoPath must already
// be the canonical, explicitly configured workspace path; accepting a
// symlink here would allow a caller to change the project after preflight.
//
// git archive deliberately supplies the input rather than copying a directory:
// ignored files, untracked files, .git and host secrets never enter the
// sandbox. Extraction is implemented here rather than delegated to tar so a
// malicious tracked archive member cannot create a symlink or escape dir.
func Prepare(ctx context.Context, repoPath, baseSHA string) (dir string, cleanup func() error, err error) {
	if baseSHA == "" || strings.ContainsAny(baseSHA, " \t\r\n") {
		return "", nil, fmt.Errorf("invalid base SHA")
	}
	abs, err := filepath.Abs(repoPath)
	if err != nil {
		return "", nil, fmt.Errorf("resolve project path: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", nil, fmt.Errorf("resolve canonical project path: %w", err)
	}
	if canonical != abs {
		return "", nil, fmt.Errorf("project path must be canonical, not a symlink")
	}

	// Resolve the revision before creating a sandbox. This makes a malformed
	// revision fail without leaving temporary state behind.
	verify := exec.CommandContext(ctx, "git", "rev-parse", "--verify", baseSHA+"^{commit}")
	verify.Dir = canonical
	if out, verifyErr := verify.CombinedOutput(); verifyErr != nil {
		if ctx.Err() != nil {
			return "", nil, ctx.Err()
		}
		return "", nil, fmt.Errorf("verify base SHA: %w: %s", verifyErr, strings.TrimSpace(string(out)))
	}

	dir, err = os.MkdirTemp("", "vuelta-sandbox-*")
	if err != nil {
		return "", nil, fmt.Errorf("create sandbox dir: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			_ = os.RemoveAll(dir)
		}
	}()
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", nil, fmt.Errorf("chmod sandbox dir: %w", err)
	}

	archive := exec.CommandContext(ctx, "git", "archive", "--format=tar", baseSHA)
	archive.Dir = canonical
	stdout, err := archive.StdoutPipe()
	if err != nil {
		return "", nil, fmt.Errorf("open git archive: %w", err)
	}
	if err := archive.Start(); err != nil {
		return "", nil, fmt.Errorf("start git archive: %w", err)
	}
	extractErr := extract(stdout, dir)
	archiveErr := archive.Wait()
	if extractErr != nil {
		return "", nil, extractErr
	}
	if archiveErr != nil {
		if ctx.Err() != nil {
			return "", nil, ctx.Err()
		}
		return "", nil, fmt.Errorf("git archive %s: %w", baseSHA, archiveErr)
	}

	failed = false
	return dir, func() error { return os.RemoveAll(dir) }, nil
}

func extract(r io.Reader, root string) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read git archive: %w", err)
		}
		rel, err := safeArchivePath(h.Name)
		if err != nil {
			return err
		}
		path := filepath.Join(root, rel)
		switch h.Typeflag {
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			// Git may emit PAX metadata. archive/tar applies it to the next
			// member; it is not a filesystem entry.
			continue
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o700); err != nil {
				return fmt.Errorf("create archive directory %s: %w", rel, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return fmt.Errorf("create archive parent %s: %w", rel, err)
			}
			mode := os.FileMode(h.Mode) & 0o700
			if mode == 0 {
				mode = 0o600
			}
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return fmt.Errorf("create archive file %s: %w", rel, err)
			}
			_, copyErr := io.Copy(f, tr)
			closeErr := f.Close()
			if copyErr != nil {
				return fmt.Errorf("extract archive file %s: %w", rel, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close archive file %s: %w", rel, closeErr)
			}
		default:
			return fmt.Errorf("archive entry %s is not a regular file or directory", rel)
		}
	}
}

func safeArchivePath(name string) (string, error) {
	if name == "" || filepath.IsAbs(name) {
		return "", fmt.Errorf("archive path %q is invalid", name)
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) ||
		clean == ".git" || strings.HasPrefix(clean, ".git"+string(filepath.Separator)) {
		return "", fmt.Errorf("archive path %q is not allowed", name)
	}
	return clean, nil
}
