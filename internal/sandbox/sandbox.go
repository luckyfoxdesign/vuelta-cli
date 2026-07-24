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
	"path/filepath"
	"strings"

	"github.com/luckyfoxdesign/vuelta/internal/gitexec"
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
	if err := gitexec.ValidateCommitSHA(baseSHA); err != nil {
		return "", nil, fmt.Errorf("verify base SHA: %w", err)
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
	if _, verifyErr := gitexec.Output(ctx, canonical, "rev-parse", "--verify", "--end-of-options", baseSHA+"^{commit}"); verifyErr != nil {
		if ctx.Err() != nil {
			return "", nil, ctx.Err()
		}
		return "", nil, fmt.Errorf("verify base SHA: %w", verifyErr)
	}

	// A separate local is load-bearing: error paths return `""` through the
	// named result dir, which would otherwise empty the path the deferred
	// cleanup removes.
	sandboxDir, err := os.MkdirTemp("", "vuelta-sandbox-*")
	if err != nil {
		return "", nil, fmt.Errorf("create sandbox dir: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			_ = os.RemoveAll(sandboxDir)
		}
	}()
	if err := os.Chmod(sandboxDir, 0o700); err != nil {
		return "", nil, fmt.Errorf("chmod sandbox dir: %w", err)
	}

	archiveCtx, cancelArchive := context.WithCancel(ctx)
	defer cancelArchive()
	stdout, archiveWriter := io.Pipe()
	archiveDone := make(chan error, 1)
	go func() {
		_, runErr := gitexec.Default().Run(archiveCtx, gitexec.Request{
			Args: []string{"archive", "--format=tar", baseSHA}, Dir: canonical, Stdout: archiveWriter,
		})
		_ = archiveWriter.Close()
		archiveDone <- runErr
	}()
	extractErr := extract(stdout, sandboxDir, defaultArchiveLimits)
	if extractErr != nil {
		cancelArchive()
		_ = stdout.Close()
	} else {
		// archive/tar stops at the logical end marker; drain Git's remaining
		// block padding so the child and os/exec copier can finish.
		_, _ = io.Copy(io.Discard, stdout)
	}
	archiveErr := <-archiveDone
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
	return sandboxDir, func() error { return os.RemoveAll(sandboxDir) }, nil
}

// archiveLimits bounds resource consumption while extracting an untrusted
// git archive. Limits are internal policy: compiled in, never read from the
// repository or user configuration, so a hostile tracked tree cannot raise
// its own budget.
type archiveLimits struct {
	maxFileBytes  int64 // declared size of one regular file
	maxTotalBytes int64 // sum of declared regular-file sizes
	maxEntries    int   // tar members, including PAX metadata entries
	maxPathDepth  int   // components in the cleaned relative path
	maxPathBytes  int   // bytes in the raw member name
}

// defaultArchiveLimits comfortably fits normal supported repositories while
// keeping a hostile archive from exhausting disk space or inodes.
var defaultArchiveLimits = archiveLimits{
	maxFileBytes:  512 << 20, // 512 MiB
	maxTotalBytes: 2 << 30,   // 2 GiB
	maxEntries:    200_000,
	maxPathDepth:  32,
	maxPathBytes:  512,
}

// extract materializes the tar stream under root, enforcing lim and failing
// closed on malformed or inconsistent metadata. The caller removes root on
// error.
func extract(r io.Reader, root string, lim archiveLimits) error {
	tr := tar.NewReader(r)
	entries := 0
	var totalBytes int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read git archive: %w", err)
		}
		entries++
		if entries > lim.maxEntries {
			return fmt.Errorf("archive exceeds %d entries", lim.maxEntries)
		}
		if h.Typeflag == tar.TypeXGlobalHeader || h.Typeflag == tar.TypeXHeader {
			// Git may emit PAX metadata. archive/tar applies it to the next
			// member; it is not a filesystem entry, but it still spends
			// entry budget above.
			continue
		}
		rel, err := safeArchivePath(h.Name, lim)
		if err != nil {
			return err
		}
		path := filepath.Join(root, rel)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o700); err != nil {
				return fmt.Errorf("create archive directory %s: %w", rel, err)
			}
		case tar.TypeReg:
			if h.Size < 0 || h.Size > lim.maxFileBytes {
				return fmt.Errorf("archive file %s declares %d bytes, per-file limit is %d", rel, h.Size, lim.maxFileBytes)
			}
			totalBytes += h.Size
			if totalBytes > lim.maxTotalBytes {
				return fmt.Errorf("archive exceeds %d total bytes", lim.maxTotalBytes)
			}
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
			n, copyErr := io.Copy(f, io.LimitReader(tr, h.Size))
			if copyErr == nil && n != h.Size {
				copyErr = fmt.Errorf("declared %d bytes, got %d", h.Size, n)
			}
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

func safeArchivePath(name string, lim archiveLimits) (string, error) {
	if len(name) > lim.maxPathBytes {
		// Deliberately not echoing the name: errors must stay bounded.
		return "", fmt.Errorf("archive path length %d exceeds %d bytes", len(name), lim.maxPathBytes)
	}
	if name == "" || filepath.IsAbs(name) {
		return "", fmt.Errorf("archive path %q is invalid", name)
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) ||
		clean == ".git" || strings.HasPrefix(clean, ".git"+string(filepath.Separator)) ||
		clean == ".vuelta" || strings.HasPrefix(clean, ".vuelta"+string(filepath.Separator)) {
		return "", fmt.Errorf("archive path %q is not allowed", name)
	}
	if strings.Count(clean, string(filepath.Separator))+1 > lim.maxPathDepth {
		return "", fmt.Errorf("archive path %q exceeds depth %d", name, lim.maxPathDepth)
	}
	return clean, nil
}
