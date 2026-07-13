// Package gitops commits, pushes, and tags changes produced by an update run.
package gitops

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// FetchAndBaseSHA runs `git fetch --prune` against remote and returns the
// exact SHA of remote/branch at that moment. Callers keep this SHA and pass
// it to VerifyBaseSHAUnchanged right before committing, so a push that
// landed on the remote while this run was updating is never silently
// overwritten.
func FetchAndBaseSHA(ctx context.Context, repoPath, remote, branch string) (string, error) {
	if _, err := runGit(ctx, repoPath, "fetch", "--prune", remote); err != nil {
		return "", err
	}
	return remoteSHA(ctx, repoPath, remote, branch)
}

// VerifyBaseSHAUnchanged re-fetches remote and fails if remote/branch has
// moved past baseSHA.
func VerifyBaseSHAUnchanged(ctx context.Context, repoPath, remote, branch, baseSHA string) error {
	if _, err := runGit(ctx, repoPath, "fetch", "--prune", remote); err != nil {
		return err
	}
	current, err := remoteSHA(ctx, repoPath, remote, branch)
	if err != nil {
		return err
	}
	if current != baseSHA {
		return fmt.Errorf("base SHA changed since fetch: was %s, now %s", baseSHA, current)
	}
	return nil
}

func remoteSHA(ctx context.Context, repoPath, remote, branch string) (string, error) {
	out, err := runGit(ctx, repoPath, "rev-parse", fmt.Sprintf("%s/%s", remote, branch))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// NewLandingCopy creates a git worktree of repoPath detached at baseSHA in a
// fresh temporary directory. It is the git-backed working copy that
// SyncTree, DiffCheck, Commit, and Push operate on — distinct from the
// container sandbox (part F) that runs the updater and tests without a
// .git directory at all.
func NewLandingCopy(ctx context.Context, repoPath, baseSHA string) (dir string, cleanup func() error, err error) {
	tmp, err := os.MkdirTemp("", "vuelta-landing-*")
	if err != nil {
		return "", nil, fmt.Errorf("create landing tmp dir: %w", err)
	}
	// git worktree add wants to create the directory itself.
	if err := os.Remove(tmp); err != nil {
		return "", nil, fmt.Errorf("prepare landing tmp dir: %w", err)
	}
	if _, err := runGit(ctx, repoPath, "worktree", "add", "--detach", tmp, baseSHA); err != nil {
		return "", nil, err
	}
	cleanup = func() error {
		_, rmErr := runGit(ctx, repoPath, "worktree", "remove", "--force", tmp)
		return rmErr
	}
	return tmp, cleanup, nil
}

// SyncTree copies every regular file from src into dst at the same
// relative path, creating directories as needed. It refuses to copy
// symlinks or any non-regular file: the sandbox that produces src is
// expected to contain only tracked files and the updater's own edits, and
// a symlink appearing there is treated as a policy violation rather than
// something to silently follow. It never touches dst's own .git.
func SyncTree(src, dst string) error {
	if err := rejectMissingFiles(src, dst); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) {
			return fmt.Errorf("sync: refusing to copy %s from sandbox", rel)
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("sync: %s is a symlink, refusing to copy", rel)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("sync: %s is not a regular file", rel)
		}
		return copyFile(path, target)
	})
}

// rejectMissingFiles prevents an updater or AI agent from deleting a tracked
// file in the sandbox and having that deletion silently disappear when the
// sandbox is copied into the Git-backed landing worktree. Deletions are a
// security-policy failure, not an operation SyncTree attempts to reproduce.
func rejectMissingFiles(src, dst string) error {
	return filepath.WalkDir(dst, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dst, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if rel == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("sync: destination %s is not a regular file", rel)
		}
		info, err := os.Lstat(filepath.Join(src, rel))
		if os.IsNotExist(err) {
			return fmt.Errorf("sync: sandbox deleted tracked file %s", rel)
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("sync: sandbox path %s is not a regular file", rel)
		}
		return nil
	})
}

func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode().Perm())
}

// DiffCheck compares the landing copy's working tree against its checked
// out HEAD (which is baseSHA) and fails closed unless every changed path is
// allowlisted, is a plain-file modification (no rename/delete/symlink/mode
// change), and passes `git diff --check`.
func DiffCheck(ctx context.Context, repoPath string, allowedPaths []string) error {
	out, err := runGit(ctx, repoPath, "status", "--porcelain")
	if err != nil {
		return err
	}
	out = strings.TrimRight(out, "\n")
	if out == "" {
		return nil
	}
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if len(line) < 4 {
			return fmt.Errorf("unexpected git status line: %q", line)
		}
		status := line[:2]
		rel := strings.TrimSpace(line[3:])
		if strings.Contains(rel, " -> ") {
			return fmt.Errorf("path rename is not allowed: %q", rel)
		}
		if strings.Contains(status, "D") {
			return fmt.Errorf("path deletion is not allowed: %s", rel)
		}
		if !pathAllowed(rel, allowedPaths) {
			return fmt.Errorf("changed path %q is outside git.allowed_changed_paths", rel)
		}
		full := filepath.Join(repoPath, rel)
		info, err := os.Lstat(full)
		if err != nil {
			return fmt.Errorf("stat changed path %s: %w", rel, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("changed path %q is a symlink, not allowed", rel)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("changed path %q is not a regular file", rel)
		}
	}
	if _, err := runGit(ctx, repoPath, "diff", "--check"); err != nil {
		return fmt.Errorf("git diff --check: %w", err)
	}
	return nil
}

// AllowlistedDiff returns the checked policy-approved diff for an AI autofix
// prompt. It first performs DiffCheck, then asks Git only for the configured
// paths. Callers must treat the returned bytes as untrusted input and never
// send it to notifications or logs.
func AllowlistedDiff(ctx context.Context, repoPath string, allowedPaths []string) (string, error) {
	if err := DiffCheck(ctx, repoPath, allowedPaths); err != nil {
		return "", err
	}
	args := append([]string{"diff", "--no-ext-diff", "--"}, allowedPaths...)
	out, err := runGit(ctx, repoPath, args...)
	if err != nil {
		return "", err
	}
	return out, nil
}

func pathAllowed(rel string, patterns []string) bool {
	base := filepath.Base(rel)
	for _, p := range patterns {
		if ok, _ := filepath.Match(p, rel); ok {
			return true
		}
		if ok, _ := filepath.Match(p, base); ok {
			return true
		}
	}
	return false
}

// CommitSummary holds only the allowlisted content that may appear in a
// dependency-update commit message: package/version lines and CVE/GHSA
// identifiers. It never includes raw test logs or diffs.
type CommitSummary struct {
	Date     time.Time
	Packages []string
	CVERefs  []string
}

// Message renders the commit message per part B §7 step 8:
// "chore(deps): update dependencies YYYY-MM-DD" with an allowlisted body.
func (s CommitSummary) Message() string {
	var b strings.Builder
	fmt.Fprintf(&b, "chore(deps): update dependencies %s\n", s.Date.Format("2006-01-02"))
	if len(s.Packages) > 0 {
		b.WriteString("\n")
		for _, p := range s.Packages {
			fmt.Fprintf(&b, "- %s\n", p)
		}
	}
	if len(s.CVERefs) > 0 {
		b.WriteString("\n")
		for _, c := range s.CVERefs {
			fmt.Fprintf(&b, "Refs: %s\n", c)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// Commit stages every change in repoPath and commits it with summary's
// message. Callers must run DiffCheck first: Commit does not re-validate
// the allowlist itself.
func Commit(ctx context.Context, repoPath string, summary CommitSummary) error {
	if _, err := runGit(ctx, repoPath, "add", "-A"); err != nil {
		return err
	}
	if _, err := runGit(ctx, repoPath, "commit", "-q", "-m", summary.Message()); err != nil {
		return err
	}
	return nil
}

// HeadSHA returns the immutable commit currently checked out in repoPath.
func HeadSHA(ctx context.Context, repoPath string) (string, error) {
	out, err := runGit(ctx, repoPath, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// ChangedPaths returns the policy-checked paths staged for the next commit.
// Callers must run DiffCheck first; this function is only an audit helper.
func ChangedPaths(ctx context.Context, repoPath string) ([]string, error) {
	out, err := runGit(ctx, repoPath, "diff", "--name-only", "--no-ext-diff")
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

// AutofixBranch returns the fixed review-branch name for an autofix commit,
// per part C: vuelta/autofix/<project>-<YYYY-MM-DD>.
func AutofixBranch(project string, now time.Time) string {
	return fmt.Sprintf("vuelta/autofix/%s-%s", project, now.Format("2006-01-02"))
}

// reviewBranch returns the default review-branch name for a dependency
// update, per part B §7 step 9: vuelta/deps/<project>-<YYYY-MM-DD>.
func reviewBranch(project string, now time.Time) string {
	return fmt.Sprintf("vuelta/deps/%s-%s", project, now.Format("2006-01-02"))
}

// Push publishes repoPath's current HEAD commit. In the default
// review_branch mode it always pushes to a fresh vuelta/deps/<project>-date
// branch for review. direct_branch is an explicitly opted-in exception and
// is only accepted when HEAD fast-forwards from remote/branch; verifying
// that the target branch is actually protected on the remote is out of
// scope here (parts D/G own the deploy-side remote API checks). It returns
// the branch name that was pushed.
func Push(ctx context.Context, repoPath string, ws config.Workspace, git config.GitConfig, project string, now time.Time) (string, error) {
	switch git.PushMode {
	case "direct_branch":
		if err := verifyFastForward(ctx, repoPath, ws.Remote, ws.Branch); err != nil {
			return "", fmt.Errorf("direct_branch push blocked: %w", err)
		}
		if _, err := runGit(ctx, repoPath, "push", ws.Remote, fmt.Sprintf("HEAD:%s", ws.Branch)); err != nil {
			return "", err
		}
		return ws.Branch, nil
	default:
		branch := reviewBranch(project, now)
		if _, err := runGit(ctx, repoPath, "push", ws.Remote, fmt.Sprintf("HEAD:refs/heads/%s", branch)); err != nil {
			return "", err
		}
		return branch, nil
	}
}

// PushBranch force-creates and pushes an explicit named branch (used for
// the autofix review branch, which is never review_branch/direct_branch
// selected — it always goes to vuelta/autofix/<project>-<date>).
func PushBranch(ctx context.Context, repoPath, remote, branch string) error {
	_, err := runGit(ctx, repoPath, "push", remote, fmt.Sprintf("HEAD:refs/heads/%s", branch))
	return err
}

func verifyFastForward(ctx context.Context, repoPath, remote, branch string) error {
	if _, err := runGit(ctx, repoPath, "merge-base", "--is-ancestor", fmt.Sprintf("%s/%s", remote, branch), "HEAD"); err != nil {
		return fmt.Errorf("remote %s/%s is not an ancestor of HEAD: %w", remote, branch, err)
	}
	return nil
}
