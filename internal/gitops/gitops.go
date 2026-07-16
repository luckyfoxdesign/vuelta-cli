// Package gitops commits, pushes, and tags changes produced by an update run.
package gitops

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
	"github.com/luckyfoxdesign/vuelta/internal/gitexec"
	"github.com/luckyfoxdesign/vuelta/internal/gitpath"
	"github.com/luckyfoxdesign/vuelta/internal/sandbox"
)

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	return runGitEnv(ctx, dir, nil, args...)
}

func runGitEnv(ctx context.Context, dir string, env []string, args ...string) (string, error) {
	var out []byte
	var err error
	if len(env) == 0 {
		out, err = gitexec.Output(ctx, dir, args...)
	} else if len(env) == 1 && strings.HasPrefix(env[0], "GIT_INDEX_FILE=") {
		out, err = gitexec.OutputWithIndex(ctx, dir, strings.TrimPrefix(env[0], "GIT_INDEX_FILE="), args...)
	} else {
		return "", errors.New("unsupported Git environment")
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", fmt.Errorf("git %s: %w", args[0], err)
	}
	return string(out), nil
}

// FetchAndBaseSHA runs `git fetch --prune` against remote and returns the
// exact SHA of remote/branch at that moment. Callers keep this SHA and pass
// it to VerifyBaseSHAUnchanged right before committing, so a push that
// landed on the remote while this run was updating is never silently
// overwritten.
func FetchAndBaseSHA(ctx context.Context, repoPath, remote, branch string) (string, error) {
	if err := validateRemoteBranch(remote, branch); err != nil {
		return "", err
	}
	if _, err := runGit(ctx, repoPath, "fetch", "--prune", remote); err != nil {
		return "", err
	}
	return remoteSHA(ctx, repoPath, remote, branch)
}

// VerifyBaseSHAUnchanged re-fetches remote and fails if remote/branch has
// moved past baseSHA.
func VerifyBaseSHAUnchanged(ctx context.Context, repoPath, remote, branch, baseSHA string) error {
	if err := validateRemoteBranch(remote, branch); err != nil {
		return err
	}
	if err := gitexec.ValidateCommitSHA(baseSHA); err != nil {
		return err
	}
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
	out, err := runGit(ctx, repoPath, "rev-parse", "--verify", "--end-of-options", fmt.Sprintf("refs/remotes/%s/%s", remote, branch))
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
	if err := gitexec.ValidateCommitSHA(baseSHA); err != nil {
		return "", nil, err
	}
	cleanTree, cleanTreeCleanup, err := sandbox.Prepare(ctx, repoPath, baseSHA)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = cleanTreeCleanup() }()
	tmp, err := os.MkdirTemp("", "vuelta-landing-*")
	if err != nil {
		return "", nil, fmt.Errorf("create landing tmp dir: %w", err)
	}
	// git worktree add wants to create the directory itself.
	if err := os.Remove(tmp); err != nil {
		return "", nil, fmt.Errorf("prepare landing tmp dir: %w", err)
	}
	if _, err := runGit(ctx, repoPath, "worktree", "add", "--no-checkout", "--detach", tmp, baseSHA); err != nil {
		return "", nil, err
	}
	// --no-checkout deliberately leaves the worktree index unpopulated. Seed it
	// from the immutable base tree without materializing files or filters.
	if _, err := runGit(ctx, tmp, "read-tree", baseSHA); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = runGit(cleanupCtx, repoPath, "worktree", "remove", "--force", tmp)
		return "", nil, err
	}
	if err := SyncTree(cleanTree, tmp); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = runGit(cleanupCtx, repoPath, "worktree", "remove", "--force", tmp)
		return "", nil, fmt.Errorf("populate hook-free landing copy: %w", err)
	}
	cleanup = func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, rmErr := runGit(cleanupCtx, repoPath, "worktree", "remove", "--force", tmp)
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
	if err := gitpath.ValidatePatterns(allowedPaths); err != nil {
		return fmt.Errorf("validate git.allowed_changed_paths: %w", err)
	}
	head, err := HeadSHA(ctx, repoPath)
	if err != nil {
		return err
	}
	changes, err := gitexec.InspectWorktree(ctx, repoPath, head)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		return nil
	}
	if err := validateWorktreeChanges(repoPath, changes, allowedPaths); err != nil {
		return err
	}
	tree, cleanup, err := stageTree(ctx, repoPath, head, changes)
	if err != nil {
		return err
	}
	defer cleanup()
	raw, err := runGit(ctx, repoPath, "diff-tree", "--raw", "-z", "--no-commit-id", "--no-abbrev", "-r", "--find-renames", head, tree)
	if err != nil {
		return err
	}
	if _, err := validateRawChanges(raw, allowedPaths); err != nil {
		return fmt.Errorf("working tree policy: %w", err)
	}
	if _, err := runGit(ctx, repoPath, "diff-tree", "--no-ext-diff", "--no-textconv", "--check", "-r", head, tree); err != nil {
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
	head, err := HeadSHA(ctx, repoPath)
	if err != nil {
		return "", err
	}
	changes, err := gitexec.InspectWorktree(ctx, repoPath, head)
	if err != nil {
		return "", err
	}
	if len(changes) == 0 {
		return "", nil
	}
	tree, cleanup, err := stageTree(ctx, repoPath, head, changes)
	if err != nil {
		return "", err
	}
	defer cleanup()
	out, err := runGit(ctx, repoPath, "diff-tree", "-p", "--no-ext-diff", "--no-textconv", "--no-commit-id", "-r", head, tree, "--")
	if err != nil {
		return "", err
	}
	return out, nil
}

func pathAllowed(rel string, patterns []string) bool {
	allowed, err := gitpath.Allowed(rel, patterns)
	return err == nil && allowed
}

func validateWorktreeChanges(repoPath string, changes []gitexec.WorktreeChange, allowedPaths []string) error {
	for _, change := range changes {
		if change.Status != "A" && change.Status != "M" {
			return fmt.Errorf("changed path %q has unsupported git status %q", change.Path, change.Status)
		}
		allowed, err := gitpath.Allowed(change.Path, allowedPaths)
		if err != nil {
			return fmt.Errorf("validate changed path %q: %w", change.Path, err)
		}
		if !allowed {
			return fmt.Errorf("changed path %q is outside git.allowed_changed_paths", change.Path)
		}
		info, err := os.Lstat(filepath.Join(repoPath, filepath.FromSlash(change.Path)))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("changed path %q is not a regular file", change.Path)
		}
	}
	return nil
}

func stageTree(ctx context.Context, repoPath, head string, changes []gitexec.WorktreeChange) (string, func(), error) {
	indexDir, err := os.MkdirTemp("", "vuelta-git-index-*")
	if err != nil {
		return "", nil, fmt.Errorf("create private Git index directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(indexDir) }
	indexEnv := []string{"GIT_INDEX_FILE=" + filepath.Join(indexDir, "index")}
	if _, err := runGitEnv(ctx, repoPath, indexEnv, "read-tree", head); err != nil {
		cleanup()
		return "", nil, err
	}
	for _, change := range changes {
		if change.Status != "A" && change.Status != "M" {
			cleanup()
			return "", nil, fmt.Errorf("cannot stage path %q with status %q", change.Path, change.Status)
		}
		info, err := os.Lstat(filepath.Join(repoPath, filepath.FromSlash(change.Path)))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			cleanup()
			return "", nil, fmt.Errorf("cannot stage non-regular path %q", change.Path)
		}
		blob, err := runGit(ctx, repoPath, "hash-object", "-w", "--no-filters", "--", change.Path)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		blob = strings.TrimSpace(blob)
		if err := gitexec.ValidateCommitSHA(blob); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("invalid Git blob object ID: %w", err)
		}
		mode := "100644"
		if info.Mode().Perm()&0o111 != 0 {
			mode = "100755"
		}
		if _, err := runGitEnv(ctx, repoPath, indexEnv, "update-index", "--add", "--cacheinfo", mode+","+blob+","+change.Path); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	tree, err := runGitEnv(ctx, repoPath, indexEnv, "write-tree")
	if err != nil {
		cleanup()
		return "", nil, err
	}
	tree = strings.TrimSpace(tree)
	if err := gitexec.ValidateCommitSHA(tree); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("invalid Git tree object ID: %w", err)
	}
	return tree, cleanup, nil
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

// Commit stages the current working tree in a private index, validates the
// resulting immutable tree with the same allowlist and file-type policy as
// DiffCheck, and advances HEAD to a commit containing exactly that tree. The
// private index and commit-tree plumbing prevent a shared-index or working-tree
// mutation between the final policy check and commit from changing its content.
func Commit(ctx context.Context, repoPath string, allowedPaths []string, summary CommitSummary) error {
	if err := gitpath.ValidatePatterns(allowedPaths); err != nil {
		return fmt.Errorf("validate git.allowed_changed_paths: %w", err)
	}
	head, err := HeadSHA(ctx, repoPath)
	if err != nil {
		return err
	}
	changes, err := gitexec.InspectWorktree(ctx, repoPath, head)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		return errors.New("nothing to commit")
	}
	if err := validateWorktreeChanges(repoPath, changes, allowedPaths); err != nil {
		return err
	}
	tree, cleanup, err := stageTree(ctx, repoPath, head, changes)
	if err != nil {
		return err
	}
	defer cleanup()
	raw, err := runGit(ctx, repoPath, "diff-tree", "--raw", "-z", "--no-commit-id", "--no-abbrev", "-r", "--find-renames", head, tree)
	if err != nil {
		return err
	}
	count, err := validateRawChanges(raw, allowedPaths)
	if err != nil {
		return fmt.Errorf("final staged tree policy: %w", err)
	}
	if count == 0 {
		return errors.New("nothing to commit")
	}
	if _, err := runGit(ctx, repoPath, "diff-tree", "--no-ext-diff", "--no-textconv", "--check", "-r", head, tree); err != nil {
		return fmt.Errorf("final staged tree git diff --check: %w", err)
	}
	nameStatus, err := runGit(ctx, repoPath, "diff-tree", "--name-status", "-z", "--no-commit-id", "--no-renames", "-r", head, tree, "--")
	if err != nil {
		return err
	}
	if err := validateStagedNameStatus(nameStatus, allowedPaths, count); err != nil {
		return fmt.Errorf("final NUL-delimited staged status policy: %w", err)
	}
	commit, err := runGit(ctx, repoPath, "commit-tree", tree, "-p", head, "-m", summary.Message())
	if err != nil {
		return err
	}
	commit = strings.TrimSpace(commit)
	if _, err := runGit(ctx, repoPath, "update-ref", "HEAD", commit, head); err != nil {
		return err
	}
	return nil
}

// HeadSHA returns the immutable commit currently checked out in repoPath.
func HeadSHA(ctx context.Context, repoPath string) (string, error) {
	out, err := runGit(ctx, repoPath, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(out)
	if err := gitexec.ValidateCommitSHA(sha); err != nil {
		return "", err
	}
	return sha, nil
}

// ChangedPaths returns the policy-checked working-tree paths for the next
// commit. Callers must run DiffCheck first; this function is only an audit helper.
func ChangedPaths(ctx context.Context, repoPath string) ([]string, error) {
	head, err := HeadSHA(ctx, repoPath)
	if err != nil {
		return nil, err
	}
	changes, err := gitexec.InspectWorktree(ctx, repoPath, head)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(changes))
	for _, change := range changes {
		paths = append(paths, change.Path)
	}
	return paths, nil
}

type porcelainChange struct {
	status string
	path   string
}

func parsePorcelainStatus(out string) ([]porcelainChange, error) {
	fields, err := splitNUL(out)
	if err != nil {
		return nil, fmt.Errorf("parse git status: %w", err)
	}
	changes := make([]porcelainChange, 0, len(fields))
	for _, field := range fields {
		if len(field) < 4 || field[2] != ' ' {
			return nil, fmt.Errorf("unexpected NUL-delimited git status entry: %q", field)
		}
		status, rel := field[:2], field[3:]
		if strings.ContainsAny(status, "RC") {
			return nil, fmt.Errorf("path rename or copy is not allowed: status %q path %q", status, rel)
		}
		if err := gitpath.ValidatePath(rel); err != nil {
			return nil, err
		}
		changes = append(changes, porcelainChange{status: status, path: rel})
	}
	return changes, nil
}

func validateStagedNameStatus(out string, allowedPaths []string, wantCount int) error {
	fields, err := splitNUL(out)
	if err != nil {
		return err
	}
	if len(fields)%2 != 0 {
		return errors.New("staged name/status output has an incomplete entry")
	}
	if len(fields)/2 != wantCount {
		return fmt.Errorf("staged name/status count changed: got %d, want %d", len(fields)/2, wantCount)
	}
	for i := 0; i < len(fields); i += 2 {
		status, rel := fields[i], fields[i+1]
		if status != "A" && status != "M" {
			return fmt.Errorf("staged path %q has unsupported status %q", rel, status)
		}
		allowed, err := gitpath.Allowed(rel, allowedPaths)
		if err != nil {
			return err
		}
		if !allowed {
			return fmt.Errorf("staged path %q is outside git.allowed_changed_paths", rel)
		}
	}
	return nil
}

type rawChange struct {
	oldMode string
	newMode string
	status  string
	paths   []string
}

func parseRawChanges(out string) ([]rawChange, error) {
	fields, err := splitNUL(out)
	if err != nil {
		return nil, fmt.Errorf("parse raw Git diff: %w", err)
	}
	changes := make([]rawChange, 0)
	for i := 0; i < len(fields); {
		header := fields[i]
		i++
		parts := strings.Fields(header)
		if len(parts) != 5 || !strings.HasPrefix(parts[0], ":") || len(parts[0]) != 7 {
			return nil, fmt.Errorf("unexpected raw Git diff header: %q", header)
		}
		status := parts[4]
		pathCount := 1
		if strings.HasPrefix(status, "R") || strings.HasPrefix(status, "C") {
			pathCount = 2
		}
		if i+pathCount > len(fields) {
			return nil, fmt.Errorf("raw Git diff entry %q is missing a path", header)
		}
		paths := append([]string(nil), fields[i:i+pathCount]...)
		i += pathCount
		for _, rel := range paths {
			if err := gitpath.ValidatePath(rel); err != nil {
				return nil, err
			}
		}
		changes = append(changes, rawChange{oldMode: strings.TrimPrefix(parts[0], ":"), newMode: parts[1], status: status, paths: paths})
	}
	return changes, nil
}

func validateRawChanges(out string, allowedPaths []string) (int, error) {
	changes, err := parseRawChanges(out)
	if err != nil {
		return 0, err
	}
	for _, change := range changes {
		if len(change.paths) != 1 || strings.HasPrefix(change.status, "R") || strings.HasPrefix(change.status, "C") {
			return 0, fmt.Errorf("rename or copy is not allowed: status %q paths %q", change.status, change.paths)
		}
		rel := change.paths[0]
		allowed, err := gitpath.Allowed(rel, allowedPaths)
		if err != nil {
			return 0, err
		}
		if !allowed {
			return 0, fmt.Errorf("changed path %q is outside git.allowed_changed_paths", rel)
		}
		switch change.status {
		case "A":
			if change.oldMode != "000000" || !regularGitMode(change.newMode) {
				return 0, fmt.Errorf("added path %q is not a regular file: modes %s -> %s", rel, change.oldMode, change.newMode)
			}
		case "M":
			if !regularGitMode(change.oldMode) || !regularGitMode(change.newMode) {
				return 0, fmt.Errorf("changed path %q is not a regular file: modes %s -> %s", rel, change.oldMode, change.newMode)
			}
			if change.oldMode != change.newMode {
				return 0, fmt.Errorf("mode change is not allowed for %q: %s -> %s", rel, change.oldMode, change.newMode)
			}
		default:
			return 0, fmt.Errorf("changed path %q has unsupported staged status %q", rel, change.status)
		}
	}
	return len(changes), nil
}

func regularGitMode(mode string) bool {
	return mode == "100644" || mode == "100755"
}

func splitNUL(out string) ([]string, error) {
	if out == "" {
		return nil, nil
	}
	if out[len(out)-1] != 0 {
		return nil, errors.New("output is not NUL-terminated")
	}
	return strings.Split(out[:len(out)-1], "\x00"), nil
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
	if err := validateRemoteBranch(ws.Remote, ws.Branch); err != nil {
		return "", err
	}
	switch git.PushMode {
	case "direct_branch":
		if err := verifyFastForward(ctx, repoPath, ws.Remote, ws.Branch); err != nil {
			return "", fmt.Errorf("direct_branch push blocked: %w", err)
		}
		if _, err := runGit(ctx, repoPath, "push", ws.Remote, fmt.Sprintf("HEAD:refs/heads/%s", ws.Branch)); err != nil {
			return "", err
		}
		return ws.Branch, nil
	default:
		branch := reviewBranch(project, now)
		if err := gitexec.ValidateBranch(branch); err != nil {
			return "", err
		}
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
	if err := validateRemoteBranch(remote, branch); err != nil {
		return err
	}
	_, err := runGit(ctx, repoPath, "push", remote, fmt.Sprintf("HEAD:refs/heads/%s", branch))
	return err
}

func verifyFastForward(ctx context.Context, repoPath, remote, branch string) error {
	if err := validateRemoteBranch(remote, branch); err != nil {
		return err
	}
	if _, err := runGit(ctx, repoPath, "merge-base", "--is-ancestor", fmt.Sprintf("refs/remotes/%s/%s", remote, branch), "HEAD"); err != nil {
		return fmt.Errorf("remote %s/%s is not an ancestor of HEAD: %w", remote, branch, err)
	}
	return nil
}

func validateRemoteBranch(remote, branch string) error {
	if err := gitexec.ValidateRemoteName(remote); err != nil {
		return err
	}
	return gitexec.ValidateBranch(branch)
}
