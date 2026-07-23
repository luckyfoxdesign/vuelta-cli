# vuelta-app Project Map
<!-- Repo-local map is the source of truth for this repo internals. -->
<!-- Workspace ../PROJECT_MAP.md aggregates repo maps and should not duplicate this detail. -->

## Map contract

- Keep generated facts inside `generated` block.
- Keep short repo-local notes inside `manual` block.
- Store long architecture decisions in workspace `../docs/product/architecture/`.
- Update this map when repo structure, entrypoints, commands, routes, jobs, models, or configs change.
- Keep the repo-local update script at `scripts/update-project-map.sh`.

<!-- generated:start -->
## Generated Structure

```text
app/
├── AGENTS.md, CLAUDE.md, PROJECT_MAP.md
├── cmd/vuelta/          # one-snapshot CLI entrypoint
├── cmd/vuelta-scheduler/ # external JSON orchestration helper
├── internal/            # config, localupdate, scanner, updater, updatesnapshot, vulnscan, githubalerts,
│                        # toolchain, sandbox, testrunner, autofix, gitops, tasks, notify, logging, scheduler
├── acceptance/          # opt-in real Docker engine scan/update matrix
├── scanner-images/      # embedded exact-version scanner build inputs
├── egress/              # local registry-allowlisting forward proxy
├── deploy/              # launchd and systemd scheduler examples
├── config.example.yaml, Makefile
├── Dockerfile, compose.yml, .golangci.yml
└── scripts/update-project-map.sh
```

## Commands

```bash
docker compose run --rm test   # go test ./...
docker compose run --rm race   # go test -race ./...
docker compose run --rm lint   # golangci-lint run
docker compose run --rm tidy   # go mod tidy
docker compose run --rm build  # go build ./...
vuelta environment bootstrap --socket PATH # trust one explicit Docker endpoint
scripts/real-engine-acceptance.sh MATRIX # manual/networked real-engine suite
make build-mac                 # Docker cross-build both binaries for darwin/arm64
make build-linux               # Docker cross-build both binaries for linux/amd64
make build                     # both cross-build targets
```

## Entrypoints

- `cmd/vuelta-scheduler/main.go` — `vuelta-scheduler` binary entrypoint.
- `cmd/vuelta/main.go` — `vuelta` binary entrypoint.

## Config Files

- `go.mod` — Go module definition.
- `config.example.yaml` — template for `~/.config/vuelta/config.yaml`.
- `local.example.yaml` — optional standalone allowlist policy for an explicit adhoc scan.
- `compose.yml` — Docker services: test, race, lint, tidy, build, egress-proxy, opt-in real-engine.
- `scanner-images/` — embedded exact-version scanner build inputs.
- `acceptance/` — environment-gated real-engine matrix and example catalog.
- `egress/` — local fail-closed proxy and its scratch-image Dockerfile.
- `Dockerfile` — shared dev image for the test/race/tidy/build services.
- `Makefile` — Docker-only cross-build targets for the CLI and scheduler.
- `.golangci.yml` — lint rules.
- `deploy/` — external launchd/systemd scheduling examples.
- `scripts/update-project-map.sh` — updates this repo map generated block.

## Notable Directories

- `internal/autofix/` — optionally invokes `claude -p` when tests fail after an update. Test logs/diffs are untrusted input: the invocation never grants Bash tool access (see part C of the spec).
- `internal/capio/` — provides bounded collectors for untrusted subprocess output. Limits are enforced while the child is still streaming, so host memory stays bounded regardless of how much a process writes: Tail soft-truncates diagnostic output to a marked tail, Limit hard-stops structured output that must be parsed in full.
- `internal/config/` — loads and validates vuelta's config.yaml (~/.config/vuelta/config.yaml).  Validation never walks parent directories or discovers projects: only the paths explicitly listed under workspaces[] are ever scanned or updated.
- `internal/configinit/` — creates protected config containers, deterministically detects a selected project's supported files, and applies reviewed project edits. It never walks parent directories or reads unallowlisted files.
- `internal/deployworker/` — applies authenticated, immutable deployment candidates and restores the previous digest when a rollout is unhealthy.
- `internal/dockerexec/` — is the single process boundary for Docker CLI commands. It binds commands to one verified absolute executable and approved local Unix socket, attests daemon identity/capabilities, and runs every command with a minimal environment and bounded output collectors.
- `internal/egress/` — owns the fail-closed Docker network and registry proxy used by networked scanner stages.
- `internal/egressproxy/` — implements the embedded registry-allowlisting forward proxy used by Vuelta-managed scanner networks.
- `internal/gitexec/` — is the single process boundary for production Git commands.  Security invariants:   - the executable is selected only from compiled-in absolute system paths;   - children receive a small explicit environment, never the caller's Git,     askpass, proxy, or executable-selection variables;   - system/global config, hooks, fsmonitor, credential helpers, external     diff, automatic maintenance, signing, and unsafe protocols are disabled;   - callers may run only the reviewed command set and may add only a private     absolute GIT_INDEX_FILE.  Repository data and ordinary non-executable repository configuration remain visible to Git. Callers must still validate remote names, refs, and paths at their own trust boundary before placing them in argv.
- `internal/githubalerts/` — is a read-only client for GitHub Dependabot and Security Advisories APIs.  The client sends the configured token only to the single approved HTTPS origin derived from the validated API base URL. Pagination must stay on that origin, redirects are never followed, and response size, page count, and decoded alert count are hard-bounded.
- `internal/gitops/` — commits, pushes, and tags changes produced by an update run.
- `internal/gitpath/` — defines platform-independent matching for Git repository paths.
- `internal/localexec/` — is the process boundary for the explicit host-local tools. It resolves only allowlisted executables, gives every child a private state tree and minimal environment, and bounds all captured output.
- `internal/localupdate/` — implements explicit adhoc host package-manager updates in a minimal private writable copy. It never calls Git or Docker, rejects changes outside the recognized manifest/lock pair, and is intentionally separate from the registered-workspace pipeline.
- `internal/logging/` — writes local, structured operational and audit logs without accepting configuration secrets or forwarding log content to notifiers.
- `internal/notify/` — sends run results via webhook and/or Telegram.
- `internal/pipeline/` — applies one selected workspace snapshot through preflight, sandbox, security gates, update, diff/allowlist checks, tests, optional autofix, commit, push, and notification. The runner uses the hardened isolation provided by sandbox, updater, and testrunner.
- `internal/repopolicy/` — TODO: describe this package.
- `internal/safeerr/` — builds safe, bounded, redacted diagnostic text and stable failure categories for hardened command boundaries (dockerexec, localexec). It only ever operates on output a boundary already captured under its own size limits; it never sees full argv, environment, or unbounded output.
- `internal/sandbox/` — prepares a one-off, cleaned working copy (no .git, no .env, no untracked files) for running updates and tests in a container. See part F of the spec for the isolation model.
- `internal/scancontainer/` — runs a scanner against an in-memory input archive. Repository contents are copied into a stopped container through Docker's stdin API; no host path is mounted and no host staging copy is created.
- `internal/scaninput/` — TODO: describe this package.
- `internal/scanner/` — validates the explicitly configured project paths and determines each project's stack. It never walks parent directories or discovers projects on its own; only workspaces[] from the config are ever considered.
- `internal/scheduler/` — orchestrates the public scan and update CLI contract. It intentionally remains outside the vuelta command tree: each update still receives exactly one reviewed snapshot ID.
- `internal/tasks/` — creates and reads immutable deploy candidates. It never deploys anything: delivery verification and rollback are owned by the production worker.
- `internal/testfixture/` — provides deterministic, network-free project fixtures and external-service stand-ins for integration and acceptance tests.
- `internal/testrunner/` — runs a project's docker compose test service against the sandboxed working copy.
- `internal/toolchain/` — resolves declarative project constraints to an operator override or embedded scan default and builds defaults without executing project code.
- `internal/updater/` — discovers package candidates in read-only hardened containers and applies validated dependency and Docker image plans inside a sandboxed working copy.
- `internal/updatesnapshot/` — stores short-lived, read-only package update plans. A snapshot deliberately contains only metadata and candidate versions; it never stores project file contents, command output, or configuration secrets.
- `internal/vulnscan/` — runs pinned Trivy and/or OSV-Scanner containers for CVE scanning of dependencies and built images.
<!-- generated:end -->

<!-- manual:start -->
## Architecture Notes

- One-shot CLI, no resident daemon; scheduling is external (launchd/systemd timer).
- The top-level `scan` → `update SNAPSHOT_ID` workflow validates a single format-3 snapshot before environment checks. Registered updates remain container-only; explicit adhoc `--execution local` is the sole narrow host-manager exception and never runs project tests.
- Registered scan containers never mount a live repository. `internal/scaninput` builds an exact tracked allowlist in memory, while `internal/scancontainer` transfers it through a stopped loader into an ephemeral image and starts only the separately hardened read-only scanner container.
- One `internal/` package per pipeline stage; `internal/updater` exposes an `Updater` interface with one implementation per stack (python/node/docker).
- `deploy/` contains scheduler examples only; the binary remains a one-shot CLI.
- Deploy candidates are immutable handoffs. `internal/deployworker` verifies signed queue/manifest delivery, records state atomically, and rolls back a failed digest-pinned Compose rollout.

## Conventions

- `internal/config` never auto-discovers projects: only `workspaces[].path` from the config is ever touched.
- New workspaces persist stable names and project-scoped changed-path allowlists; unnamed legacy workspaces use a warning-only basename fallback without automatic rewrites.
- Go module dependencies are managed only via `docker compose run --rm tidy`, never a host-installed `go`.

## Known Sharp Edges

- Package scanner defaults are embedded and built locally on demand; `update.toolchain_profiles` is only an explicit digest-pinned operator override.
- Container scans lazily build the embedded egress proxy, verify its exact local image identity, and manage only labeled Vuelta-owned network/container resources; no source checkout or Compose startup is required.
- `.golangci.yml` targets golangci-lint v2's config schema (`version: "2"`), matching the tag-and-digest-pinned `golangci/golangci-lint:v2.12.2-alpine` image in `compose.yml`; refresh its multi-platform index digest with the controlled process in `README.md`.
<!-- manual:end -->
