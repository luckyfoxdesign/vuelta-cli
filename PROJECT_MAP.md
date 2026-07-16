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
│                        # sandbox, testrunner, autofix, gitops, tasks, notify, logging, scheduler
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
docker compose up -d egress-proxy # strict local package-registry proxy
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
- `compose.yml` — Docker services: test, race, lint, tidy, build, egress-proxy.
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
- `internal/egress/` — resolves the checked-in, fail-closed Docker egress policy shared by containers that need approved registry access.
- `internal/githubalerts/` — is a read-only client for GitHub Dependabot and Security Advisories APIs.
- `internal/gitops/` — commits, pushes, and tags changes produced by an update run.
- `internal/localupdate/` — implements explicit adhoc host package-manager updates in a minimal private writable copy. It never calls Git or Docker, rejects changes outside the recognized manifest/lock pair, and is intentionally separate from the registered-workspace pipeline.
- `internal/logging/` — writes local, structured operational and audit logs without accepting configuration secrets or forwarding log content to notifiers.
- `internal/notify/` — sends run results via webhook and/or Telegram.
- `internal/pipeline/` — applies one selected workspace snapshot through preflight, sandbox, security gates, update, diff/allowlist checks, tests, optional autofix, commit, push, and notification. The runner uses the hardened isolation provided by sandbox, updater, and testrunner.
- `internal/sandbox/` — prepares a one-off, cleaned working copy (no .git, no .env, no untracked files) for running updates and tests in a container. See part F of the spec for the isolation model.
- `internal/scanner/` — validates the explicitly configured project paths and determines each project's stack. It never walks parent directories or discovers projects on its own; only workspaces[] from the config are ever considered.
- `internal/scheduler/` — orchestrates the public scan and update CLI contract. It intentionally remains outside the vuelta command tree: each update still receives exactly one reviewed snapshot ID.
- `internal/tasks/` — creates and reads immutable deploy candidates. It never deploys anything: delivery verification and rollback are owned by the production worker.
- `internal/testfixture/` — provides deterministic, network-free project fixtures and external-service stand-ins for integration and acceptance tests.
- `internal/testrunner/` — runs a project's docker compose test service against the sandboxed working copy.
- `internal/updater/` — discovers package candidates in read-only hardened containers and applies validated dependency and Docker image plans inside a sandboxed working copy.
- `internal/updatesnapshot/` — stores short-lived, read-only package update plans. A snapshot deliberately contains only metadata and candidate versions; it never stores project file contents, command output, or configuration secrets.
- `internal/vulnscan/` — runs pinned Trivy and/or OSV-Scanner containers for CVE scanning of dependencies and built images.
<!-- generated:end -->

<!-- manual:start -->
## Architecture Notes

- One-shot CLI, no resident daemon; scheduling is external (launchd/systemd timer).
- The top-level `scan` → `update SNAPSHOT_ID` workflow validates a single format-2 snapshot before environment checks. Registered updates remain container-only; explicit adhoc `--execution local` is the sole narrow host-manager exception and never runs project tests.
- One `internal/` package per pipeline stage; `internal/updater` exposes an `Updater` interface with one implementation per stack (python/node/docker).
- `deploy/` contains scheduler examples only; the binary remains a one-shot CLI.
- Deploy candidates are immutable handoffs. `internal/deployworker` verifies signed queue/manifest delivery, records state atomically, and rolls back a failed digest-pinned Compose rollout.

## Conventions

- `internal/config` never auto-discovers projects: only `workspaces[].path` from the config is ever touched.
- New workspaces persist stable names and project-scoped changed-path allowlists; unnamed legacy workspaces use a warning-only basename fallback without automatic rewrites.
- Go module dependencies are managed only via `docker compose run --rm tidy`, never a host-installed `go`.

## Known Sharp Edges

- `config.example.yaml` uses real arm64 image digests. Refresh them deliberately with `docker manifest inspect --verbose` when upgrading an image or toolchain.
- A real package-manager update needs `docker compose up -d egress-proxy`; Vuelta rejects an unavailable proxy/network before an updater starts.
- `.golangci.yml` targets golangci-lint v2's config schema (`version: "2"`), matching the pinned `golangci/golangci-lint:v2.12.2-alpine` image in `compose.yml`.
<!-- manual:end -->
