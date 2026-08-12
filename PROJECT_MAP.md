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
├── cmd/vuelta-gateway/  # minimal machine-owned blue/green HTTP gateway
├── cmd/vuelta-scheduler/ # external JSON orchestration helper
├── cmd/vuelta-telegram-bridge/ # SQLite-backed Telegram interface
├── cmd/vuelta-corpus/   # manual real-world corpus harness
├── internal/            # ecosystem adapters, config, scanner, updater, toolchain,
│                        # projectstate, updatesnapshot, vulnscan, sandbox, scheduler
├── acceptance/          # opt-in real-engine matrix and pinned corpus manifest
├── scanner-images/      # embedded exact-version scanner build inputs
├── egress/              # local registry-allowlisting forward proxy
├── .github/workflows/   # reusable update and central release engines
├── deploy/              # scheduler units, release engine, gateway image
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
vuelta project verify init       # generate hardened compose.verify.yml
vuelta project verify init --refresh-image # refresh only its pinned base image digest
vuelta project verify approve    # promote reviewed project verification
vuelta deploy plan PROJECT     # discover without project writes
vuelta deploy sync             # build/release/switch every ready workspace
vuelta deploy status [PROJECT] # durable contract and release state
vuelta deploy rollback PROJECT # restore recorded immutable prior digest
scripts/real-engine-acceptance.sh MATRIX # manual/networked real-engine suite
scripts/local-update-smoke.sh # non-interactive CLI-only local update dry-run
scripts/corpus-scan.sh ROOT [MODE] # manual pinned corpus scan and reports
scripts/corpus-refresh.sh ROOT # validated candidate pins without manifest mutation
make build-mac                 # Docker cross-build three binaries for darwin/arm64
make build-linux               # Docker cross-build three binaries for linux/amd64
make build                     # both cross-build targets
```

## Entrypoints

- `cmd/vuelta-corpus/main.go` — `vuelta-corpus` binary entrypoint.
- `cmd/vuelta-gateway/main.go` — `vuelta-gateway` binary entrypoint.
- `cmd/vuelta-scheduler/main.go` — `vuelta-scheduler` binary entrypoint.
- `cmd/vuelta-telegram-bridge/main.go` — `vuelta-telegram-bridge` binary entrypoint.
- `cmd/vuelta/main.go` — `vuelta` binary entrypoint.

## Config Files

- `go.mod` — Go module definition.
- `config.example.yaml` — template for `~/.config/vuelta/config.yaml`.
- `.vuelta.yaml` — generated project-local policy; `workspace.path` is always `.`.
- `local.example.yaml` — optional standalone allowlist policy for an explicit adhoc scan.
- `compose.yml` — Docker services: test, race, lint, tidy, build, and opt-in real-engine/corpus profiles.
- `scanner-images/` — embedded exact-version scanner build inputs.
- `acceptance/` — environment-gated real-engine matrix plus the pinned stable corpus manifest.
- `egress/` — local fail-closed proxy and its scratch-image Dockerfile.
- `Dockerfile` — shared dev image for the test/race/tidy/build services.
- `Makefile` — Docker-only cross-build targets for the CLI, scheduler, and Telegram bridge.
- `.golangci.yml` — lint rules.
- `.github/workflows/` — pinned reusable update workflow and central zero-edit release engine.
- `deploy/` — external scheduling, central release script, systemd deploy/bridge units, and digest-pinned gateway image.
- `scripts/update-project-map.sh` — updates this repo map generated block.

## Notable Directories

- `internal/adhoc/` — detects explicit unregistered project roots and prepares minimal private copies for container-only updates.
- `internal/capio/` — provides bounded collectors for untrusted subprocess output. Limits are enforced while the child is still streaming, so host memory stays bounded regardless of how much a process writes: Tail and Excerpt soft-truncate diagnostics, while Limit hard-stops structured output that must be parsed in full.
- `internal/config/` — strictly loads machine config and the narrow project-owned .vuelta.yaml schema. Project paths resolve relative to their config without granting project policy control over machine authority.  Validation never walks parent directories or discovers projects; the CLI resolver supplies an exact selected root or configured workspace.
- `internal/configinit/` — creates protected config containers, guards unsafe roots, deterministically detects a selected project's supported files without requiring Git, and applies atomic reviewed edits. It never walks parent directories or reads unallowlisted files.
- `internal/corpus/` — implements the offline-testable core of the manual real-world scan harness. Network access and process execution are supplied through narrow interfaces so the standard test suite never needs GitHub or Docker.
- `internal/deploy/` — discovers and executes machine-owned deployments without writing configuration into managed repositories.
- `internal/dockerexec/` — is the single process boundary for Docker CLI commands. It binds commands to one verified absolute executable and approved local Unix socket, attests daemon identity/capabilities, and runs every command with a minimal environment and bounded output collectors.
- `internal/ecosystem/` — defines immutable adapter identity, normalized data contracts, typed capability errors, and deterministic registry construction. It owns no command or container execution boundary.
- `internal/ecosystems/` — contains concrete built-in stack/package-manager adapters, structured candidate decoders, and data-only mutation policies.
- `internal/egress/` — owns the fail-closed Docker network and registry proxy used by networked scanner stages.
- `internal/egressproxy/` — implements the embedded registry-allowlisting forward proxy used by Vuelta-managed scanner networks.
- `internal/gateway/` — provides the minimal Vuelta-owned stable HTTP hop used when an existing reverse proxy already targets a fixed Docker DNS name.
- `internal/gitexec/` — is the single process boundary for production Git commands.  Security invariants:   - the executable is selected only from compiled-in absolute system paths;   - children receive a small explicit environment, never the caller's Git,     askpass, proxy, or executable-selection variables;   - system/global config, hooks, fsmonitor, credential helpers, external     diff, automatic maintenance, signing, and unsafe protocols are disabled;   - callers may run only the reviewed command set and may add only a private     absolute GIT_INDEX_FILE.  Repository data and ordinary non-executable repository configuration remain visible to Git. Callers must still validate remote names, refs, and paths at their own trust boundary before placing them in argv.
- `internal/githubactions/` — implements the narrow GitHub Actions API surface used to dispatch and inspect Vuelta update workflows.
- `internal/githubalerts/` — is a read-only client for GitHub Dependabot and Security Advisories APIs.  The client sends the configured token only to the single approved HTTPS origin derived from the validated API base URL. Pagination must stay on that origin, redirects are never followed, and response size, page count, and decoded alert count are hard-bounded.
- `internal/gitops/` — commits, pushes, and tags changes produced by an update run.
- `internal/gitpath/` — defines platform-independent matching for Git repository paths.
- `internal/history/` — owns Vuelta's machine-local durable SQLite state.  The database contains structured, bounded metadata only. Project contents, command output, environment values, credentials, and message bodies do not belong in this package. Narrow delivery IDs and cursors are persisted so an external bridge can recover idempotently without owning operation state.
- `internal/logging/` — writes local, structured operational and audit logs without accepting configuration secrets or forwarding log content to notifiers.
- `internal/pipeline/` — applies one selected workspace snapshot through preflight, sandbox, security gates, update, diff/allowlist checks, tests, commit, and push. The runner uses the hardened isolation provided by sandbox, updater, and testrunner.
- `internal/projectstate/` — resolves one exact canonical target and owns its hardened private .vuelta directories plus bounded atomic scan reports.
- `internal/repopolicy/` — TODO: describe this package.
- `internal/runlease/` — labels and reclaims Docker resources owned by one Vuelta invocation, including cleanup after abrupt parent-process termination.
- `internal/safeerr/` — builds safe, bounded, redacted diagnostic text and stable failure categories for hardened command boundaries. It only ever operates on output a boundary already captured under its own size limits; it never sees full argv, environment, or unbounded output.
- `internal/sandbox/` — prepares a one-off, cleaned working copy (no .git, no .env, no untracked files) for running updates and tests in a container. See part F of the spec for the isolation model.
- `internal/scancontainer/` — runs a scanner against an in-memory input archive. Repository contents are copied into a stopped container through Docker's stdin API; no host path is mounted and no host staging copy is created.
- `internal/scaninput/` — validates and archives only exact files declared by an ecosystem adapter or a core Docker/policy stage. It never discovers files and denies secret-like inputs unless a reviewed adapter config explicitly opts in.
- `internal/scanner/` — validates the explicitly configured project paths and determines each project's stack. It never walks parent directories or discovers projects on its own; only workspaces[] from the config are ever considered.
- `internal/scheduler/` — orchestrates the public scan and update CLI contract. It intentionally remains outside the vuelta command tree: each update receives one exact target directory and its reviewed snapshot ID.
- `internal/telegrambridge/` — presents Vuelta's bounded SQLite operation contract through one exactly authorized private Telegram chat. It owns transport delivery, update cursors, and presentation, but no operation execution.
- `internal/testfixture/` — provides deterministic, network-free project fixtures and external-service stand-ins for integration and acceptance tests.
- `internal/testrunner/` — runs a project's docker compose test service against the sandboxed working copy.
- `internal/toolchain/` — resolves declarative project constraints to an operator override or embedded scan default and builds defaults without executing project code.
- `internal/updatepolicy/` — applies Vuelta's machine-owned delayed-latest policy to normalized, non-executable dependency metadata.
- `internal/updater/` — executes adapter-provided reviewed scanner and mutation argv inside core-owned hardened containers, then applies validated dependency and Docker image plans inside a sandboxed working copy.
- `internal/updatesnapshot/` — stores short-lived, project-local read-only package update plans. A snapshot deliberately contains only metadata and candidate versions; it never stores project file contents, command output, or configuration secrets.
- `internal/verificationprep/` — materializes only lockfile-bound package dependencies needed by an approved verification command. Preparation runs in the snapshot-selected toolchain container with managed registry egress; the later verification container remains offline.
- `internal/vulnscan/` — TODO: describe this package.
<!-- generated:end -->

<!-- manual:start -->
## Architecture Notes

- Vuelta core is a one-shot CLI with external scheduling. The optional
  `vuelta-telegram-bridge` is a separate resident SQLite/Telegram interface
  with no operation execution or Docker/GitHub authority.
- The normal top-level `scan` → `update PROJECT` workflow records durable
  history in machine-owned SQLite and dispatches one exact GitHub Actions run;
  it never mutates the server checkout. The separately named `update local`
  compatibility path retains format-7 project snapshots and container-only
  mutation.
- `update local`'s trusted baseline is the exact clean local HEAD captured at
  scan time (`scanner.IdentityForSnapshotWithOptions`, bound into
  `Snapshot.Workspace.BaseRevision`) and revalidated immediately before
  execution (`updatesnapshot.ValidateForWorkspace`, then
  `gitops.VerifyLocalBaseUnchanged` right before commit). It never fetches or
  compares against a remote-tracking ref, so a clean local HEAD ahead of
  `origin` runs without first being pushed. `internal/gitops.Push` is the only
  step that still touches the configured remote/branch.
- Registered scan containers never mount a live repository. `internal/scaninput` builds an exact tracked allowlist in memory, while `internal/scancontainer` transfers it through a stopped loader into an ephemeral image and starts only the separately hardened read-only scanner container.
- Package ecosystem behavior is selected through one explicit built-in catalog; core orchestration has no manager-name registry tables or switches.
- Verification dependency ownership is split deliberately: `pipeline` decides
  when preparation runs, `verificationprep` enforces the input and container
  boundary, adapters supply frozen install argv, and `testrunner` remains an
  offline executor. The preparer reuses the snapshot-selected toolchain and
  egress policy, rejects unbound/local workspace inputs, always disables
  lifecycle scripts, and proves admitted package inputs stayed unchanged.
- `deploy/` contains scheduler units, the central release engine, and the
  machine-owned gateway image. Managed projects do not receive Vuelta files.

## Conventions

- `internal/config` never auto-discovers projects. The CLI onboarding resolver checks only the exact selected root and passes a resolved workspace into config validation.
- New workspaces persist stable names and project-scoped changed-path allowlists; unnamed legacy workspaces use a warning-only basename fallback without automatic rewrites.
- Go module dependencies are managed only via `docker compose run --rm tidy`, never a host-installed `go`.

## Known Sharp Edges

- Package scanner defaults are embedded and built locally on demand; `update.toolchain_profiles` is only an explicit digest-pinned operator override.
- Container scans lazily build the embedded egress proxy, verify its exact local image identity, and manage only labeled Vuelta-owned network/container resources; no source checkout or Compose startup is required.
- `.golangci.yml` targets golangci-lint v2's config schema (`version: "2"`), matching the tag-and-digest-pinned `golangci/golangci-lint:v2.12.2-alpine` image in `compose.yml`; refresh its multi-platform index digest with the controlled process in `README.md`.
- `configinit.IsTerminal` classifies stdin as interactive whenever it is a character device, which also matches `/dev/null`; unattended invocations without an explicit `--no-input` are misclassified as interactive (no hang, but the wrong error shape). See `../docs/product/architecture/stack-resolution.md`.
<!-- manual:end -->
