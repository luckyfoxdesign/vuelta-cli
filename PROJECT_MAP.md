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
├── cmd/vuelta/          # vulnerability scan and fix CLI
├── internal/            # ecosystem adapters, config, scanner, updater, toolchain,
│                        # projectstate, remediation, vulnscan, sandbox
├── acceptance/          # read-only smoke and opt-in real repair tests
├── scanner-images/      # embedded exact-version scanner build inputs
├── egress/              # local registry-allowlisting forward proxy
├── .github/workflows/   # Linux vulnerability scan contract
├── attic/               # inert historical orchestration (nested module)
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
vuelta environment bootstrap --socket PATH # add/update one explicit trusted Docker endpoint
scripts/real-engine-acceptance.sh # manual/networked real-engine suite
make build-mac                 # Docker cross-build CLI for darwin/arm64
make build-linux               # Docker cross-build CLI for linux/amd64
make build                     # both cross-build targets
```

## Entrypoints

- `cmd/vuelta/main.go` — `vuelta` binary entrypoint.

## Config Files

- `go.mod` — Go module definition.
- `config.example.yaml` — template for `~/.config/vuelta/config.yaml`.
- `.vuelta.yaml` — generated project-local policy; `workspace.path` is always `.`.
- `compose.yml` — Docker services: test, race, lint, tidy, build, and opt-in real-engine profile.
- `scanner-images/` — embedded exact-version scanner build inputs.
- `acceptance/` — read-only smoke and environment-gated repair tests.
- `egress/` — local fail-closed proxy and its scratch-image Dockerfile.
- `Dockerfile` — shared dev image for the test/race/tidy/build services.
- `Makefile` — Docker-only cross-build targets for the CLI.
- `.golangci.yml` — lint rules.
- `.github/workflows/` — Linux vulnerability scan/build/checksum workflow.
- `scripts/update-project-map.sh` — updates this repo map generated block.

## Notable Directories

- `internal/adhoc/` — detects explicit unregistered project roots and prepares minimal private copies for container-only updates.
- `internal/capio/` — provides bounded collectors for untrusted subprocess output. Limits are enforced while the child is still streaming, so host memory stays bounded regardless of how much a process writes: Tail and Excerpt soft-truncate diagnostics, while Limit hard-stops structured output that must be parsed in full.
- `internal/config/` — strictly loads machine config and the narrow project-owned .vuelta.yaml schema. Project paths resolve relative to their config without granting project policy control over machine authority.  Validation never walks parent directories or discovers projects; the CLI resolver supplies an exact selected root or configured workspace.
- `internal/configinit/` — creates protected config containers, guards unsafe roots, deterministically detects a selected project's supported files without requiring Git, and applies atomic reviewed edits. It never walks parent directories or reads unallowlisted files.
- `internal/dockerexec/` — is the single process boundary for Docker CLI commands. It binds commands to one verified absolute executable and approved local Unix socket, attests daemon identity/capabilities, and runs every command with a minimal environment and bounded output collectors.
- `internal/ecosystem/` — defines immutable adapter identity, normalized data contracts, typed capability errors, and deterministic registry construction. It owns no command or container execution boundary.
- `internal/ecosystems/` — contains concrete built-in stack/package-manager adapters, structured candidate decoders, and data-only mutation policies.
- `internal/egress/` — owns the fail-closed Docker network and registry proxy used by networked scanner stages.
- `internal/egressproxy/` — implements the embedded registry-allowlisting forward proxy used by Vuelta-managed scanner networks.
- `internal/gitexec/` — is the single process boundary for production Git commands.  Security invariants:   - the executable is selected only from compiled-in absolute system paths;   - children receive a small explicit environment, never the caller's Git,     askpass, proxy, or executable-selection variables;   - system/global config, hooks, fsmonitor, credential helpers, external     diff, automatic maintenance, signing, and unsafe protocols are disabled;   - callers may run only the reviewed command set and may add only a private     absolute GIT_INDEX_FILE.  Repository data and ordinary non-executable repository configuration remain visible to Git. Callers must still validate remote names, refs, and paths at their own trust boundary before placing them in argv.
- `internal/githubalerts/` — is a read-only client for GitHub Dependabot and Security Advisories APIs.  The client sends the configured token only to the single approved HTTPS origin derived from the validated API base URL. Pagination must stay on that origin, redirects are never followed, and response size, page count, and decoded alert count are hard-bounded.
- `internal/gitpath/` — defines platform-independent matching for Git repository paths.
- `internal/logging/` — writes local, structured operational and audit logs without accepting configuration secrets or forwarding log content to notifiers.
- `internal/projectstate/` — resolves one exact canonical target and owns its hardened private .vuelta directories plus bounded atomic scan reports.
- `internal/remediation/` — repairs vulnerability findings through reviewed adapter commands in minimal private copies. It owns no commits, pushes or project tests.
- `internal/runlease/` — labels and reclaims Docker resources owned by one Vuelta invocation, including cleanup after abrupt parent-process termination.
- `internal/safeerr/` — builds safe, bounded, redacted diagnostic text and stable failure categories for hardened command boundaries. It only ever operates on output a boundary already captured under its own size limits; it never sees full argv, environment, or unbounded output.
- `internal/sandbox/` — prepares a one-off, cleaned working copy (no .git, no .env, no untracked files) for running updates and tests in a container. See part F of the spec for the isolation model.
- `internal/scancontainer/` — runs a scanner against an in-memory input archive. Repository contents are copied into a stopped container through Docker's stdin API; no host path is mounted and no host staging copy is created.
- `internal/scaninput/` — validates and archives only exact files declared by an ecosystem adapter or a core Docker/policy stage. It never discovers files and denies secret-like inputs unless a reviewed adapter config explicitly opts in.
- `internal/scanner/` — validates the explicitly configured project paths and determines each project's stack. It never walks parent directories or discovers projects on its own; only workspaces[] from the config are ever considered.
- `internal/testfixture/` — provides deterministic, network-free project fixtures and external-service stand-ins for integration and acceptance tests.
- `internal/toolchain/` — resolves declarative project constraints to an operator override or embedded scan default and builds defaults without executing project code.
- `internal/updater/` — provides hardened container execution and immutable image resolution for vulnerability repair. Candidate selection and copyback belong to remediation and adhoc.
- `internal/vulnscan/` — TODO: describe this package.
<!-- generated:end -->

<!-- manual:start -->
## Architecture Notes

- Vuelta is a one-shot vulnerability CLI: scan and fix, with config/project/environment helpers.
- `scan --read-only` accepts tracked allowlisted inputs and writes no project config or state. JSON uses `schema_version: 1` and structured `findings`.
- `scan image` accepts versioned digest/platform metadata on stdin and exact repository allowlists; scans full OS/library inventories with explicit partial coverage and production-export comparison. Contract: `../docs/product/architecture/image-digest-scanning.md`.
- Ordinary scan may onboard the exact root and save bounded reports/image drift. There are no update plans, SQLite history, scheduler, bridge, commits, push, or deployment commands.
- `fix` scans, selects conservative candidates, mutates a private copy in containers with scripts disabled, verifies candidates and copies back only manifest/lock files or image references.
- Docker endpoint attestation, managed allowlisted registry egress, bounded subprocess output, and tracked scan inputs remain core boundaries.
- `attic/go.mod` excludes archived deploy/gateway and corpus/update acceptance code from active `./...` builds/tests. Recover the complete historical implementation from `pre-vuln-focus`.
- The schema-1 config retains legacy data structures for parsing existing configs; verification profiles never execute. `update.toolchain_profiles` and `update.egress` still configure repair containers.

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
