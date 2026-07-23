# vuelta

A one-shot CLI that creates reviewable dependency-update snapshots, applies
one explicitly selected snapshot inside a sandbox, runs the project's checks,
and can queue an immutable deploy task. It has no resident daemon. Optional
launchd/systemd automation invokes the separate `vuelta-scheduler` helper,
which uses the same JSON `scan` → `update` workflow as a human operator.

Node and Python scans resolve adaptive defaults from declarative runtime,
manager, lock, and platform metadata. Scanner Dockerfiles are embedded in the
binary, built locally on first use, and cached by content hash; an explicit
`update.toolchain_profiles` entry is only an operator override. Snapshot format
6 records the profile source, local image identity, runtime and tool versions,
platform, non-root user, lock support, and security capabilities. See
`scanner-images/` and the real-engine section of `../docs/runbook-local.md`.

## Stack

- Language: Go. Static `vuelta` and optional `vuelta-scheduler` binaries; no
  language runtime is required on target machines.
- Supported targets are Darwin and Linux. Windows is not a build target because
  config-file ownership and no-symlink checks use Unix filesystem semantics.
- Runtime dependencies (not vendored, must exist in the environment): `git`
  and `docker`/`docker compose`. Trivy and OSV-Scanner always run from
  configured digest-pinned containers, never from the host PATH.
- Package managers (`poetry`/`uv`/`pip-tools`, `npm`/`pnpm`) run only inside
  Docker containers, never on the host — their install scripts execute
  arbitrary code and must stay isolated.
- A root `requirements.txt` without `requirements.in` is detected as the
  distinct `python/requirements` profile. Its container only parses exact
  pins and requests bounded PyPI metadata; it never invokes pip or project
  code and cannot produce an update snapshot.

## Layout

```text
cmd/vuelta/       # main.go, CLI entrypoint
cmd/vuelta-scheduler/ # external JSON orchestration helper
internal/
  config/         # config.yaml parsing and validation
  scanner/        # validates only explicitly configured project paths, detects stack
  updater/        # read-only candidate scan and per-stack updates (python/js/docker)
  updatesnapshot/ # atomic, short-lived package-update plans
  vulnscan/       # trivy/osv-scanner integration
  githubalerts/   # read-only GitHub Dependabot/Security Advisories client
  sandbox/        # one-off sandboxed working copy for update/test
  testrunner/     # runs docker compose test
  autofix/        # optional claude -p invocation on test failure
  gitops/         # commit, push, tags
  tasks/          # deploy task creation/reading
  notify/         # webhook/telegram notifications
  scheduler/      # scan/update JSON orchestration and aggregate policy
deploy/           # launchd/systemd scheduler examples
config.example.yaml
```

## Configuration

Copy `config.example.yaml` to `~/.config/vuelta/config.yaml` and set its
permissions to `0600`. The config must be a regular, non-symlink file owned by
the process uid; loading fails closed if these checks do not pass. Webhook URLs
and Telegram bot tokens are never stored in YAML: the config refers only to the
fixed `VUELTA_NOTIFY_WEBHOOK_URL` and `VUELTA_NOTIFY_TELEGRAM_BOT_TOKEN`
environment variables, which are resolved only when a notification is sent.
See the file for the full schema:
notification targets, vulnerability scan settings, GitHub advisories,
optional package-scanner overrides, autofix, deploy task mode, the list of
`workspaces` to manage, and the git allowlist that gates which files an
update is allowed to touch.

`vuelta` never scans parent directories or auto-discovers projects: only
paths listed under `workspaces[]` are ever touched.

## Runner isolation

Every Docker child is bound to the reviewed local Unix socket with an explicit
`--host unix:///absolute/path`; Docker context discovery and inherited
`DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`, TLS, proxy, and credential
helper settings are never authority. Before the first caller command, Vuelta
checks the socket type, ownership, and permissions, then attests the daemon ID,
exact server version, OS/architecture, minimum API version, and required
security options. A mismatch fails closed before a scanner, updater, test, or
deploy command runs.

Configure development under `docker.developer`. Linux Docker Engine normally
uses `/var/run/docker.sock`; Docker Desktop on macOS normally uses the
per-user `/Users/YOU/.docker/run/docker.sock`. Do not create a system-wide
socket symlink. Bootstrap the endpoint through Vuelta so the exact non-secret
identity is displayed for review and atomically written to the protected
config without reading ambient Docker configuration or credential helpers:

```bash
vuelta environment bootstrap --socket /absolute/path/to/docker.sock
```

For automation, both authority-bearing flags are mandatory:

```bash
vuelta --no-input environment bootstrap \
  --socket /absolute/path/to/docker.sock --yes --json
```

The command normalizes `aarch64` to `arm64` and `x86_64` to `amd64` before
persisting and attesting image platforms. Re-review the identity after an
intentional Engine or Docker Desktop upgrade. The server-only worker uses the separate
`production_worker.docker` block; never reuse a developer socket path in a
deploy configuration.

Each update starts from `git archive <base SHA>` in a fresh `0700` directory.
Only tracked regular files are extracted; `.git`, ignored/untracked files,
`.env*`, host credentials, sockets, and symlinks do not enter the runner. The
original working tree is never mounted into an update or test container.

Before the first networked scanner stage, Vuelta builds its exact-version proxy
from source embedded in the installed binary, validates its local `sha256`
image identity, and ensures the owned internal network and hardened healthy
proxy. Scanner containers attach only to `vuelta-update-egress` and receive the
proxy through explicit `HTTP(S)_PROXY` variables; Docker's default bridge is
never a scanner fallback. Names, labels, image identity, hardening, health, and
network attachments are checked before reuse. Foreign collisions and drift
fail closed. Invocation-created resources are removed after the command;
`update.egress.persistent: true` explicitly retains verified resources. No
source checkout, Compose file, host proxy variable, or GitHub token is required
or passed to a runner.

Dependency vulnerability findings come from exactly one configured source:
Trivy, OSV-Scanner, or GitHub Dependabot. Selecting Dependabot does not scan
lock files locally and makes its GitHub API access fail closed. Image scanning
is independent: it remains Trivy-only and checks OS packages only, so language
dependencies are not reported again from an immutable image.

Vulnerability and package-candidate scanners use exact per-stage input
contracts. Registered projects contribute only tracked, non-ignored regular
manifest, lock, Docker-manifest, and policy files; source trees, `.git`,
`.env*`, credentials, symlinks, sockets, and unrelated files are never exposed.
Package-manager configuration is excluded unless `--allow-project-config` was
explicitly reviewed, and credential-bearing configuration still fails closed.

Container scans do not bind-mount the repository or create a host-readable
staging tree. Vuelta sends a bounded in-memory archive to a stopped loader,
commits an ephemeral local input image, removes the loader, and starts a
separate final container from the returned immutable image ID. The final
container is read-only, runs as fixed non-root UID 65532 with all capabilities
dropped, and never receives a Docker socket. Containers, loader, and ephemeral
image are removed with an independent bounded cleanup context. Explicit local
adhoc scanners receive the same minimal files in a same-user `0700` context
with `0600` files.

Trivy receives `--image-src registry`, so an image scan pulls only through the
allowlisted registry rather than inspecting the host Docker daemon. Each scan
uses a new tmpfs cache and refreshes its vulnerability database through the
proxy for every scan. If a scanner reports a database timestamp, it must also
satisfy `vuln_scan.database_max_age_hours`. The checked-in allowlist includes
Trivy's GHCR database endpoint and OSV's API. Add an image registry
deliberately to the egress proxy before configuring a workspace that scans
images from it.

Every `docker-compose.test.yml` selected by a workspace must use immutable
image digests and an explicit internal test network. Each service reachable by
the test service must set a non-root numeric `user`, `cap_drop: [ALL]`,
`security_opt: [no-new-privileges:true]`, and positive `cpus`, `mem_limit`,
and `pids_limit` values. `privileged`, host namespaces, devices, Docker socket
or absolute host mounts, `env_file`, inherited/interpolated environment values,
external networks, mutable image tags, configs, and secrets are rejected.

Fixtures and credentials for tests must be synthetic, concrete values declared
in that compose file or generated inside the sandbox. Do not reference a host
`.env`, developer credentials, or production secret store. To add a project,
first provision its registry allowlist in the egress-policy layer, pin all
runner/test images to digests, add the restricted compose profile, then add the
workspace path and dependency-file allowlist to `config.yaml`.

## Acceptance fixtures

Deterministic, offline fixture projects and mock boundaries live in
`testdata/fixtures/`. They never contain a nested Git repository: test setup
copies one fixture into a temporary directory and initializes a fresh Git
repository for each scenario.

- `projects/py-poetry-ok`, `node-pnpm-ok`, and `docker-app-ok` cover the
  accepted Python, Node, and digest-pinned Docker update paths.
- `projects/py-poetry-failtest`, `node-pnpm-cve`, and `docker-app-cve` cover
  a failing test, a package CVE, and a runtime/base-image CVE respectively.
- `projects/malicious-postinstall` and `projects/escape-symlink` are hostile
  inputs: they are only used to verify tracked-files-only sandboxing and path
  rejection. They must never be run against a host checkout.
- `bad-compose-*` files each isolate one prohibited Compose field and must be
  rejected before Docker is invoked.
- `mock-claude/claude` has explicit `fix` and `fail` modes; the former creates
  an untracked file deliberately so rollback behavior remains observable.

The Go test suite starts in-memory GitHub-alert and registry stand-ins; it
does not contact GitHub, a package registry, or an OCI registry. The deploy
target mock accepts only well-formed immutable candidate fields and can model
either `healthy` or `rolled_back` results. Cryptographic tag verification and
the real deployment adapter are owned by part G.

## Development

```bash
docker compose run --rm test   # go test ./...
docker compose run --rm lint   # golangci-lint run
docker compose run --rm tidy   # go mod tidy
docker compose run --rm build  # go build ./...
make build-mac                 # darwin/arm64 CLI and scheduler via Docker
make build-linux               # linux/amd64 CLI and scheduler via Docker
make build                     # both targets
```

### Development image provenance

Every service in the repository `compose.yml` that is not built locally must
use a reviewable `<repository>:<tag>@sha256:<digest>` reference. The repository
policy test parses the complete services map and rejects mutable tags, missing
images, placeholder digests, and digests that are not 64 lowercase hex
characters.

The current lint pin was resolved from the official Docker Hub repository on
2026-07-17. `golangci/golangci-lint:v2.12.2-alpine` published an OCI image
index for `linux/amd64` and `linux/arm64` with digest
`sha256:91b27804074a0bacea298707f016911e60cf0cdbc6c7bf5ccacb5f0606d18d60`.

Refresh an external development image only as a controlled image upgrade:

1. Inspect the intended tag with
   `docker buildx imagetools inspect <repository>:<tag>` and confirm the
   registry/repository, index media type, and required platforms.
2. With shell pipe failure enabled, hash
   `docker buildx imagetools inspect --raw <repository>:<tag>` using SHA-256
   and confirm it matches the reported top-level index digest.
3. Update the tag and digest together, run `docker compose run --rm test` and
   `docker compose run --rm lint`, and review the reference change in the diff.

This command is also the repeatable local verification of the fixture suite.
`docs/runbook-local.md` maps every acceptance criterion to its fixture and
notes the remaining prerequisites for a full manual end-to-end run.

## Operations

`vuelta scan`, `vuelta update`, and `vuelta config validate` use
`~/.config/vuelta/config.yaml` by default. Select another file with the global
`--config PATH` option. The normal dependency workflow is deliberately two
steps:

```bash
vuelta scan --all
vuelta update --yes SNAPSHOT_ID
```

`scan` is read-only. It reports vulnerabilities and package candidates and
creates one short-lived snapshot for each ready project. With no selector it
uses the registered project containing the current directory; use
`--project NAME`, `--directory PATH`, or explicit `--all` for another scope.
`update` accepts exactly one snapshot ID, revalidates it before environment
checks or writes, displays its plan, and requires confirmation or `--yes`.
Use `--dry-run` to run checks in a disposable copy without durable changes.

For a `requirements.txt`-only Python project, candidate discovery remains
read-only and the result is `scan_only`. JSON includes
`package_updates: {"status":"scan_only","reason":"manifest_has_no_safe_mutation_contract"}`
plus bounded per-line `diagnostics`; `snapshot_id` and the human `Next: vuelta
update ...` instruction are absent. Migrate to a reviewed Poetry, uv, or
pip-tools source/lock contract before enabling package mutation.

Snapshots are stored in `~/.config/vuelta/update-snapshots` by default (or the
absolute `update.snapshot_state_dir`). They contain only identity metadata,
the canonical stage set, exact input-manifest/content hashes, gates, and
candidate versions—never file contents, credentials, or command logs. Format-3
snapshots are invalidated when any scanned input changes; unrelated source
changes do not alter the input manifest. A missing, older-format, malformed,
expired, reconfigured, dirty, rebased, or changed-input snapshot exits with
code 3 before any package manager runs; create a fresh scan instead.

### Explicit adhoc local execution

An unregistered directory can use local package tools only through an explicit
scan and update mode. Copy `local.example.yaml` to a private policy file,
restrict `allowed_packages`, and create the snapshot without writing:

```bash
vuelta scan --directory /path/to/project --execution local \
  --policy ./vuelta-local.yaml --only packages
```

After reviewing the returned snapshot, apply exactly that snapshot:

```bash
vuelta update --execution local --yes SNAPSHOT_ID
```

Adhoc local execution never creates a commit, push, or deploy candidate and
does not run project tests. Manifests and locks must be regular root files and
exactly one supported pair must exist: npm, pnpm, Bun, Poetry, uv, or
pip-tools. Vuelta resolves the manager only from system `PATH`, rejects a
manager inside the project, supplies a minimal environment without inherited
credentials, uses a private writable copy, and never runs a shell.

Lifecycle/install scripts remain disabled unless update receives the explicit
`--allow-scripts` gate. Project manager configuration is ignored unless scan
records `--allow-project-config` in the snapshot. The final root allowlist
check is detection and recovery, not process isolation, so local execution
should be reserved for reviewed projects and policies.

Deploy candidates are created explicitly after a protected merge:

```bash
vuelta deploy enqueue --project api-service --commit <full-sha> \
  --image-digest sha256:<verified-image-digest> \
  --manifest-digest sha256:<verified-manifest-digest>
```

The digests must come from the build and security-scan stage; mutable tags and
branch names are refused. `queue_file` candidates can be inspected with
`vuelta tasks list`. The local queue is only a handoff record, not proof that
the production worker received it.

Operational records are written to `~/.local/state/vuelta/vuelta.log` with a
0700 state directory and 0600 files. A command's `--json` option controls only
its single result envelope on stdout; plans, progress, and diagnostics remain
on stderr. Do not put test logs, diffs, webhook URLs, or Telegram tokens in
notification text or audit fields.

Scheduling is external. `vuelta-scheduler` runs one `scan --all --json`,
structurally selects only `status: ready` results, and invokes one
`update --yes --json SNAPSHOT_ID` process per ready snapshot. It never parses
human output or passes result fields through a shell. `--failure-policy` is
explicitly `continue` or `stop`; `--findings-policy` is `report` or `fail`.
The continue policy preserves successful independent updates while returning
a non-zero aggregate result for partial scan or update failures. Findings-only
policy failures return 5, and cancellation returns 130.

Templates live in `deploy/`: load `com.vuelta.schedule.plist` with `launchctl`
on macOS after replacing `REPLACE_ME`, or install both binaries plus
`vuelta.service` and `vuelta.timer` on Linux. Scheduler stdout is one aggregate
JSON document; child plans and diagnostics are kept on stderr. Adjust the
example units to the intended unprivileged user, binary paths, and writable
project paths.

### Verified production deploys

`vuelta deploy worker /etc/vuelta/config.yaml` is a separate, one-shot
server worker. Its `vuelta-deploy-worker.service`/timer template runs as a
dedicated unprivileged account with a private state directory. It accepts only
Ed25519-signed queue records or GPG-signed annotated tags from a configured
bare mirror, plus a signed manifest, then pulls
`<allowlisted-repository>@sha256:<digest>`, and never uses a mutable tag,
`git pull`, source checkout, image build, SSH agent, or database migration.

Configure `production_worker` with public keys/fingerprints only; signing keys
stay in the CI/delivery system. The queue or bare mirror, manifest directory,
and state directory must be private absolute paths. Each project has a fixed Compose file/service and
health and smoke URLs; the Compose service must use `${VUELTA_IMAGE}` as its
image. Before changing the service, the worker writes its currently running
RepoDigest as the rollback target. A failed deploy, health check, smoke check,
timeout, or restart from `running` rolls that digest back and verifies health
again. Notifications contain only project, candidate ID, status, and digest.

The worker schema intentionally has no migration command. Database migrations
need a separately reviewed adapter, backup, reversibility proof, and rollback
plan; they are never part of a dependency deploy.

## Status

Implemented: configuration, update pipeline, security gates, notifications,
immutable candidate transport, and the signed-queue production worker with
durable state and automatic rollback. The build pipeline remains responsible
for producing and scanning the signed OCI artifact/manifest before delivery.
