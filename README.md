# vuelta

A one-shot CLI that scans configured projects read-only, records bounded
dependency history in machine-owned SQLite, and dispatches reviewed updates to
GitHub-hosted runners. The production server never resolves lock files, runs
project tests, or builds images during the normal update path. It has no
resident daemon; launchd/systemd invokes scans and typed command consumption.

Node and Python scans resolve adaptive defaults from declarative runtime,
manager, lock, and platform metadata. Scanner Dockerfiles are embedded in the
binary, built locally on first use, and cached by content hash; an explicit
`update.toolchain_profiles` entry is only an operator override. Snapshot format
7 records the profile source, local image identity, runtime and tool versions,
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

## Local Quick Start (macOS)

From a fresh `app` checkout, build the Apple Silicon CLI in Docker, select the
local npm or Python project to inspect, and follow the four commands below:

```bash
make build-mac
VUELTA="$PWD/bin/vuelta-darwin-arm64"
PROJECT="/absolute/path/to/your/npm-or-python-project"

"$VUELTA" config init
"$VUELTA" environment bootstrap --socket "$HOME/.docker/run/docker.sock"
"$VUELTA" config validate
"$VUELTA" scan --directory "$PROJECT" --only packages
```

`make build-mac` always writes the CLI to
`bin/vuelta-darwin-arm64`; installation on `PATH` is not required. Docker
Desktop must be running. The bootstrap command displays the exact socket and
daemon identity and asks for confirmation before saving them. Each successful
onboarding command prints the next command with the selected config path and
the same invoked binary preserved.

No YAML editing, Compose startup, Docker resource inspection, or cleanup is
part of this flow. If another application already occupies the configured
egress names, Vuelta leaves those resources unchanged and uses deterministic
isolated names for its own invocation. The final scan prints one result per
project as a compact `manager / package / current / latest / status` table. A
standalone `requirements.txt` is explicitly reported as a read-only result
because it has no safe automatic mutation contract. Add `--verbose` to the
scan command only when technical stages, selected inputs, warnings, and Docker
error details are needed; `--json` remains the stable automation interface.

## Layout

```text
cmd/vuelta/       # main.go, CLI entrypoint
cmd/vuelta-scheduler/ # external JSON orchestration helper
internal/
  config/         # config.yaml parsing and validation
  scanner/        # validates only explicitly configured project paths, detects stack
  updater/        # read-only candidate scan and per-stack updates (python/js/docker)
  updatesnapshot/ # atomic, short-lived package-update plans
  updatepolicy/   # delayed-latest direct dependency policy
  history/        # machine-owned SQLite schema and repositories
  githubactions/  # narrow workflow dispatch and known-run synchronization
  vulnscan/       # trivy/osv-scanner integration
  githubalerts/   # read-only GitHub Dependabot/Security Advisories client
  sandbox/        # one-off sandboxed working copy for update/test
  testrunner/     # runs docker compose test
  gitops/         # commit, push, tags
  notify/         # deprecated compatibility package; core does not call it
  scheduler/      # scan/update JSON orchestration and aggregate policy
deploy/           # scheduler units and GitHub update workflow contract/example
config.example.yaml
```

## Configuration

For local scanning, create the protected default config with `vuelta config
init`; no manual YAML edit is required. `config.example.yaml` is the reference
for advanced server and notification settings. The config must be a regular,
non-symlink file owned by the process uid, use mode `0600`, and declare the
current top-level `schema_version`; loading fails closed if these checks do not
pass. When an interactive command finds the recognized legacy format without
`schema_version`, it offers to add the current version while preserving all
compatible settings, comments, key order, ownership, and protected mode.
Recognized retired fields are listed by name before confirmation; their values
are never printed, and ambiguous conversions fail closed. The
same reviewed operation is available explicitly as `vuelta config migrate`;
scripts use `vuelta --no-input config migrate --yes`. Explicit unsupported
versions and configs that do not validate under the current schema still fail
closed without being changed. `state.database_path` selects the protected
machine-owned SQLite database; when omitted it defaults beside the machine
config under `state/history.db`. GitHub credentials remain environment-only
through the fixed allowlisted `github_actions.token_env` reference. Legacy
`notify` references are accepted during migration, but core scan/update paths
write structured SQLite events and outbox intents and never call Telegram or
webhook APIs. See `config.example.yaml` for the full schema.

`vuelta` never scans parent directories or auto-discovers projects: only
paths listed under `workspaces[]` are ever touched.

## Runner isolation

Every Docker child is bound to the reviewed local Unix socket with an explicit
`--host unix:///absolute/path`; Docker context discovery and inherited
`DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`, TLS, proxy, and credential
helper settings are never authority. Before the first caller command, Vuelta
checks the socket type, ownership, and permissions, then attests the daemon ID,
exact server version, OS/architecture, minimum API version, and required
security options. A mismatch fails closed before a scanner, updater, or test
command runs.

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
intentional Engine or Docker Desktop upgrade.

Each update starts from `git archive <base SHA>` in a fresh `0700` directory.
Only tracked regular files are extracted; `.git`, ignored/untracked files,
`.env*`, host credentials, sockets, and symlinks do not enter the runner. The
original working tree is never mounted into an update or test container.

Before the first networked scanner stage, Vuelta builds its exact-version proxy
from source embedded in the installed binary, validates its local `sha256`
image identity, and ensures the owned internal network and hardened healthy
proxy. Scanner containers attach only to the invocation's verified internal
egress network and receive the proxy through explicit `HTTP(S)_PROXY`
variables; Docker's default bridge is never a scanner fallback. Names, labels,
image identity, hardening, health, and network attachments are checked before
reuse. Foreign name collisions are left untouched and routed to deterministic
isolated Vuelta names. Every resource actually selected for a scan must pass
the full ownership, identity, hardening, health, and attachment contract.
Invocation-created resources are removed after the command;
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

## Real-world corpus scan

The manual corpus harness runs production `vuelta scan` against exactly 20
reviewed public GitHub commits and, unless disabled, attempts up to five
non-blocking discovery cases. Only Docker Compose runs on the host. Choose an
existing absolute storage directory outside this repository; it retains
immutable source caches and timestamped reports:

```bash
scripts/corpus-scan.sh /absolute/path/to/vuelta-corpus
scripts/corpus-scan.sh /absolute/path/to/vuelta-corpus --stable-only
scripts/corpus-scan.sh /absolute/path/to/vuelta-corpus --case axios-npm-v3
scripts/corpus-scan.sh /absolute/path/to/vuelta-corpus \
  --case gperdomor-oss-pnpm-workspace --timeout 10m
scripts/corpus-scan.sh /absolute/path/to/vuelta-corpus \
  --only-failed /absolute/path/to/vuelta-corpus/runs/RUN_ID/report.json \
  --timeout 10m
```

On Docker Desktop, point the wrapper at the explicit per-user socket when it
is not available at `/var/run/docker.sock`:

```bash
VUELTA_DOCKER_SOCKET=/Users/YOU/.docker/run/docker.sock \
  scripts/corpus-scan.sh /absolute/path/to/vuelta-corpus --stable-only
```

Each run writes `runs/RUN_ID/report.json`, `report.md`, and bounded per-pass
logs. The Markdown report separates stable failures from discovery findings
and compares stable scenario/pass results with the previous completed report.
Stable source failures, contract mismatches, unexpected partials, timeouts,
and filesystem mutations make the command fail; discovery findings do not.
Before fetching a project, the harness performs one Docker/scanner preflight
so a broken engine or exhausted network pool produces one infrastructure
failure.

Each selected scenario pass has a five-minute deadline by default. Use
`--timeout DURATION` for an intentionally large diagnostic run, up to
`24h`; zero, negative, malformed, and larger values are rejected before
preflight. The override applies separately to every corpus pass. It does not
bound the whole harness and does not replace stage-level deadlines inside the
production scanner. Reports record the effective per-pass timeout, and
reproduction commands retain non-default overrides.

The storage layout is append-only:

```text
vuelta-corpus/
├── cache/          # immutable URL + commit source caches
└── runs/
    └── RUN_ID/
        ├── report.json
        ├── report.md
        └── logs/
```

To review updated pins without changing the committed stable manifest:

```bash
scripts/corpus-refresh.sh /absolute/path/to/vuelta-corpus
```

Refresh writes a validated `candidate-manifest.yaml` and `candidate.diff`
beside its reports. The full corpus and refresh workflows require GitHub,
registries, and a trusted Docker endpoint, so they remain manual; ordinary
Docker `test`, `race`, and `lint` use only offline harness fakes.

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

Inside a supported project, the primary scan flow is zero-setup:

```bash
cd /path/to/project
vuelta scan
```

The first run atomically onboards a protected, versioned `.vuelta.yaml`
containing only project policy with `workspace.path: .` and adds only the
anchored `/.vuelta/` rule to the root `.gitignore`. The scan continues, but no
snapshot is published until those versioned changes are reviewed, committed,
and a clean scan is run again. Later runs reuse both entries byte-for-byte.
`.` is always resolved relative to `.vuelta.yaml`, not the process CWD.

Machine authority remains in `~/.config/vuelta/config.yaml`: the approved
Docker endpoint and daemon identity, scanner/update defaults,
and allowlisted credential-variable names. A project-controlled
`.vuelta.yaml` cannot choose a socket, executable, credential source, or
weaken machine security policy. If Docker trust is not configured, the
project config remains saved and scan reports the existing explicit
`environment bootstrap` flow.

Global multi-project operations (`scan --all`, `scan --project`, scheduler,
and administrative commands) continue to use machine authority while each
target is onboarded and stores short-lived execution inputs in its own root.
Select a specific machine config with the global `--config PATH` option. The
normal server workflow is:

Legacy scripts that intentionally use a machine-config workspace with
`--directory` must now pass that machine config explicitly; local scan never
silently falls back to an unrelated global workspace.

```bash
vuelta scan --all --timeout 10m
vuelta status
vuelta update api
vuelta update status api
```

After onboarding, `scan` is read-only with respect to manifests and source:
it never changes manifests, lock files, or source. It reports vulnerabilities
and package candidates, atomically updates `.vuelta/last-scan.md`, and creates
one short-lived `.vuelta/snapshots/<ID>.json` plan for each ready Git project.
Gitless projects remain scannable and report
`git_update_snapshot=unavailable` with reason `git_repository_not_found`;
their findings and candidates remain visible while Git-bound snapshots and
updates are disabled. Use `--project NAME` or `--all` for global configured
workspaces, or `--directory PATH` to select an exact local root.
Each project scan has an independent four-minute deadline by default. Use
`--timeout DURATION` to override it up to one hour. With `scan --all`, every
project receives a fresh deadline and a timed-out project does not prevent
later projects from running. JSON and human output record the effective
timeout and identify `scan_timeout` plus the active stage while retaining
completed stage results. A timed-out project never publishes a ready update
snapshot; its existing snapshots remain untouched and its bounded scan report
is still written when safe.

The deadline hierarchy is: stage-specific operation deadline, then project
scan deadline, then the external corpus harness or scheduler deadline. The
shorter stage deadlines remain in force; an intentionally smaller project
override becomes the earlier backstop. Final result rendering and bounded
cleanup of Vuelta-owned containers, networks, and child processes are outside
the project deadline.
Every per-project JSON result includes `package_updates` with status
`available`, `scan_only`, or `unavailable`. Non-available states include a
stable machine-readable reason code; corpus and automation contracts match
that code exactly rather than parsing human diagnostics.
Every completed scan also writes a short transaction to the machine database:
the scan run, current dependency state, first observation and eligibility
times, and an installed-version event only when the resolved version changes.
Identical scans update `last_seen_at` without appending duplicate events. A
database write failure is reported while the current in-memory and
project-local scan report remain available.

`update PROJECT` selects the newest valid snapshot for the exact configured
project and base commit. It displays routine and deferred candidates, requires
confirmation, dispatches the allowlisted GitHub workflow, records the returned
run, and exits without changing the server checkout. Routine candidates are
direct stable patch/minor releases that passed the machine-owned 14-day
cooldown. Major and unknown changes are deferred; `--include-major` is an
explicit reviewed exception and never admits prerelease, yanked, transitive,
or unknown candidates.

The GitHub wrapper rechecks the exact commit and candidates with the same
pinned Vuelta engine, performs one package-manager resolution, validates
changed paths, runs security and repository verification gates, pushes one
review branch, and creates a pull request only after success. It has no deploy
step or production credentials. See `deploy/github-update-workflow.md`.

`status`, `history PROJECT`, and `update status [PROJECT]` read SQLite.
Status commands synchronize only already-known unfinished GitHub run IDs.
GitHub outages leave the last state visible as stale and never repeat a
dispatch.

For a `requirements.txt`-only Python project, candidate discovery remains
read-only and the result is `scan_only`. JSON includes
`package_updates: {"status":"scan_only","reason":"manifest_has_no_safe_mutation_contract"}`
plus bounded per-line `diagnostics`; `snapshot_id` and the human `Next: vuelta
update ...` instruction are absent. Migrate to a reviewed Poetry, uv, or
pip-tools source/lock contract before enabling package mutation.

Project-local operational state is:

```text
.vuelta.yaml
.vuelta/
├── last-scan.md
└── snapshots/
    └── <SNAPSHOT_ID>.json
```

`.vuelta/` and its files use 0700/0600 modes, reject symlinks and foreign
ownership, and are excluded from scan inputs and update sandboxes. Snapshots
contain only identity metadata,
the canonical stage set, exact input-manifest/content hashes, gates, and
candidate versions—never file contents, credentials, or command logs. Format-7
snapshots are invalidated when any scanned input changes; unrelated source
changes do not alter the input manifest. A missing, older-format, malformed,
expired, reconfigured, dirty, rebased, or changed-input snapshot exits with
code 3 before any package manager runs; create a fresh scan instead.

### Explicit adhoc container scans

An unregistered directory can be scanned explicitly without adding it to the
machine workspace list. Pass the machine config explicitly so local project
policy onboarding is not selected, copy `local.example.yaml` to a private
policy file, and restrict `allowed_packages`. The first invocation may add the
exact root ignore rule; review/commit it and repeat the scan before updating:

```bash
vuelta scan --directory /path/to/project \
  --policy ./vuelta-local.yaml --only packages \
  --config ~/.config/vuelta/config.yaml
```

The separately named compatibility path can still apply an exact snapshot on
a non-production workstation:

```bash
vuelta update local --directory /path/to/project --snapshot SNAPSHOT_ID --yes \
  --config ~/.config/vuelta/config.yaml
```

Adhoc execution never creates a commit or push and does not run project tests.
Manifests and locks must be regular root files and exactly one supported pair
must exist: npm, pnpm, Bun, Poetry, uv, or pip-tools. Package-manager and
scanner processes run only in hardened containers; host PATH is never used.

Lifecycle/install scripts remain disabled unless update receives the explicit
`--allow-scripts` gate. Project manager configuration is ignored unless scan
records `--allow-project-config` in the snapshot. Updates run against a
minimal private copy and atomically copy back only the recognized manifest and
lock files after the changed-path check succeeds.

Operational records are written to `~/.local/state/vuelta/vuelta.log` with a
0700 state directory and 0600 files. A command's `--json` option controls only
its single result envelope on stdout; plans, progress, and diagnostics remain
on stderr. Do not put test logs, diffs, webhook URLs, or Telegram tokens in
notification text or audit fields.

Scheduling is external. Production timers run sequential `scan --all` and may
run `commands consume` to process one typed `request_update` row. There is no
update-all command. Queue records contain a closed command type and stable
identifiers only; stale, duplicate, unknown, and non-update records never
reach execution, and no queue value is interpreted as shell text. The older
`vuelta-scheduler` helper remains a local compatibility surface and is not the
production update default.

Templates live in `deploy/`: load `com.vuelta.schedule.plist` with `launchctl`
on macOS after replacing `REPLACE_ME`, or install both binaries plus
`vuelta.service` and `vuelta.timer` on Linux. Scheduler stdout is one aggregate
JSON document; child plans and diagnostics are kept on stderr. Adjust the
example units to the intended unprivileged user, binary paths, and writable
project paths.

## Status

Implemented: configuration, read-only scanning, SQLite history/event/outbox
state, delayed-latest policy, GitHub Actions update dispatch/synchronization,
the explicit local compatibility pipeline, and security gates. Blue-green
deployment and the SQLite-backed Telegram bridge remain separate tasks.
