# Vuelta

Vuelta finds known vulnerabilities in dependencies and referenced Docker images,
and repairs selected findings with `fix`. It is a one-shot Go CLI. Scheduling,
GitHub Issues, project tests, commits, push, PRs and deployment belong to its consumer.

## Build and configure

All Go tooling runs in Docker:

```sh
COMPOSE_DISABLE_ENV_FILE=1 make build
bin/vuelta-darwin-arm64 config init --no-input
bin/vuelta-darwin-arm64 environment bootstrap --socket /absolute/path/to/docker.sock --yes --no-input
```

Use `bin/vuelta-linux-amd64` and `/var/run/docker.sock` on Linux Engine.
Docker Desktop macOS normally uses `/Users/YOU/.docker/run/docker.sock`.
Bootstrap reviews and persists the exact socket plus daemon identity; Vuelta
never takes ambient Docker context as execution authority. Repeat bootstrap
for additional explicitly trusted endpoints. Use `--config PATH` consistently
when choosing a separate machine configuration. The config must be a private,
process-owned regular file. Never put token values in YAML.

## Scan

```sh
vuelta --no-input scan --directory /path/to/project --read-only --json --fail-on vulnerabilities --require-image-scan
vuelta scan --directory /path/to/project --timeout 8m
vuelta scan --all --json
```

`--read-only` neither onboards nor writes reports/configuration/state. Inputs
must be tracked, allowed manifest/lock/Docker/policy files. Untracked files and
project secrets are excluded. Ordinary scan may create `.vuelta.yaml`, add the
exact `/.vuelta/` ignore rule and save bounded reports/image drift under the
selected root. It never changes manifests, lockfiles or source.

`--only vulnerabilities` remains accepted; vulnerability scanning is the default.
`--only packages`, release-age gates, package candidate plans and snapshots are removed.
`--allow-project-config` is an explicit opt-in for reviewed manager configuration.
Choose one of `--project NAME`, `--directory PATH`, or `--all`. No parent traversal
or implicit scan of every workspace occurs. The timeout defaults to four minutes,
with a one-hour maximum; an incomplete network scan is never proof of a clean result.

JSON has `schema_version: 1` and a `findings` array for every project, including
clean and failed projects. Findings include `id`, `kind`, `package`,
`installed_version`, `fixed_versions`, `severity`, `target`, `source`; available
aliases, ecosystem, dependency ownership and image reference are included.
Severity is critical/high/medium/low/unknown. The retired string findings field
`vulnerabilities` and update candidate/snapshot fields are no longer emitted.

| Exit | Meaning |
|---|---|
| 0 | Completed without the requested failure condition |
| 1 | Operation/output failure |
| 2 | Invalid configuration or invocation |
| 4 | Environment unavailable |
| 5 | Findings with `--fail-on vulnerabilities` |
| 6 | Partial scan/repair; inspect structured errors |
| 7 | Required image scan could not resolve a digest |
| 130 | Interrupted |

Dependency sources: Trivy, OSV-Scanner or GitHub Dependabot (one selected source).
Image scans use Trivy against immutable resolved references; this covers referenced
base/runtime OS packages, not the application's built image layers. Unresolved
references remain visible skips. Dependabot token configuration accepts only fixed
environment-variable names and the approved HTTPS origin; values stay outside config.

## Repair

```sh
vuelta --no-input fix --directory /path/to/project --json
vuelta --no-input fix --directory /path/to/project --finding CVE-2022-0155 --min-severity high --json --verbose
```

Repair scans current tracked inputs, selects conservative same-major package
versions, mutates a minimal private copy in hardened non-root containers with
lifecycle scripts disabled, verifies the candidate, copies back only approved
manifest/lock or image-reference changes and rescans. No snapshot, project test
profile, commit, push or confirmation prompt is required. Use a fresh checkout
when automation intends to commit the resulting changes.

Transitive npm repairs change only the lockfile when the parent range allows it.
`needs_parent_upgrade`, `needs_major`, `no_fix`, `filtered` and
`source_requires_local_verification` explain skipped findings without granting
broader mutation authority. Image candidates stay within the supported release
line and must clear the selected finding before copyback. Other findings may remain.

npm, pnpm, Bun and Poetry have real repair acceptance evidence. Bun is supported
by `fix` and its built-in rescan; standalone Bun `scan` is unsupported. uv/pip-tools
have code coverage but remain outside the recorded real acceptance matrix.
Live Dependabot repair requires separate local-verification work. Alpine 3.10
previously produced an incomplete scan; this is not a verified no-fix outcome.

## Configuration and security

`config init`, `config validate`, `config migrate`, `project list`, `project add`
and `environment bootstrap` are the supported helpers. Toolchain defaults are
embedded and built on demand. Schema 1 retains legacy data fields for existing
configuration compatibility, including inert verification/Git/orchestration fields;
these do not execute workflows or project tests. `update.egress` and explicit
`update.toolchain_profiles` remain active repair-container settings.

The exact Docker executable/socket is attested. Scanners receive bounded in-memory
allowlisted archives rather than repository mounts. Registry access uses managed
fail-closed egress. Mutation runs in private copies without lifecycle scripts and
admits only recognized output files. Scan/fix do not execute project code on the host.

## Verification and distribution

```sh
COMPOSE_DISABLE_ENV_FILE=1 docker compose run --rm test
COMPOSE_DISABLE_ENV_FILE=1 docker compose run --rm race
COMPOSE_DISABLE_ENV_FILE=1 docker compose run --rm lint
COMPOSE_DISABLE_ENV_FILE=1 docker compose run --rm build
COMPOSE_DISABLE_ENV_FILE=1 make build
VUELTA_DOCKER_SOCKET=/absolute/path/to/docker.sock scripts/real-engine-acceptance.sh
```

Real-engine acceptance is opt-in and networked: fresh private projects, real npm,
Trivy and image candidates. The read-only fixture smoke is
`bash acceptance/readonly-smoke.sh BINARY SOCKET` (requires jq). The Ubuntu workflow
builds a Linux binary and checksum, runs read-only scan smoke, the compiled-CLI
repair smoke and the real package/image repair suite, then uploads the binary
and checksum only after every acceptance step succeeds.
Refreshing pinned images requires review of the registry's multi-platform index
digest and Docker verification; never substitute floating tags.

The only maintained binary is `vuelta`. Old update/scheduler/bridge/history commands
are removed. Historical deployment/gateway and corpus/update matrix source lives in
`attic/`, excluded from active builds by a nested module. The local `pre-vuln-focus`
tag identifies the complete tree before removal.

Architecture: [vulnerability focus](../docs/product/architecture/vulnerability-focus.md),
[trust model](../docs/product/architecture/app-boundaries-and-trust-model.md).
