# vuelta-app — Codex Instructions

This repo belongs to workspace `dev/vuelta`. Product docs, backlog, and task flow live in `../docs/`, `../AGENTS.md`, and `../CLAUDE.md`. This file contains only repo-local rules.

## Source Of Truth

- Workspace `../AGENTS.md` and `../CLAUDE.md`: shared rules and multi-repo task flow.
- Workspace `../docs/folder-rules.md`: docs and task rules.
- Local `PROJECT_MAP.md`: repo structure, entrypoints, commands, configs.
- This file: repo-local architecture, tests, lint, dependency rules.

Do not scan the whole repo when `PROJECT_MAP.md` gives a clear entrypoint.

## Project Map Contract

`PROJECT_MAP.md` is the source of truth for this repo internals. Workspace `../PROJECT_MAP.md` only aggregates repo maps.

Repo-local map should include:

- entrypoints;
- key directories;
- configs;
- Docker services;
- package/build/test scripts;
- API/routes/jobs/models when relevant;
- `scripts/update-project-map.sh`.

Use protected blocks:

```markdown
<!-- generated:start -->
... generated facts ...
<!-- generated:end -->

<!-- manual:start -->
... short notes ...
<!-- manual:end -->
```

Scripts may edit only the `generated` block. Long architecture decisions live in `../docs/product/architecture/`.

`scripts/update-project-map.sh` is repo-specific. It updates only this repo's `PROJECT_MAP.md`. If not implemented, keep an explicit TODO stub.

## `/start-task` And `/complete-task`

Use the full algorithm in workspace `../AGENTS.md`.

## Architecture Rules

- Language: Go. One package per pipeline stage under `internal/`; `cmd/vuelta` stays a thin entrypoint.
- The CLI is one-shot, no daemon; scheduling is external.
- Registered workspaces are container-only: package managers (`poetry`/`uv`/`npm`/`pnpm`/`bun`) run inside sandboxed containers, never on the host.
- The only host package-manager exception is an explicit format-2 adhoc snapshot created by `scan --directory PATH` and applied with `update --execution local SNAPSHOT_ID`. That path runs the resolved system manager in a private writable copy, disables project tests, rejects every change outside the recognized manifest/lock pair, and atomically copies back only those files after confirmation. There is no automatic local fallback.

## Testing

```bash
docker compose run --rm test   # go test ./...
```

## Code Quality

```bash
docker compose run --rm lint   # golangci-lint run
```

## Dependencies

Use current stable dependency versions. When adding or updating a dependency:

1. Check the current version on the official registry.
2. Set the lower bound to the current version, e.g. `>=X.Y.Z`.
3. Check compatibility between framework/plugins/ORM/adapters.
4. For major upgrades, review breaking changes first.

Go modules are managed only via `docker compose run --rm tidy` (`go mod tidy`), never a host-installed `go`.

## Security

Full policy: workspace `../AGENTS.md` → Security. Repo-local baseline:

- Never hardcode secrets in code, configs, or compose files; new env variables go to `.env.example` with placeholder values.
- Never print or log secret values (`echo $SECRET`, `env`, `docker compose config` without `--quiet`).
- Validate external input at boundaries; use parameterized queries; never interpolate user data into shell commands or HTML.
- Containers: no `privileged: true`, no host network, publish only required ports, prefer non-root users.

- `internal/config` never auto-discovers projects: only `workspaces[].path` from config is scanned, never parent directories.
- Autofix (`internal/autofix`) never gets shell/`Bash` tool access — test logs/diffs are untrusted input (part C of the spec).

## Local Permissions

- Do not read `.env` or `.env.*`.
- Do not read private key material: `.ssh/`, `id_rsa*`, `*.pem`, `*.key`.
- `.env.example` may be read and edited.
- Never run `rm -rf`, `git push --force`, `git reset --hard`, `chmod 777`, `sudo rm`, or `curl/wget ... | bash`.
- Use Docker for local verification.
- After Docker builds, clean only dangling layers when needed:
  `docker image prune -f --filter "dangling=true"`.
- Do not run `docker system prune -a`, `docker volume prune`, or remove named volumes unless explicitly requested.
