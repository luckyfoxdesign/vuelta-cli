# vuelta-app

Part of workspace `dev/vuelta`. Product docs, backlog, and shared commands live in `../docs/`, `../AGENTS.md`, `../CLAUDE.md`, and `../.claude/commands/`.

This file is repo-local context only.

## Project Map

`PROJECT_MAP.md` indexes repo structure: entrypoints, key directories, configs, Docker services, package/build/test scripts, API/routes/jobs/models when relevant.

Read it before scanning the repo.

Protected blocks:

- `generated`: facts that scripts may rewrite;
- `manual`: short repo-local notes, conventions, sharp edges.

Long architecture decisions live in `../docs/product/architecture/`.

Update the map with `scripts/update-project-map.sh`. The script is repo-specific and updates only the generated block.

## Docker

Use Docker for all runtime, test, lint, and dependency work. Git runs locally.

- Config file: `compose.yml`.
- Use `docker compose run --rm <service>` or `docker compose up`.
- Do not use local venv, local pip, or local interpreters.
- After Docker builds, clean only dangling layers when needed:
  `docker image prune -f --filter "dangling=true"`.
- Do not run `docker system prune -a`, `docker volume prune`, or remove named volumes unless explicitly requested.

## Architecture

`vuelta` is a one-shot vulnerability CLI: `scan` and `fix` plus config,
project and Docker environment helpers. `scan --read-only` uses tracked
allowlisted inputs without project writes. `fix` verifies candidates in private
container-mutated copies and returns only admitted manifest/lock or image edits.
Ordinary scans may onboard the exact root and save bounded reports.
Historical deploy/gateway and corpus/update harness code is inert in `attic/`.
See `../docs/product/architecture/vulnerability-focus.md`.

## Code Quality

```bash
docker compose run --rm lint
docker compose run --rm test
```

## Distribution

`make build` cross-compiles only the CLI for darwin/arm64 and linux/amd64.
`.github/workflows/vulnerability-scan.yml` builds/checksums the Linux binary
and checks read-only scans on isolated fixtures. Publishing is a separate task.
