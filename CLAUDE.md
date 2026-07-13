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

`vuelta` is a one-shot CLI (Go), no resident daemon; external scheduler (launchd/systemd timer) triggers `vuelta run`. See `cmd/vuelta/` (entrypoint) and `internal/*` (one package per pipeline stage: config, scanner, updater, vulnscan, githubalerts, sandbox, testrunner, autofix, gitops, tasks, notify). Full spec: `../docs/done/short/13-07-26-app-init-a-core.md` once the task is complete, or `../docs/wip/13-07-26-app-init-a-core.md` while active.

## Code Quality

```bash
docker compose run --rm lint
docker compose run --rm test
```

## Deploy

`vuelta` itself is a CLI binary, not a deployed service; it drives deploys of *other* projects (see part D/G of the spec). No deploy pipeline for this repo yet.
