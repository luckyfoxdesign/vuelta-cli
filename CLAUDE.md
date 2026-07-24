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

`vuelta` is a one-shot Go CLI with no resident daemon. Each exact project root
owns `.vuelta/last-scan.md` and `.vuelta/snapshots/`; `update` resolves the
target from cwd or `--directory` before selecting its newest plan, while
`--snapshot ID` pins automation to one exact project-local plan. The separate
`vuelta-scheduler` binary owns optional multi-project automation by parsing
`scan --all --json` and invoking one update with both exact directory and
snapshot ID per ready result. See
`cmd/vuelta/`, `cmd/vuelta-scheduler/`, and `internal/*`.

## Code Quality

```bash
docker compose run --rm lint
docker compose run --rm test
```

## Deploy

`vuelta` itself is a CLI binary, not a deployed service; it drives deploys of *other* projects (see part D/G of the spec). No deploy pipeline for this repo yet.
