#!/usr/bin/env bash
# Repo-local PROJECT_MAP updater for the vuelta Go module.
# Regenerates only the `generated` block in PROJECT_MAP.md: directory
# structure, commands, entrypoints, config files, notable directories.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAP="$ROOT/PROJECT_MAP.md"

entrypoints=""
for dir in "$ROOT"/cmd/*/; do
  [ -f "${dir}main.go" ] || continue
  name="$(basename "$dir")"
  entrypoints="${entrypoints}- \`cmd/${name}/main.go\` — \`${name}\` binary entrypoint.\n"
done
[ -n "$entrypoints" ] || entrypoints="- TODO: add application entrypoints.\n"

notable=""
for dir in "$ROOT"/internal/*/; do
  [ -d "$dir" ] || continue
  name="$(basename "$dir")"
	doc_files=("$dir"*.go)
	[ -f "${dir}doc.go" ] && doc_files=("${dir}doc.go")
  doc="$(awk '
    /^\/\// {
      if ($0 ~ /^\/\/ Package/) started = 1
      if (started) { line = $0; sub(/^\/\/ ?/, "", line); printf "%s ", line }
      next
    }
    { exit }
  ' "${doc_files[@]}" 2>/dev/null | sed -E "s#^Package [a-zA-Z0-9_]+ ##; s/ +\$//")"
  notable="${notable}- \`internal/${name}/\` — ${doc:-TODO: describe this package.}\n"
done
[ -n "$notable" ] || notable="- TODO: add important directories.\n"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

{
  printf '<!-- generated:start -->\n'
  printf '## Generated Structure\n\n'
  printf '```text\n'
  printf 'app/\n'
  printf '├── AGENTS.md, CLAUDE.md, PROJECT_MAP.md\n'
  printf '├── cmd/vuelta/          # vulnerability scan and fix CLI\n'
	printf '├── internal/            # ecosystem adapters, config, scanner, updater, toolchain,\n'
	printf '│                        # projectstate, remediation, vulnscan, sandbox\n'
	printf '├── acceptance/          # read-only smoke and opt-in real repair tests\n'
	printf '├── scanner-images/      # embedded exact-version scanner build inputs\n'
	printf '├── egress/              # local registry-allowlisting forward proxy\n'
	printf '├── .github/workflows/   # Linux vulnerability scan contract\n'
  printf '├── attic/               # inert historical orchestration (nested module)\n'
  printf '├── config.example.yaml, Makefile\n'
  printf '├── Dockerfile, compose.yml, .golangci.yml\n'
  printf '└── scripts/update-project-map.sh\n'
  printf '```\n\n'
  printf '## Commands\n\n'
  printf '```bash\n'
  printf 'docker compose run --rm test   # go test ./...\n'
	printf 'docker compose run --rm race   # go test -race ./...\n'
  printf 'docker compose run --rm lint   # golangci-lint run\n'
	printf 'docker compose run --rm tidy   # go mod tidy\n'
	printf 'docker compose run --rm build  # go build ./...\n'
	printf 'vuelta environment bootstrap --socket PATH # add/update one explicit trusted Docker endpoint\n'
	printf 'scripts/real-engine-acceptance.sh # manual/networked real-engine suite\n'
	printf 'make build-mac                 # Docker cross-build CLI for darwin/arm64\n'
	printf 'make build-linux               # Docker cross-build CLI for linux/amd64\n'
	printf 'make build                     # both cross-build targets\n'
  printf '```\n\n'
  printf '## Entrypoints\n\n'
  printf '%b' "$entrypoints"
  printf '\n## Config Files\n\n'
  printf -- '- `go.mod` — Go module definition.\n'
  printf -- '- `config.example.yaml` — template for `~/.config/vuelta/config.yaml`.\n'
	printf -- '- `.vuelta.yaml` — generated project-local policy; `workspace.path` is always `.`.\n'
	printf -- '- `compose.yml` — Docker services: test, race, lint, tidy, build, and opt-in real-engine profile.\n'
	printf -- '- `scanner-images/` — embedded exact-version scanner build inputs.\n'
	printf -- '- `acceptance/` — read-only smoke and environment-gated repair tests.\n'
	printf -- '- `egress/` — local fail-closed proxy and its scratch-image Dockerfile.\n'
	printf -- '- `Dockerfile` — shared dev image for the test/race/tidy/build services.\n'
	printf -- '- `Makefile` — Docker-only cross-build targets for the CLI.\n'
	printf -- '- `.golangci.yml` — lint rules.\n'
	printf -- '- `.github/workflows/` — Linux vulnerability scan/build/checksum workflow.\n'
  printf -- '- `scripts/update-project-map.sh` — updates this repo map generated block.\n'
  printf '\n## Notable Directories\n\n'
  printf '%b' "$notable"
  printf '<!-- generated:end -->\n'
} > "$tmp"

awk -v block="$tmp" '
  /<!-- generated:start -->/ { skip = 1; while ((getline line < block) > 0) print line; close(block) }
  /<!-- generated:end -->/ { skip = 0; next }
  !skip { print }
' "$MAP" > "$MAP.new"

mv "$MAP.new" "$MAP"
echo "Updated generated block in $MAP"
