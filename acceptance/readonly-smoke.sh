#!/usr/bin/env bash
# Networked acceptance only. Use a new private root and never real projects.
set -euo pipefail
binary=${1:?absolute path to vuelta required}
socket=${2:?absolute Docker socket required}
smoke_root=${VUELTA_SMOKE_ROOT:-$(mktemp -d)}
mkdir -p "$smoke_root"
machine_config="$smoke_root/config.yaml"
projects="$smoke_root/projects"
mkdir "$projects"

# Existing unit fixtures deliberately use fictitious packages/digests. Copy
# only allowlisted inputs and replace those synthetic values in these copies.
mkdir "$projects/node-pnpm-cve" "$projects/docker-app-cve"
cp testdata/fixtures/projects/node-pnpm-cve/package.json "$projects/node-pnpm-cve/package.json"
cp testdata/fixtures/projects/docker-app-cve/Dockerfile "$projects/docker-app-cve/Dockerfile"
cat > "$projects/node-pnpm-cve/package.json" <<'JSON'
{"name":"readonly-cve-smoke","packageManager":"pnpm@9.15.0","dependencies":{"lodash":"4.17.20"}}
JSON
cat > "$projects/node-pnpm-cve/pnpm-lock.yaml" <<'YAML'
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      lodash:
        specifier: 4.17.20
        version: 4.17.20
packages:
  lodash@4.17.20: {}
snapshots:
  lodash@4.17.20: {}
YAML
cat > "$projects/docker-app-cve/Dockerfile" <<'DOCKER'
FROM alpine:3.10.0
DOCKER

for project in "$projects"/*; do
  git -C "$project" init -q
  git -C "$project" add -- package.json pnpm-lock.yaml 2>/dev/null || git -C "$project" add -- Dockerfile
  git -C "$project" -c user.name=smoke -c user.email=smoke@example.invalid commit -qm 'fixture baseline'
done

"$binary" --no-input --config "$machine_config" config init --yes
"$binary" --no-input --config "$machine_config" environment bootstrap --socket "$socket" --yes
for project in "$projects"/*; do
  name=$(basename "$project")
  # Check tracked inputs with Git and list every entry, including untracked
  # and ignored state. Reports stay outside the scanned directory.
  (cd "$project" && find . -not -path './.git/*' -print | LC_ALL=C sort) > "$smoke_root/$name.before"
  "$binary" --no-input --config "$machine_config" scan --directory "$project" --read-only --only vulnerabilities --verbose --json --fail-on vulnerabilities --require-image-scan > "$smoke_root/$name.json" && status=0 || status=$?
  if test "$status" -ne 5; then
    jq '.results[] | {status, error, stages, image_scans, warnings, tools}' "$smoke_root/$name.json" >&2
    exit 1
  fi
  (cd "$project" && find . -not -path './.git/*' -print | LC_ALL=C sort) > "$smoke_root/$name.after"
  cmp "$smoke_root/$name.before" "$smoke_root/$name.after"
  test -z "$(git -C "$project" status --porcelain --untracked-files=all --ignored)"
  jq -e '.schema_version == 1 and (.results | length == 1) and (.results[0].findings | length > 0) and ([.results[0].findings[].severity] | all(. == "critical" or . == "high" or . == "medium" or . == "low" or . == "unknown")) and any(.results[0].findings[]; (.fixed_versions | length) > 0)' "$smoke_root/$name.json" > /dev/null
done
