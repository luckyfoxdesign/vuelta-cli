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
previous_report=
phase='scan'
input_index=0
retain_database_evidence() {
  local script_exit=$?
  trap - EXIT
  jq -n --arg phase "$phase" --argjson input_index "$input_index" --argjson script_exit "$script_exit" \
    '{schema_version:1,phase:$phase,input_index:$input_index,script_exit:$script_exit,invocations:[]}' \
    > "$smoke_root/db-cache-evidence.json"
  for report in "$smoke_root/docker-app-cve.json" "$smoke_root/node-pnpm-cve.json"; do
    test -s "$report" || continue
    jq -e . "$report" > /dev/null 2>&1 || continue
    jq -s '.[0] as $evidence | .[1].results[0] as $result | $evidence |
      .invocations += [{database_caches:(($result.database_caches // []) |
          map({scanner_image,cache_key,cache_status,updated_at,download_attempts})),
        status:([$result.status] | map(select(. == "clean" or . == "findings" or . == "failed" or . == "partial"))),
        error_code:([$result.error.code] | map(select(type == "string" and test("^[a-z_]{1,64}$")))),
        stages:[$result.stages[]? | {name,status} | select(
          (.name == "preflight" or .name == "vulnerability" or .name == "alerts") and
          (.status == "succeeded" or .status == "failed" or .status == "not_requested"))]}]' \
      "$smoke_root/db-cache-evidence.json" "$report" > "$smoke_root/db-cache-evidence.next"
    mv "$smoke_root/db-cache-evidence.next" "$smoke_root/db-cache-evidence.json"
  done
}
trap retain_database_evidence EXIT
for project in "$projects"/*; do
  phase='scan'
  input_index=$((input_index + 1))
  name=$(basename "$project")
  # Check tracked inputs with Git and list every entry, including untracked
  # and ignored state. Reports stay outside the scanned directory.
  (cd "$project" && find . -not -path './.git/*' -print | LC_ALL=C sort) > "$smoke_root/$name.before"
  "$binary" --no-input --config "$machine_config" scan --directory "$project" --read-only --only vulnerabilities --verbose --json --fail-on vulnerabilities --require-image-scan > "$smoke_root/$name.json" && status=0 || status=$?
  if test "$status" -ne 5; then
    jq '.results[] | {status, error, stages, image_scans, warnings, tools}' "$smoke_root/$name.json" >&2
    exit 1
  fi
  phase='input-integrity'
  (cd "$project" && find . -not -path './.git/*' -print | LC_ALL=C sort) > "$smoke_root/$name.after"
  cmp "$smoke_root/$name.before" "$smoke_root/$name.after"
  test -z "$(git -C "$project" status --porcelain --untracked-files=all --ignored)"
  phase='report-contract'
  jq -e '.schema_version == 1 and (.results | length == 1) and (.results[0].findings | length > 0) and ([.results[0].findings[].severity] | all(. == "critical" or . == "high" or . == "medium" or . == "low" or . == "unknown")) and any(.results[0].findings[]; (.fixed_versions | length) > 0)' "$smoke_root/$name.json" > /dev/null
  phase='db-observations'
  jq -e '.results[0].database_caches | length > 0 and all(.[]; .updated_at != null and (.cache_key | length) == 16)' "$smoke_root/$name.json" > /dev/null
  if test -z "$previous_report"; then
    jq -e 'all(.results[0].database_caches[];
      (.cache_status == "hit" and .download_attempts == 0) or
      ((.cache_status == "miss" or .cache_status == "refreshed") and .download_attempts > 0))' "$smoke_root/$name.json" > /dev/null
  else
    phase='db-reuse'
    jq -se '.[0].results[0].database_caches as $previous |
      all(.[1].results[0].database_caches[];
        . as $current | .cache_status == "hit" and .download_attempts == 0 and
        any($previous[]; .cache_key == $current.cache_key and .scanner_image == $current.scanner_image and .updated_at == $current.updated_at))' \
      "$previous_report" "$smoke_root/$name.json" > /dev/null
  fi
  previous_report="$smoke_root/$name.json"
done
phase='done'
