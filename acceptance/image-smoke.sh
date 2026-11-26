#!/usr/bin/env bash
# Run a compiled CLI against public immutable synthetic images. jq and Docker
# are harness dependencies; the scanner itself retains managed egress.
set -euo pipefail
binary=${1:?absolute CLI path required}
socket=${2:?absolute Docker socket required}
fixtures=${3:?reviewed fixture JSON required}
root=${VUELTA_IMAGE_SMOKE_ROOT:-$(mktemp -d)}
mkdir -p "$root"
machine_config="$root/config.yaml"
repository=ghcr.io/luckyfoxdesign/vuelta-cli-scan-fixtures
export DOCKER_CONFIG="$root/empty-docker-config"
export DOCKER_HOST="unix://$socket"
mkdir "$DOCKER_CONFIG"
jq -e --arg repository "$repository" '
  .schema_version == 1 and (.source_sha | test("^[0-9a-f]{40}$")) and
  ([.vulnerable,.clean,.db_stale,.db_missing] | all(. != null and
    startswith($repository+"@sha256:") and test("@sha256:[0-9a-f]{64}$")))
' "$fixtures" >/dev/null
"$binary" --no-input --config "$machine_config" config init --yes >/dev/null
"$binary" --no-input --config "$machine_config" environment bootstrap --socket "$socket" --yes >/dev/null

snapshot() {
  for resource in container image network; do
    docker "$resource" ls -q --filter label=com.luckyfoxdesign.vuelta.lifecycle-contract=1 | LC_ALL=C sort
  done
}
snapshot > "$root/resources.before"
docker container ls -aq | LC_ALL=C sort > "$root/workloads.before"
docker volume ls -q | LC_ALL=C sort > "$root/volumes.before"

input() {
  jq -n --arg image "$1" --arg platform "$2" --arg sha "$(jq -r .source_sha "$fixtures")" \
    '{schema_version:1,artifact:{project:"synthetic-image-acceptance",sha:$sha,image:$image,platform:$platform}}'
}
check_cleanup() {
  snapshot > "$root/resources.after"
  cmp "$root/resources.before" "$root/resources.after"
  # Existing workloads and volumes must survive; new managed DB caches stay.
  docker container ls -aq | LC_ALL=C sort > "$root/workloads.after"
  docker volume ls -q | LC_ALL=C sort > "$root/volumes.after"
  test -z "$(comm -23 "$root/workloads.before" "$root/workloads.after")"
  test -z "$(comm -23 "$root/volumes.before" "$root/volumes.after")"
}
scan() {
  local name=$1 expected=$2 config=$3 timeout=${4:-10m} actual
  "$binary" --no-input --config "$config" scan image --allow-repository "$repository" \
    --allow-repository registry-1.docker.io/library/alpine --timeout "$timeout" \
    --fail-on vulnerabilities > "$root/$name.json" && actual=0 || actual=$?
  jq -n --arg case "$name" --argjson exit "$actual" '{case:$case,exit:$exit}' >> "$root/exits.jsonl"
  test "$actual" -eq "$expected"
  jq -e '.schema_version == 1 and (.status != "clean" or (.findings | length == 0))' "$root/$name.json" >/dev/null
  check_cleanup
}
complete() {
  jq -e --arg status "$2" '
    (.database_updated_at | sub("\\.[0-9]+Z$";"Z") | fromdateiso8601) as $db |
    (.scanned_at | sub("\\.[0-9]+Z$";"Z") | fromdateiso8601) as $scan |
    .status == $status and .coverage == {os:"detected",libraries:"detected"} and
    $db <= ($scan+300) and ($scan-$db) <= (.database_max_age_hours*3600)
  ' "$root/$1.json" >/dev/null
}
vulnerable=$(jq -r .vulnerable "$fixtures")
clean=$(jq -r .clean "$fixtures")
input "$vulnerable" linux/amd64 | jq --arg image "$clean" \
  '.production=(.artifact+{image:$image,observed_at:(now|todateiso8601)})' |
  scan vulnerable 5 "$machine_config"
complete vulnerable findings
jq -e --arg image "$vulnerable" --arg clean "$clean" '
  .production_comparison == "different" and .production.image == $clean and
  .artifact.image == $image and .artifact.platform == "linux/amd64" and
  any(.findings[]; .package == "lodash" and .installed_version == "4.17.20" and
    .image == $image and .kind == "image" and (.target | length > 0))
' "$root/vulnerable.json" >/dev/null
input "$clean" linux/amd64 | jq '.production=(.artifact+{observed_at:(now|todateiso8601)})' |
  scan clean 0 "$machine_config"
complete clean clean
jq -e '.production_comparison == "matches_export" and .findings == [] and
  .production.image == .artifact.image and .production.sha == .artifact.sha' "$root/clean.json" >/dev/null
input "$clean" linux/arm64 | scan arm64-image 0 "$machine_config"
complete arm64-image clean
jq -e '.artifact.platform == "linux/arm64"' "$root/arm64-image.json" >/dev/null

# This is a scan of arm64 contents, not execution of an arm64 CLI/Engine.
amd64=$(docker buildx imagetools inspect "$clean" --raw | jq -er '.manifests[] | select(.platform.architecture=="amd64") | .digest')
input "$repository@$amd64" linux/arm64 | scan wrong-platform 6 "$machine_config"
jq -e '.status == "failed" or .status == "partial"' "$root/wrong-platform.json" >/dev/null
input "$repository@sha256:$(printf '%064d' 0)" linux/amd64 | scan unavailable 6 "$machine_config"
jq -e '.status == "failed" and .error == "image_scan_failed"' "$root/unavailable.json" >/dev/null
input registry-1.docker.io/library/alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf linux/amd64 |
  scan os-only 6 "$machine_config"
jq -e '.status == "partial" and .coverage.os == "detected" and
  .coverage.libraries == "missing_metadata"' "$root/os-only.json" >/dev/null
for mode in stale missing; do
  scanner=$(jq -r ".db_$mode" "$fixtures")
  awk -v scanner="$scanner" '
    $1 == "image_scan:" { image_scan=1 }
    image_scan && $1 == "image:" {
      sub(/image:.*/, "image: \"" scanner "\""); image_scan=0; updated=1
    }
    { print }
    END { if (!updated) exit 1 }
  ' "$machine_config" > "$root/db-$mode-config.yaml"
  chmod 600 "$root/db-$mode-config.yaml"
  input "$clean" linux/amd64 | scan "db-$mode-standin" 6 "$root/db-$mode-config.yaml"
  jq -e --arg scanner "$scanner" '.status == "failed" and .error == "database_unavailable" and .scanner_image == $scanner and
    (has("database_updated_at") | not)' "$root/db-$mode-standin.json" >/dev/null
done
input "$clean" linux/amd64 | scan timeout 6 "$root/db-missing-config.yaml" 5s &
timeout_pid=$!
observed=false
while kill -0 "$timeout_pid" 2>/dev/null; do
  if test -n "$(docker container ls -q --filter label=com.luckyfoxdesign.vuelta.resource=scanner-final)"; then
    observed=true
    break
  fi
  sleep 0.1
done
wait "$timeout_pid"
test "$observed" = true
jq -n '{case:"timeout",active_scanner_observed:true}' > "$root/timeout-observation.json"
jq -e '.status == "failed"' "$root/timeout.json" >/dev/null
printf '%s\n' '{"schema_version":2}' | scan invalid-input 2 "$machine_config"
jq -e '.status == "failed" and .error == "invalid_image_input"' "$root/invalid-input.json" >/dev/null
printf '%s\n' 'Live registry and separately labelled database stand-in cases passed; cleanup verified.'
