#!/usr/bin/env bash
# CI-only publisher. Authentication is supplied by the dedicated publishing
# job; the CLI acceptance job receives no registry credentials.
set -euo pipefail
repository=ghcr.io/luckyfoxdesign/vuelta-cli-scan-fixtures
output=${1:?output JSON required}
builder="vuelta-fixtures-${GITHUB_RUN_ID:?}"
docker buildx create --name "$builder" --driver docker-container --use
trap 'docker buildx rm "$builder" >/dev/null' EXIT
mkdir -p "$(dirname "$output")"
for fixture in vulnerable clean db-stale db-missing; do
  case "$fixture" in
    vulnerable) args=(--target application --build-arg VERSION=4.17.20 --build-arg CHECKSUM=d2aa8c6afc3c8591765785a37d1c5acae482a8eb3ab9729ed28922692454f2e2) ;;
    clean) args=(--target application --build-arg VERSION=4.18.1 --build-arg CHECKSUM=696942c2a488c9d7428e9ca5f12ccf03b52de01dcdbfe4d4751d392f0491ae16) ;;
    db-*) args=(--target database-standin --build-arg "DB_MODE=${fixture#db-}") ;;
  esac
  docker buildx build --platform linux/amd64,linux/arm64 --provenance=false \
    "${args[@]}" --tag "$repository:$fixture-${GITHUB_SHA:?}" \
    --metadata-file "$(dirname "$output")/$fixture.build.json" --push acceptance/image-fixtures
done
jq -n --arg repository "$repository" --arg source_sha "$GITHUB_SHA" \
  --slurpfile vulnerable "$(dirname "$output")/vulnerable.build.json" \
  --slurpfile clean "$(dirname "$output")/clean.build.json" \
  --slurpfile stale "$(dirname "$output")/db-stale.build.json" \
  --slurpfile missing "$(dirname "$output")/db-missing.build.json" \
  '{schema_version:1, source_sha:$source_sha,
    vulnerable:($repository+"@"+$vulnerable[0]["containerimage.digest"]),
    clean:($repository+"@"+$clean[0]["containerimage.digest"]),
    db_stale:($repository+"@"+$stale[0]["containerimage.digest"]),
    db_missing:($repository+"@"+$missing[0]["containerimage.digest"])}' > "$output"
cat "$output"
