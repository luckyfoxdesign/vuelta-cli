#!/bin/sh
set -eu

die() {
  printf '%s\n' "$1" >&2
  exit 2
}

safe_relative() {
  value=$1
  case "$value" in
    ""|/*|..|../*|*/../*|*//*|*[!A-Za-z0-9_./-]*) return 1 ;;
  esac
}

validate_identity() {
  case "${REQUEST_ID:-}" in
    ""|*[!A-Za-z0-9_-]*) die "invalid request ID" ;;
  esac
  test "${#REQUEST_ID}" -eq 22 || die "invalid request ID length"
  test "${CONTRACT_VERSION:-}" = "1" || die "unsupported contract version"
  case "${SOURCE_REPOSITORY:-}" in
    */*) source_owner=${SOURCE_REPOSITORY%/*}; source_name=${SOURCE_REPOSITORY#*/} ;;
    *) die "invalid source repository" ;;
  esac
  case "$source_owner" in ""|*..*|*[!A-Za-z0-9_.-]*) die "invalid source repository owner" ;; esac
  case "$source_name" in ""|*..*|*[!A-Za-z0-9_.-]*) die "invalid source repository name" ;; esac
  case "${SOURCE_COMMIT:-}" in
    ""|*[!0-9a-f]*) die "invalid source commit" ;;
  esac
  test "${#SOURCE_COMMIT}" -eq 40 || die "invalid source commit length"
  case "${IMAGE_REPOSITORY:-}" in
    ghcr.io/*/*) ;;
    *) die "image repository must be on GHCR" ;;
  esac
  case "$IMAGE_REPOSITORY" in
    *..*|*[!a-z0-9._/-]*) die "invalid image repository" ;;
  esac
  safe_relative "${BUILD_CONTEXT:-}" || die "invalid build context"
  safe_relative "${DOCKERFILE:-}" || die "invalid Dockerfile"
  case "${BUILD_TARGET:-}" in
    *[!A-Za-z0-9_.-]*) die "invalid build target" ;;
  esac
}

validate_source_identity() {
  case "${SOURCE_REPOSITORY:-}" in
    */*) source_owner=${SOURCE_REPOSITORY%/*}; source_name=${SOURCE_REPOSITORY#*/} ;;
    *) die "invalid source repository" ;;
  esac
  case "$source_owner" in ""|*..*|*[!A-Za-z0-9_.-]*) die "invalid source repository owner" ;; esac
  case "$source_name" in ""|*..*|*[!A-Za-z0-9_.-]*) die "invalid source repository name" ;; esac
  case "${SOURCE_COMMIT:-}" in
    ""|*[!0-9a-f]*) die "invalid source commit" ;;
  esac
  test "${#SOURCE_COMMIT}" -eq 40 || die "invalid source commit length"
}

verify_source_checks() {
  validate_source_identity
  checks_file="$(mktemp)"
  trap 'rm -f "$checks_file"' EXIT HUP INT TERM
  attempt=0
  while test "$attempt" -lt 120; do
    GH_TOKEN="${SOURCE_READ_TOKEN:?missing source read token}" \
      gh api \
        -H "Accept: application/vnd.github+json" \
        "/repos/$SOURCE_REPOSITORY/commits/$SOURCE_COMMIT/check-runs?filter=latest&per_page=100" \
        > "$checks_file"
    total="$(jq -r '.total_count' "$checks_file")"
    returned="$(jq -r '.check_runs | length' "$checks_file")"
    incomplete="$(jq -r '[.check_runs[] | select(.status != "completed")] | length' "$checks_file")"
    failed="$(jq -r '[.check_runs[] | select(
      .status == "completed" and
      (.conclusion != "success" and .conclusion != "neutral" and .conclusion != "skipped")
    )] | length' "$checks_file")"
    case "$total:$returned:$incomplete:$failed" in
      *[!0-9:]*|:*|*::*|*:) die "source check response is invalid" ;;
    esac
    test "$returned" -eq "$total" || die "source commit has too many checks for the bounded release contract"
    test "$failed" -eq 0 || die "source commit has unsuccessful CI checks"
    if test "$total" -gt 0 && test "$incomplete" -eq 0; then
      return
    fi
    attempt=$((attempt + 1))
    test "$attempt" -lt 120 || break
    sleep 15
  done
  die "source commit CI checks did not complete before the bounded release deadline"
}

build_release() {
  project_root=$1
  archive=$2
  validate_identity
  test -d "$project_root/.git" || die "source checkout is missing"
  test "$(git -C "$project_root" rev-parse HEAD)" = "$SOURCE_COMMIT" || die "source commit mismatch"
  test -z "$(git -C "$project_root" status --porcelain=v1)" || die "source checkout is dirty"

  image="$IMAGE_REPOSITORY:$SOURCE_COMMIT"
  set -- docker buildx build \
    --file "$project_root/$DOCKERFILE" \
    --label "org.opencontainers.image.source=https://github.com/$SOURCE_REPOSITORY" \
    --label "org.opencontainers.image.revision=$SOURCE_COMMIT" \
    --tag "$image" \
    --output "type=docker,dest=$archive"
  if test -n "${BUILD_TARGET:-}"; then
    set -- "$@" --target "$BUILD_TARGET"
  fi
  set -- "$@" "$project_root/$BUILD_CONTEXT"
  "$@"
}

publish_release() {
  archive=$1
  case "${SOURCE_COMMIT:-}" in
    ""|*[!0-9a-f]*) die "invalid source commit" ;;
  esac
  test "${#SOURCE_COMMIT}" -eq 40 || die "invalid source commit length"
  case "${IMAGE_REPOSITORY:-}" in
    ghcr.io/*/*) ;;
    *) die "image repository must be on GHCR" ;;
  esac
  test -f "$archive" || die "release archive is missing"
  printf '%s' "${GHCR_TOKEN:?missing GHCR token}" | docker login ghcr.io --username "${GHCR_USER:?missing GHCR user}" --password-stdin
  docker load --input "$archive"
  docker push "$IMAGE_REPOSITORY:$SOURCE_COMMIT"
  docker logout ghcr.io
}

case "${1:-}" in
  verify)
    test "$#" -eq 1 || die "verify accepts no positional arguments"
    verify_source_checks
    ;;
  build)
    test "$#" -eq 3 || die "build requires source root and archive"
    build_release "$2" "$3"
    ;;
  publish)
    test "$#" -eq 2 || die "publish requires archive"
    publish_release "$2"
    ;;
  *)
    die "expected verify, build, or publish"
    ;;
esac
