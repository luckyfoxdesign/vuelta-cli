#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
  echo "usage: VUELTA_DOCKER_SOCKET=/absolute/docker.sock scripts/local-update-smoke.sh" >&2
  exit 2
fi

socket=${VUELTA_DOCKER_SOCKET:-}
if [ -z "$socket" ]; then
  echo "VUELTA_DOCKER_SOCKET must name the explicit local Unix socket to test" >&2
  exit 2
fi
case "$socket" in
  /*) ;;
  *) echo "VUELTA_DOCKER_SOCKET must be absolute" >&2; exit 2 ;;
esac
if [ ! -S "$socket" ]; then
  echo "Docker socket does not exist: set VUELTA_DOCKER_SOCKET to an explicit local Unix socket" >&2
  exit 2
fi

acceptance_root=$(mktemp -d "${TMPDIR:-/tmp}/vuelta-real-engine.XXXXXX")
cleanup() {
  rmdir "$acceptance_root" 2>/dev/null || true
}
trap cleanup EXIT

docker --host "unix://$socket" compose --profile acceptance run --rm --build \
  --volume "$socket:/var/run/docker.sock" \
  --volume "$acceptance_root:$acceptance_root" \
  --env "TMPDIR=$acceptance_root" \
  --env "GOTMPDIR=/tmp" \
  --env "VUELTA_ACCEPTANCE_ROOT=$acceptance_root" \
  real-engine go test -tags=realengine -count=1 -timeout=20m \
  -run '^TestCLIOnlyLocalUpdateDryRun$' ./acceptance
