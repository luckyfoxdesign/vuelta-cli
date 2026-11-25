#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
  echo "usage: scripts/real-engine-acceptance.sh" >&2
  exit 2
fi
export COMPOSE_DISABLE_ENV_FILE=1

socket=${VUELTA_DOCKER_SOCKET:-/var/run/docker.sock}
case "$socket" in
  /*) ;;
  *) echo "VUELTA_DOCKER_SOCKET must be absolute" >&2; exit 2 ;;
esac

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
  real-engine
