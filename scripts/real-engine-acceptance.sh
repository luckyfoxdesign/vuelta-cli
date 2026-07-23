#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: scripts/real-engine-acceptance.sh /absolute/path/to/matrix.yaml" >&2
  exit 2
fi

matrix=$1
case "$matrix" in
  /*) ;;
  *) echo "matrix path must be absolute" >&2; exit 2 ;;
esac

if [ ! -f "$matrix" ]; then
  echo "matrix file does not exist" >&2
  exit 2
fi

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
docker compose --profile acceptance run --rm \
  --volume "$socket:/var/run/docker.sock" \
  --volume "$acceptance_root:$acceptance_root" \
  --volume "$matrix:$matrix:ro" \
	--env "TMPDIR=$acceptance_root" \
  --env "GOTMPDIR=/tmp" \
  --env "VUELTA_ACCEPTANCE_ROOT=$acceptance_root" \
  --env "VUELTA_ACCEPTANCE_MATRIX=$matrix" \
  real-engine
