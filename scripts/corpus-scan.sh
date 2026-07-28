#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
  echo "usage: scripts/corpus-scan.sh /absolute/path/to/vuelta-corpus [--stable-only | --case NAME | --only-failed /absolute/path/to/report.json] [--timeout DURATION]" >&2
  exit 2
fi

corpus_root=$1
shift
case "$corpus_root" in
  /*) ;;
  *) echo "corpus ROOT must be absolute" >&2; exit 2 ;;
esac
if [ ! -d "$corpus_root" ]; then
  echo "corpus ROOT must be an existing directory" >&2
  exit 2
fi

socket=${VUELTA_DOCKER_SOCKET:-/var/run/docker.sock}
case "$socket" in
  /*) ;;
  *) echo "VUELTA_DOCKER_SOCKET must be absolute" >&2; exit 2 ;;
esac

docker compose --profile corpus run --rm --build \
  --volume "$socket:/var/run/docker.sock" \
  --volume "$corpus_root:$corpus_root" \
  --env "VUELTA_CORPUS_DOCKER_SOCKET=/var/run/docker.sock" \
  corpus scan "$corpus_root" "$@"
