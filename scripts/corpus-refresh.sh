#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: scripts/corpus-refresh.sh /absolute/path/to/vuelta-corpus" >&2
  exit 2
fi

corpus_root=$1
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
  corpus refresh "$corpus_root"
