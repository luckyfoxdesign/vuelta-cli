#!/bin/sh
set -eu
case "$1" in
  version)
    if [ "$(cat /db-mode)" = stale ]; then
      printf '%s\n' '{"VulnerabilityDB":{"Version":2,"UpdatedAt":"2020-01-01T00:00:00Z","DownloadedAt":"2020-01-01T01:00:00Z"}}'
    else
      printf '%s\n' '{"VulnerabilityDB":{"Version":2}}'
    fi
    ;;
  *) printf '%s\n' '{}' ;;
esac
