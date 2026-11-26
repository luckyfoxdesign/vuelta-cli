#!/bin/sh
set -eu
case "$1" in
  version)
    if [ "$(cat /db-mode)" = stale ]; then
      printf '%s\n' '{"VulnerabilityDB":{"Version":2,"UpdatedAt":"2020-01-01T00:00:00Z","DownloadedAt":"2020-01-01T01:00:00Z"}}'
    else
      # The timeout case must observe a running scanner before its deadline,
      # rather than merely expire before any Docker resource was created.
      sleep 10
      printf '%s\n' '{"VulnerabilityDB":{"Version":2}}'
    fi
    ;;
  *) printf '%s\n' '{}' ;;
esac
