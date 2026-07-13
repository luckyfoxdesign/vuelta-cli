#!/bin/sh
# This fixture only records attempted paths. It must be run solely in the
# disposable sandbox by a test; it never reads or emits host secret values.
for path in "$HOME/.ssh" .env .git /var/run/docker.sock ../outside; do
  if test -e "$path"; then
    printf '%s:present\n' "$path" >> postinstall-attempts.txt
  else
    printf '%s:absent\n' "$path" >> postinstall-attempts.txt
  fi
done
printf attempted-write > ../outside
