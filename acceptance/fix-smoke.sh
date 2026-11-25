#!/usr/bin/env bash
# Networked acceptance against fresh synthetic inputs. No host package manager.
set -euo pipefail
binary=${1:?absolute path to vuelta required}
socket=${2:?absolute Docker socket required}
case "$binary:$socket" in
  /*:/*) ;;
  *) echo "binary and socket paths must be absolute" >&2; exit 2 ;;
esac
if [ -n "${VUELTA_FIX_SMOKE_ROOT:-}" ]; then
  smoke_root=$VUELTA_FIX_SMOKE_ROOT
  if [ -e "$smoke_root" ]; then
    echo "VUELTA_FIX_SMOKE_ROOT must be a new path" >&2
    exit 2
  fi
  mkdir -m 700 "$smoke_root"
else
  smoke_root=$(mktemp -d)
fi
project="$smoke_root/project"
machine_config="$smoke_root/config.yaml"
mkdir -m 700 "$project"
cat > "$project/package.json" <<'JSON'
{"name":"vuelta-fix-smoke","version":"1.0.0","engines":{"node":"22.x"},"packageManager":"npm@10.9.2","scripts":{"preinstall":"node -e \"require('fs').writeFileSync('lifecycle-ran','unsafe');process.exit(91)\"","postinstall":"node -e \"require('fs').writeFileSync('lifecycle-ran','unsafe');process.exit(91)\""},"dependencies":{"lodash":"4.17.20"}}
JSON
cat > "$project/package-lock.json" <<'JSON'
{"name":"vuelta-fix-smoke","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"vuelta-fix-smoke","version":"1.0.0","dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}}
JSON
# Fixture setup must not consult an operator's Git configuration or run hooks.
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
git -C "$project" init -q
git -C "$project" add -- package.json package-lock.json
git -C "$project" -c user.name=smoke -c user.email=smoke@example.invalid \
  -c core.hooksPath=/dev/null -c commit.gpgSign=false commit -qm 'fixture baseline'
"$binary" --no-input --config "$machine_config" config init --yes > "$smoke_root/config-init.log"
"$binary" --no-input --config "$machine_config" environment bootstrap --socket "$socket" --yes > "$smoke_root/bootstrap.log" 2>&1
hash_inputs() {
  (cd "$project"
   if command -v sha256sum >/dev/null; then
     sha256sum package.json package-lock.json
   else
     shasum -a 256 package.json package-lock.json
   fi)
}
before=$(hash_inputs)
status=0
"$binary" --no-input --config "$machine_config" scan --directory "$project" \
  --read-only --json --fail-on vulnerabilities > "$smoke_root/before.json" 2> "$smoke_root/before.stderr" || status=$?
if [ "$status" -ne 5 ]; then
  echo "initial vulnerability scan did not return findings (exit $status)" >&2
  exit 1
fi
jq -e '.schema_version==1 and .results[0].error==null and any(.results[0].findings[]; .package=="lodash" and (.fixed_versions|length)>0)' "$smoke_root/before.json" >/dev/null
test "$before" = "$(hash_inputs)"
test -z "$(git -C "$project" status --porcelain=v1 --ignored --untracked-files=all)"
"$binary" --no-input --config "$machine_config" fix --directory "$project" \
  --json --verbose > "$smoke_root/fix.json" 2> "$smoke_root/fix.stderr"
jq -e '.format==1 and .command=="fix" and (.results|length)==1 and (.results[0] | .complete and (.fixed|length)>0 and all(.fixed[]; .package=="lodash") and (.rescan|length)==0 and (.changed_files|sort)==["package-lock.json","package.json"])' "$smoke_root/fix.json" >/dev/null
target=$(jq -r '.results[0].fixed[0].target_version' "$smoke_root/fix.json")
jq -e --arg target "$target" '.dependencies.lodash==$target' "$project/package.json" >/dev/null
jq -e --arg target "$target" '.packages["node_modules/lodash"].version==$target' "$project/package-lock.json" >/dev/null
expected=$(git -C "$project" show HEAD:package.json | jq -Sc --arg target "$target" '.dependencies.lodash=$target')
test "$expected" = "$(jq -Sc . "$project/package.json")"
test "$(git -C "$project" diff --name-only HEAD)" = "$(printf 'package-lock.json\npackage.json')"
test -z "$(git -C "$project" ls-files --others --exclude-standard)"
test ! -e "$project/lifecycle-ran"
before=$(hash_inputs)
"$binary" --no-input --config "$machine_config" scan --directory "$project" \
  --read-only --json --fail-on vulnerabilities > "$smoke_root/after.json" 2> "$smoke_root/after.stderr"
jq -e '.schema_version==1 and .results[0].error==null and (.results[0].findings|length)==0' "$smoke_root/after.json" >/dev/null
test "$before" = "$(hash_inputs)"
test ! -e "$project/.vuelta"
test ! -e "$project/.vuelta.yaml"
echo "CLI repair smoke passed: fixed lodash, admitted only manifest/lock edits, disabled lifecycle scripts, verified read-only rescan"
