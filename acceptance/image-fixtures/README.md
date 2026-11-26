# Published image acceptance

Run from `app/`. Only synthetic public images are published. The application
fixture copies the checksum-verified contents of a real lodash package into
an application layer on the pinned Alpine base. The runtime removes the unused
APK package manager and its dependencies offline with `apk del --no-scripts`;
the remaining OS files and APK inventory agree. The native build-stage package
manager operates on the target root without executing target binaries, so both
architectures build without QEMU or privileged containers. No installation
scripts run. No findings are filtered or ignored.
Versions: vulnerable `4.17.20`, clean candidate `4.18.1`. A newly disclosed
vulnerability must fail the clean gate; do not filter it out.

1. Dispatch `vulnerability-scan.yml`, mode `publish-image-fixtures`, on the
   reviewed source revision. The dedicated job has `packages:write` and its own
   Docker config. Its `image-fixture-digests` artifact records immutable image
   identities and the fixture source SHA.
2. Ensure the GHCR package `luckyfoxdesign/vuelta-cli-scan-fixtures` is Public.
   Download `fixtures.json`, review its four repository/digest entries, then
   commit it here. Acceptance never resolves a mutable fixture tag.
3. Dispatch the same workflow, mode `image-acceptance`, on that exact commit.
   This job has only `contents:read`, no registry login, and a fresh Docker config.

The exact standalone invocation is:

```sh
bash acceptance/image-smoke.sh "$PWD/bin/vuelta-linux-amd64" \
  /var/run/docker.sock acceptance/image-fixtures/fixtures.json
```

Run this on an idle nonproduction Linux/amd64 Engine. It executes the compiled
CLI and retains Docker attestation, non-root scanner containers, no socket or
host-config mount in scanners, and managed allowlisted egress. The arm64 case
scans arm64 image contents on this amd64 host; it does not accept an arm64 CLI.

Cases cover an application dependency finding (exit 5), clean inventories (0),
matching/differing production exports, arm64 contents, a wrong digest/platform
combination, unavailable digest, OS-only partial coverage, timeout and malformed
input. Resource snapshots verify cleanup after each invocation and preservation
of pre-existing containers/volumes; managed DB volumes are intentionally retained.

`db-stale` and `db-missing` are scanner stand-ins. They execute through the real
CLI/Docker boundary and exercise DB rejection without modifying the real Trivy
cache. They are not live registry/DB validation. No production or private image
is accessed. No credentials, machine configuration or stderr logs are uploaded.

On success, `vuelta-image-accepted-linux-amd64` contains the binary, checksum,
Go build metadata and source SHA. Independently download it and run
`sha256sum -c vuelta-linux-amd64.sha256`; confirm `vcs.revision` equals the
workflow head SHA and `vcs.modified=false`. Artifacts expire after 30 days;
use a recorded run-specific artifact URL, never a floating "latest" reference.
The evidence artifact contains only versioned public reports, fixture digests
and exits. A failed acceptance never uploads an accepted binary.
