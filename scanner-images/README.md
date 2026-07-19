# Self-contained scanner images

These Dockerfiles and their small helper files are embedded in the Vuelta
binary. Adaptive toolchain resolution selects one from allowlisted project
metadata and builds it locally on first use. The resulting local image ID is
cached under a content hash covering the Dockerfile, helpers, platform, and
build arguments. Every package/scanner version is installed and verified at
build time; a live scan invokes the installed executable directly and never
uses `npx`, `bunx`, Corepack downloads, or runtime `pip install`.

`python-pip-tools.Dockerfile` also installs the versioned
`vuelta-pip-tools-scan` helper. It reads only direct exact pins from
`requirements.in`, queries bounded PyPI JSON metadata through the mandatory
egress proxy, and never installs project dependencies. Pass
`SCANNER_VERSION=1.0.0` when building that image; the Docker build runs the
helper's hermetic parser and response tests and verifies the version.

`node/bun` is intentionally not a supported profile. `npm-check-updates`
cannot use the mandatory proxy when executed by Bun, while `bun outdated`
does not provide a stable structured output contract. Keep the Dockerfile as
an upstream compatibility fixture, not as a catalog release input.

Each image has an empty entrypoint and a known passwd user. Profile metadata
must declare `10001:10001`, except `bun-ncu`, which uses the base image's known
`1000:1000` Bun user. Vuelta still runs the final container with a read-only
root filesystem, `cap_drop=ALL`, `no-new-privileges`, and a `noexec` tmpfs.

The embedded default table and exact tool versions live in
`internal/toolchain/defaults.go`. `update.toolchain_profiles` is not a catalog;
it is an optional full, digest-pinned operator override for exceptional
environments. Vuelta never pushes locally built defaults and the isolated
Docker boundary does not read registry credentials.
