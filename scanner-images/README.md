# Self-contained scanner images

These Dockerfiles and their small helper files are embedded in the Vuelta
binary. Adaptive toolchain resolution selects one from allowlisted project
metadata and builds it locally on first use. The resulting local image ID is
cached under a content hash covering the Dockerfile, helpers, platform, and
build arguments. Every package/scanner version is installed and verified at
build time; a live scan invokes the installed executable directly and never
uses `npx`, `bunx`, Corepack downloads, or runtime `pip install`.

Before a newly built image receives its content-hash cache tag, Vuelta also
inspects its immutable local image ID, OS/architecture, and configured user,
then runs the scanner's exact `--version` contract with no network, a
read-only root filesystem, dropped capabilities, `no-new-privileges`, the
profile's numeric user, and a `noexec` `/tmp`. A failed inspection or smoke
test leaves the cache tag unpublished. Cached images are not reprobed during
each live scan.

`python-pip-tools.Dockerfile` also installs the versioned
`vuelta-pip-tools-scan` helper. For pip-tools it reads direct exact pins from
`requirements.in`; for the explicit `python/requirements` profile it reads
the reviewed root `requirements.txt`. It queries bounded PyPI JSON metadata
through the mandatory egress proxy and never invokes pip, follows includes,
or installs project dependencies. Exact pins survive alongside bounded
per-line diagnostics for ranges, URLs, editable installs, hashes, includes,
malformed records, and ambiguous duplicate pins. Pass
`SCANNER_VERSION=1.1.0` when building that image; the Docker build runs the
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

## Controlled refresh

Refreshing a scanner is a reviewed source change, not a background download:

1. Inspect every base tag's registry manifest, record its current digest and
   confirm the required `linux/amd64` and `linux/arm64` entries.
2. Review upstream release notes and advisories for the base runtime, package
   manager, scanner, and their installed dependency tree. Run the configured
   pinned Trivy image against each locally built image ID when performing the
   review; do not make this network/database-dependent audit part of live
   `scan`.
3. Update only exact versions in `internal/toolchain/defaults.go` and the
   matching build arguments. The build contract and embedded inputs change
   the cache key; `docker build --pull` refreshes the reviewed base tag.
4. Run the Docker test, race, and lint services plus the real-engine matrix
   for npm, pnpm, Poetry, and uv. That matrix is the registry/network command
   smoke test; the pre-cache probe separately proves hardened startup.
5. Review the diff for provenance, unexpected downloads, credentials, and
   weakened container flags before committing the refresh.
