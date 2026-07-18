# Self-contained scanner images

These Dockerfiles are release inputs for immutable toolchain profiles. Every
base image and copied tool image must be supplied as an exact `@sha256:`
reference. Every package/scanner version is installed during the build and
verified there; a live scan invokes the installed executable directly and
never uses `npx`, `bunx`, Corepack downloads, or runtime `pip install`.

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

Build and publish with BuildKit for both supported platforms. Resolve the
resulting registry digest, place that exact reference in
`update.toolchain_profiles`, then run the real-engine acceptance command before
promoting the catalog. Do not use locally invented digests or mutable tags.

Example for one profile:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg BASE_IMAGE='node:24-slim@sha256:<verified-index-digest>' \
  --build-arg NCU_VERSION='22.2.9' \
  --file scanner-images/node-ncu.Dockerfile \
  --tag registry.example/vuelta/node24-npm-ncu:22.2.9 --push .
docker buildx imagetools inspect registry.example/vuelta/node24-npm-ncu:22.2.9
```

For pip-tools, add the scanner version to the existing pinned pip build args:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg BASE_IMAGE='python:3.12-slim@sha256:<verified-index-digest>' \
  --build-arg PIP_VERSION='<exact-version>' \
  --build-arg PIP_TOOLS_VERSION='<exact-version>' \
  --build-arg SCANNER_VERSION='1.0.0' \
  --file scanner-images/python-pip-tools.Dockerfile \
  --tag registry.example/vuelta/python312-pip-tools:7.5.0-scanner1.0.0 --push .
```

The registry destination and its authentication are operator-owned release
inputs. They are never read from project files or forwarded to scanner
containers.
