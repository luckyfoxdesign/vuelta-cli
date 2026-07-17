# Self-contained scanner images

These Dockerfiles are release inputs for immutable toolchain profiles. Every
base image and copied tool image must be supplied as an exact `@sha256:`
reference. Every package/scanner version is installed during the build and
verified there; a live scan invokes the installed executable directly and
never uses `npx`, `bunx`, Corepack downloads, or runtime `pip install`.

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
  --build-arg NCU_VERSION='18.1.1' \
  --file scanner-images/node-ncu.Dockerfile \
  --tag registry.example/vuelta/node24-npm-ncu:18.1.1 --push .
docker buildx imagetools inspect registry.example/vuelta/node24-npm-ncu:18.1.1
```

The registry destination and its authentication are operator-owned release
inputs. They are never read from project files or forwarded to scanner
containers.
