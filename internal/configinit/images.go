package configinit

// Default images seeded into a freshly generated config by `vuelta config
// init`. Every reference must stay pinned to a digest (config.Validate
// rejects unpinned images): a mutable tag lets the registry silently swap
// out what gets pulled, which defeats the reproducibility and supply-chain
// guarantees the rest of the pipeline (vulnscan, autofix, deploy) relies on.
//
// To refresh a pin, resolve the current digest for the tag and update both
// the tag and the digest together, e.g.:
//
//	docker buildx imagetools inspect <image>:<tag> --format '{{json .Manifest}}'
//	# or: crane digest <image>:<tag>
//
// Never bump only the digest while leaving a stale tag comment, and never
// hand-edit a digest without re-resolving it from the registry.

const trivyImage = "aquasec/trivy@sha256:1c60229e5bc7f5830bf8aeb829442cb01f71ce3cd5b4d1b754f1f166c9945951"

func defaultImages() map[string]string {
	return map[string]string{
		"python-poetry":    "python:3.12-slim@sha256:b3acc63118e4dde71287074936a02afe84748dc6a7ef9ed544fea2745cfa6153",
		"python-uv":        "ghcr.io/astral-sh/uv:0.6.14@sha256:a06fb406bda92ac2c105cd45111a206b80294215d6480fa4ce4fd931ab66d7b2",
		"python-pip-tools": "python:3.12-slim@sha256:b3acc63118e4dde71287074936a02afe84748dc6a7ef9ed544fea2745cfa6153",
		"node":             "node:22@sha256:e59e7e103c548864aa008d397b8487c96c539538ca8ec724330fd5cb35d609b3",
		"bun":              "oven/bun:1.2@sha256:24b8162f18519860276bddcd5cf74045815be0bd1023b35061fb926f1b7989d2",
	}
}
