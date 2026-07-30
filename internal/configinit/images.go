package configinit

// Security scanners remain explicit immutable inputs. Package-manager scanner
// images are instead built from the embedded defaults in internal/toolchain.

// trivyImage must pin the multi-platform OCI index, not one
// architecture-specific manifest: generated configs support both
// linux/amd64 and linux/arm64 Docker engines. Digest pinning does not
// itself verify a registry signature.
const trivyImage = "aquasec/trivy@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f"
