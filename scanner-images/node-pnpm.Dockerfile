# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG PNPM_VERSION
RUN test -n "${PNPM_VERSION}" \
    && npm install --global --ignore-scripts --no-audit --no-fund "pnpm@${PNPM_VERSION}" \
    && pnpm --version | grep -Fx "${PNPM_VERSION}" \
    && groupadd --gid 10001 vuelta \
    && useradd --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vuelta

ENV npm_config_ignore_scripts=true \
    PNPM_CONFIG_IGNORE_SCRIPTS=true

ENTRYPOINT []
CMD ["pnpm", "--version"]
USER 10001:10001
