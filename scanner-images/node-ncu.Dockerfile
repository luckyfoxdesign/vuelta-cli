# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG NCU_VERSION
RUN test -n "${NCU_VERSION}" \
    && npm install --global --ignore-scripts --no-audit --no-fund "npm-check-updates@${NCU_VERSION}" \
    && ncu --version | grep -Fx "${NCU_VERSION}" \
    && groupadd --gid 10001 vuelta \
    && useradd --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vuelta

ENTRYPOINT []
CMD ["ncu", "--version"]
USER 10001:10001
