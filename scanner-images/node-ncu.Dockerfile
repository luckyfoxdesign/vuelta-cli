# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG NPM_VERSION
ARG NCU_VERSION
RUN test -n "${NPM_VERSION}" \
    && test -n "${NCU_VERSION}" \
    && npm install --global --ignore-scripts --no-audit --no-fund "npm@${NPM_VERSION}" "npm-check-updates@${NCU_VERSION}" \
    && npm --version | grep -Fx "${NPM_VERSION}" \
    && ncu --version | grep -Fx "${NCU_VERSION}" \
    && groupadd --gid 10001 vuelta \
    && useradd --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vuelta

ENTRYPOINT []
CMD ["ncu", "--version"]
USER 10001:10001
