# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG NCU_VERSION
ENV BUN_INSTALL=/opt/bun-tools
ENV PATH=/opt/bun-tools/bin:${PATH}
RUN test -n "${NCU_VERSION}" \
    && mkdir -p /opt/bun-tools \
    && bun add --global --exact "npm-check-updates@${NCU_VERSION}" \
    && ncu --version | grep -Fx "${NCU_VERSION}" \
    && chown -R 1000:1000 /opt/bun-tools

ENTRYPOINT []
CMD ["ncu", "--version"]
USER 1000:1000
