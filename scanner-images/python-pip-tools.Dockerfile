# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG PIP_VERSION
ARG PIP_TOOLS_VERSION
RUN test -n "${PIP_VERSION}" \
    && test -n "${PIP_TOOLS_VERSION}" \
    && python -m pip install --no-cache-dir --disable-pip-version-check "pip==${PIP_VERSION}" "pip-tools==${PIP_TOOLS_VERSION}" \
    && pip --version | grep -F " ${PIP_VERSION} " \
    && pip-compile --version | grep -F "${PIP_TOOLS_VERSION}" \
    && groupadd --gid 10001 vuelta \
    && useradd --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vuelta

ENTRYPOINT []
CMD ["pip", "--version"]
USER 10001:10001
