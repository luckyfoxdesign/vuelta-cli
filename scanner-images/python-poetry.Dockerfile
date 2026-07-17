# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG POETRY_VERSION
RUN test -n "${POETRY_VERSION}" \
    && python -m pip install --no-cache-dir --disable-pip-version-check "poetry==${POETRY_VERSION}" \
    && poetry --version | grep -F "${POETRY_VERSION}" \
    && groupadd --gid 10001 vuelta \
    && useradd --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vuelta

ENTRYPOINT []
CMD ["poetry", "--version"]
USER 10001:10001
