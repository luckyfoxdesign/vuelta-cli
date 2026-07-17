# syntax=docker/dockerfile:1.7
ARG UV_IMAGE
ARG BASE_IMAGE
FROM ${UV_IMAGE} AS uv

FROM ${BASE_IMAGE}
ARG UV_VERSION
COPY --from=uv /uv /usr/local/bin/uv
RUN test -n "${UV_VERSION}" \
    && uv --version | grep -F "uv ${UV_VERSION} " \
    && groupadd --gid 10001 vuelta \
    && useradd --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vuelta

ENTRYPOINT []
CMD ["uv", "--version"]
USER 10001:10001
