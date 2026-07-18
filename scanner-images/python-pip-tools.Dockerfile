# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG PIP_VERSION
ARG PIP_TOOLS_VERSION
ARG SCANNER_VERSION
COPY scanner-images/pip_tools_scan.py /opt/vuelta-scanner/pip_tools_scan.py
COPY scanner-images/test_pip_tools_scan.py /opt/vuelta-scanner/test_pip_tools_scan.py
RUN test -n "${PIP_VERSION}" \
    && test -n "${PIP_TOOLS_VERSION}" \
    && test -n "${SCANNER_VERSION}" \
    && python -m pip install --no-cache-dir --disable-pip-version-check "pip==${PIP_VERSION}" "pip-tools==${PIP_TOOLS_VERSION}" \
    && pip --version | grep -F " ${PIP_VERSION} " \
    && pip-compile --version | grep -F "${PIP_TOOLS_VERSION}" \
    && install -m 0555 /opt/vuelta-scanner/pip_tools_scan.py /usr/local/bin/vuelta-pip-tools-scan \
    && test "$(vuelta-pip-tools-scan --version)" = "${SCANNER_VERSION}" \
    && PYTHONDONTWRITEBYTECODE=1 python -m unittest -v /opt/vuelta-scanner/test_pip_tools_scan.py \
    && rm -f /opt/vuelta-scanner/pip_tools_scan.py /opt/vuelta-scanner/test_pip_tools_scan.py \
    && rmdir /opt/vuelta-scanner \
    && groupadd --gid 10001 vuelta \
    && useradd --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vuelta

ENTRYPOINT []
CMD ["vuelta-pip-tools-scan", "--version"]
USER 10001:10001
