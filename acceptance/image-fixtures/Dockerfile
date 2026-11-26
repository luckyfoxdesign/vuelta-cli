# Public synthetic images only. The build stage downloads package contents;
# it never executes dependency installation scripts or application code.
ARG BASE=alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
FROM --platform=$BUILDPLATFORM ${BASE} AS package
ARG VERSION
ARG CHECKSUM
RUN wget -q "https://registry.npmjs.org/lodash/-/lodash-${VERSION}.tgz" -O /package.tgz \
    && echo "${CHECKSUM}  /package.tgz" | sha256sum -c - \
    && mkdir /library && tar -xzf /package.tgz -C /library --strip-components=1

# Make a minimal runtime with a real APK inventory. Use the native package
# manager offline on the target root, with target install scripts disabled;
# this needs neither QEMU nor execution of foreign-architecture binaries.
FROM ${BASE} AS runtime-input
FROM --platform=$BUILDPLATFORM ${BASE} AS runtime
COPY --from=runtime-input / /runtime/
RUN apk --root /runtime --no-network --no-scripts del apk-tools

FROM scratch AS application
LABEL org.opencontainers.image.source="https://github.com/luckyfoxdesign/vuelta-cli"
COPY --from=runtime /runtime/ /
COPY --from=package /library /app/node_modules/lodash
USER 65532:65532

# These two scanner stand-ins test database failure through the compiled CLI
# and real Docker isolation. They are explicitly NOT live Trivy/DB evidence.
FROM ${BASE} AS database-standin
LABEL org.opencontainers.image.source="https://github.com/luckyfoxdesign/vuelta-cli"
ARG DB_MODE
COPY database-standin.sh /standin
RUN chmod 555 /standin && echo "$DB_MODE" > /db-mode
ENTRYPOINT ["/standin"]
