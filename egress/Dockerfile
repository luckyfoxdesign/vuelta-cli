FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

WORKDIR /src
COPY go.mod ./go.mod
COPY egress/main.go ./egress/main.go
COPY internal/egressproxy ./internal/egressproxy
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /egress-proxy ./egress

FROM scratch

COPY --from=build /egress-proxy /egress-proxy
USER 65532:65532
EXPOSE 3128
HEALTHCHECK --interval=2s --timeout=2s --retries=15 CMD ["/egress-proxy", "--healthcheck"]
ENTRYPOINT ["/egress-proxy"]
