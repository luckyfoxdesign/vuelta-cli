FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/vuelta-gateway ./cmd/vuelta-gateway
COPY internal/gateway ./internal/gateway
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/vuelta-gateway ./cmd/vuelta-gateway

FROM scratch
USER 65532:65532
COPY --from=build /out/vuelta-gateway /vuelta-gateway
ENTRYPOINT ["/vuelta-gateway"]
