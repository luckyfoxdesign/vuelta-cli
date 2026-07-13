# Dev image shared by the test/tidy/build compose services. Not a runtime
# image for the vuelta binary itself — packaging/distribution is a later task.
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2

RUN apk add --no-cache build-base git

WORKDIR /src
