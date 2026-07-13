.PHONY: build build-mac build-linux test lint

build: build-mac build-linux

test:
	docker compose run --rm test

lint:
	docker compose run --rm lint

# Cross-compile in the project Docker image so host Go tooling is never used.
build-mac:
	docker compose run --rm -e CGO_ENABLED=0 -e GOOS=darwin -e GOARCH=arm64 build go build -trimpath -o /src/bin/vuelta-darwin-arm64 ./cmd/vuelta

build-linux:
	docker compose run --rm -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 build go build -trimpath -o /src/bin/vuelta-linux-amd64 ./cmd/vuelta
