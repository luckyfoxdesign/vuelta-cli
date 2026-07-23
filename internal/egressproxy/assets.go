package egressproxy

import _ "embed"

// Source is the exact proxy implementation embedded in the Vuelta binary for
// a self-contained local runtime build.
//
//go:embed proxy.go
var Source []byte

// MainSource is the minimal entrypoint materialized beside Source.
const MainSource = `package main

import (
	"context"
	"log"
	"os"
	"time"

	"vuelta.local/egress-runtime/egressproxy"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := egressproxy.Healthcheck(ctx); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := egressproxy.Run(); err != nil {
		log.Fatal(err)
	}
}
`

// ModuleSource gives the isolated build context a standard-library-only
// module. It never resolves Go dependencies from the network.
const ModuleSource = "module vuelta.local/egress-runtime\n\ngo 1.26\n"
