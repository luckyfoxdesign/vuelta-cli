// Command egress-proxy runs Vuelta's registry-allowlisting forward proxy.
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/egressproxy"
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
