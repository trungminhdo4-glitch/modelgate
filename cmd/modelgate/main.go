// Command modelgate is a static, non-executing supply-chain checker for
// Hugging Face model and dataset repositories.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/trungminhdo4-glitch/modelgate/internal/cli"
)

// version is injected at build time:
//
//	go build -trimpath -ldflags "-s -w -X main.version=1.0.0"
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	app := cli.New()
	app.Version = version
	os.Exit(app.Run(ctx, os.Args[1:]))
}
