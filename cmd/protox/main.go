package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"proto-x/internal/app"
)

var version = "0.1.1-experimental"

func main() {
	if e := run(); e != nil {
		slog.Error("protox stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: protox init|server|client|version")
	}
	if os.Args[1] == "version" {
		fmt.Println("PROTO-X", version)
		return nil
	}
	if os.Args[1] == "init" {
		fs := flag.NewFlagSet("init", flag.ContinueOnError)
		dir := fs.String("dir", ".local/demo", "private config directory")
		host := fs.String("host", "127.0.0.1", "server address")
		tp := fs.Int("tls-port", 14443, "TLS server port")
		qp := fs.Int("quic-port", 14443, "QUIC server port")
		if e := fs.Parse(os.Args[2:]); e != nil {
			return e
		}
		if e := app.Init(*dir, *host, *tp, *qp); e != nil {
			return e
		}
		fmt.Println("Created private configuration in", *dir)
		return nil
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	path := fs.String("config", "", "configuration JSON path")
	if e := fs.Parse(os.Args[2:]); e != nil {
		return e
	}
	if *path == "" {
		return fmt.Errorf("-config is required")
	}
	cfg, e := app.Load(*path)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	switch os.Args[1] {
	case "server":
		return app.RunServer(ctx, cfg)
	case "client":
		return app.RunClient(ctx, cfg)
	default:
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}
