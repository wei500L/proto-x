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

var version = "0.2.0-experimental"

func main() {
	if e := run(); e != nil {
		slog.Error("protox stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: protox init|ech-keygen|server|client|version")
	}
	if os.Args[1] == "version" {
		fmt.Println("PROTO-X", version)
		return nil
	}
	if os.Args[1] == "init" {
		fs := flag.NewFlagSet("init", flag.ContinueOnError)
		dir := fs.String("dir", ".local/demo", "private config directory")
		host := fs.String("host", "127.0.0.1", "server address")
		name := fs.String("server-name", "", "HTTPS identity; defaults to the host")
		legacy := fs.Bool("legacy", false, "generate the identifiable v0.1 raw QUIC/TLS configuration for comparison")
		tp := fs.Int("tls-port", 14443, "TLS server port")
		qp := fs.Int("quic-port", 14443, "QUIC server port")
		if e := fs.Parse(os.Args[2:]); e != nil {
			return e
		}
		var e error
		if *legacy {
			e = app.Init(*dir, *host, *tp, *qp)
		} else {
			e = app.InitWeb(*dir, *host, *name, *tp, *qp)
		}
		if e != nil {
			return e
		}
		fmt.Println("Created private configuration in", *dir)
		if !*legacy {
			fmt.Println("Development certificate: client explicitly uses pin-only trust. Use a valid certificate and CA verification for a public HTTPS identity.")
		}
		return nil
	}
	if os.Args[1] == "ech-keygen" {
		fs := flag.NewFlagSet("ech-keygen", flag.ContinueOnError)
		dir := fs.String("dir", "", "private ECH configuration directory")
		name := fs.String("public-name", "", "public outer HTTPS name")
		if e := fs.Parse(os.Args[2:]); e != nil {
			return e
		}
		if *dir == "" || *name == "" {
			return fmt.Errorf("-dir and -public-name are required")
		}
		if e := app.GenerateECH(*dir, *name); e != nil {
			return e
		}
		fmt.Println("Created ECH configuration; configure ech_keys_file on the server and ech_config_file on the client.")
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
