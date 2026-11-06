package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"proto-x/internal/bench"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		var cfg bench.ServeConfig
		fs.StringVar(&cfg.HTTP, "http", "127.0.0.1:18080", "HTTP fixture listen address (empty disables)")
		fs.StringVar(&cfg.HTTPS, "https", "", "optional HTTPS fixture listen address")
		fs.StringVar(&cfg.Echo, "echo", "127.0.0.1:18081", "TCP echo listen address (empty disables)")
		fs.StringVar(&cfg.Cert, "cert", "", "HTTPS certificate PEM path")
		fs.StringVar(&cfg.Key, "key", "", "HTTPS private-key PEM path")
		fs.Parse(os.Args[2:])
		err = bench.Serve(ctx, cfg)
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		var cfg bench.RunConfig
		fs.StringVar(&cfg.Proxy, "proxy", "127.0.0.1:1080", "explicit SOCKS5 host:port; direct only for fixture self-tests")
		fs.StringVar(&cfg.HTTPTarget, "http-target", "http://127.0.0.1:18080", "controlled HTTP/HTTPS fixture base URL")
		fs.StringVar(&cfg.EchoTarget, "echo-target", "127.0.0.1:18081", "controlled raw TCP echo fixture")
		fs.DurationVar(&cfg.Duration, "duration", 30*time.Second, "measurement duration; unfinished operations are censored")
		fs.DurationVar(&cfg.Timeout, "timeout", 3*time.Second, "interactive request and stream inactivity timeout")
		fs.Float64Var(&cfg.RPS, "rps", 5, "open-loop small HTTP requests/second (0 disables)")
		fs.StringVar(&cfg.HTTPMethod, "http-method", "POST", "small request method: POST avoids replay; GET permits normal idempotent retry")
		fs.IntVar(&cfg.HTTPBytes, "http-bytes", 1024, "verified small HTTP response size")
		fs.IntVar(&cfg.Concurrency, "concurrency", 64, "HTTP concurrency cap; overload is logged as rejected")
		fs.DurationVar(&cfg.EchoInterval, "echo-interval", 100*time.Millisecond, "minimum closed-loop echo start interval (0 disables)")
		fs.DurationVar(&cfg.SSEInterval, "stream-interval", 50*time.Millisecond, "SSE source generation cadence (0 disables)")
		fs.IntVar(&cfg.Background, "background", 1, "concurrent unlimited background downloads")
		fs.Float64Var(&cfg.BackgroundMbps, "background-mbps", 0, "source pacing Mbps per download worker (0 unlimited); not a proxy wire-rate cap")
		fs.IntVar(&cfg.Uploads, "uploads", 0, "concurrent background uploads")
		fs.Int64Var(&cfg.UploadBytes, "upload-bytes", 256<<10, "bytes per background upload; only completed ACKs count as goodput")
		fs.StringVar(&cfg.Output, "output", "", "new JSONL output path (required; never overwrites)")
		fs.StringVar(&cfg.Summary, "summary", "", "new summary output path; defaults to output basename.summary.json")
		fs.StringVar(&cfg.RunID, "run-id", "", "stable experiment identifier; defaults to current UTC timestamp")
		fs.StringVar(&cfg.CAFile, "ca", "", "additional trusted PEM certificate for HTTPS fixture")
		fs.BoolVar(&cfg.InsecureTLS, "insecure-tls", false, "explicitly skip HTTPS fixture certificate verification")
		fs.BoolVar(&cfg.ColdHTTP, "cold-http", false, "disable HTTP keepalive to measure connection setup")
		fs.Parse(os.Args[2:])
		if cfg.RunID == "" {
			cfg.RunID = time.Now().UTC().Format("20060102T150405.000000000Z")
		}
		var summary bench.Summary
		summary, err = bench.Run(ctx, cfg)
		if summary.RunID != "" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if e := enc.Encode(summary); err == nil {
				err = e
			}
		}
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pxbench:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "pxbench serve [flags] | pxbench run -proxy host:port -output run.jsonl [flags]")
	fmt.Fprintln(os.Stderr, "Controlled HTTP/HTTPS, persistent echo, paced SSE, and bulk traffic with raw events.")
}
