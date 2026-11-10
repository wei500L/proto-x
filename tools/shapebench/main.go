// Command shapebench records real QUIC datagrams and compares a controlled
// native HTTP/3 streaming application with the same workload through SOCKS.
// It is experiment tooling, not a browser, DPI engine or proxy implementation.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"proto-x/internal/bench"
	"proto-x/internal/carrier"
)

type journal struct {
	mu    sync.Mutex
	enc   *json.Encoder
	start time.Time
	err   error
}

func (j *journal) emit(x map[string]any) {
	j.mu.Lock()
	defer j.mu.Unlock()
	x["t_ns"] = time.Since(j.start).Nanoseconds()
	if j.err == nil {
		j.err = j.enc.Encode(x)
	}
}

func openJournal(path string) (*journal, *os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, err
	}
	j := &journal{enc: json.NewEncoder(f), start: time.Now()}
	j.emit(map[string]any{"kind": "clock", "epoch_unix_ns": j.start.UnixNano(), "elapsed_clock": "Go monotonic; same-host wall epoch aligns process starts"})
	return j, f, nil
}

func save(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if len(os.Args) < 2 {
		panic("use server, relay or client")
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = server(ctx, os.Args[2:])
	case "relay":
		err = relay(ctx, os.Args[2:])
	case "client":
		err = client(ctx, os.Args[2:])
	default:
		err = errors.New("unknown shapebench command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func server(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	addr := fs.String("listen", "127.0.0.1:0", "owned loopback UDP listener")
	certFile := fs.String("cert", "", "private certificate file")
	keyFile := fs.String("key", "", "private key file")
	echFile := fs.String("ech-keys", "", "private ECH key file")
	ready := fs.String("ready", "", "new private readiness file")
	fs.Parse(args)
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	var keys []tls.EncryptedClientHelloKey
	if *echFile != "" {
		b, e := os.ReadFile(*echFile)
		if e != nil {
			return e
		}
		if e = json.Unmarshal(b, &keys); e != nil {
			return e
		}
	}
	tc, err := carrier.WebServerTLS(carrier.WebTLSServerOptions{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, ECHKeys: keys})
	if err != nil {
		return err
	}
	ln, err := quic.ListenAddr(*addr, http3.ConfigureTLSConfig(tc), carrier.WebQUICConfig())
	if err != nil {
		return err
	}
	defer ln.Close()
	s := &http3.Server{Handler: bench.FixtureHandler(), MaxHeaderBytes: 16 << 10, IdleTimeout: 20 * time.Second}
	defer s.Close()
	stop := context.AfterFunc(ctx, func() { ln.Close(); s.Close() })
	defer stop()
	if err := save(*ready, map[string]any{"address": ln.Addr().String()}); err != nil {
		return err
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() { defer wg.Done(); _ = s.ServeQUICConn(c) }()
	}
}

type datagram struct {
	data []byte
	due  time.Time
}

func relay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	addr := fs.String("listen", "127.0.0.1:0", "owned loopback UDP listener")
	target := fs.String("target", "", "owned server UDP target")
	ready := fs.String("ready", "", "new private readiness file")
	out := fs.String("out", "", "new packet metadata JSONL; no contents")
	delay := fs.Duration("delay", 20*time.Millisecond, "propagation delay per direction")
	up := fs.Float64("up-mbps", 2, "IPv4+UDP egress rate")
	down := fs.Float64("down-mbps", 8, "IPv4+UDP egress rate")
	fs.Parse(args)
	if *up <= 0 || *down <= 0 || *delay < 0 {
		return errors.New("invalid relay parameters")
	}
	frontAddr, err := net.ResolveUDPAddr("udp4", *addr)
	if err != nil {
		return err
	}
	front, err := net.ListenUDP("udp4", frontAddr)
	if err != nil {
		return err
	}
	defer front.Close()
	backAddr, err := net.ResolveUDPAddr("udp4", *target)
	if err != nil {
		return err
	}
	back, err := net.DialUDP("udp4", nil, backAddr)
	if err != nil {
		return err
	}
	defer back.Close()
	j, file, err := openJournal(*out)
	if err != nil {
		return err
	}
	defer file.Close()
	j.emit(map[string]any{"kind": "start", "delay_ns": int64(*delay), "up_mbps": *up, "down_mbps": *down, "counting": "actual UDP payload; egress serializer includes 28 IPv4+UDP bytes", "is_host_pcap": false})
	stop := context.AfterFunc(ctx, func() { front.Close(); back.Close() })
	defer stop()
	var peer *net.UDPAddr
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, dir := range []string{"up", "down"} {
		queue := make(chan datagram, 4096)
		wg.Add(2)
		go func(dir string) {
			defer wg.Done()
			defer close(queue)
			b := make([]byte, 65535)
			var next time.Time
			rate := *up * 1e6 / 8
			if dir == "down" {
				rate = *down * 1e6 / 8
			}
			for {
				var n int
				var e error
				if dir == "up" {
					var from *net.UDPAddr
					n, from, e = front.ReadFromUDP(b)
					if e == nil {
						mu.Lock()
						if peer == nil {
							peer = from
						}
						valid := peer.String() == from.String()
						mu.Unlock()
						if !valid {
							j.emit(map[string]any{"kind": "foreign_client_drop", "dir": dir, "n": n})
							continue
						}
					}
				} else {
					n, e = back.Read(b)
				}
				if e != nil {
					if ctx.Err() == nil {
						j.emit(map[string]any{"kind": "read_error", "dir": dir, "error_class": fmt.Sprintf("%T", e)})
					}
					return
				}
				j.emit(map[string]any{"kind": "packet", "dir": dir, "n": n})
				now := time.Now()
				if next.Before(now) {
					next = now
				}
				next = next.Add(time.Duration(float64(n+28) / rate * float64(time.Second)))
				p := datagram{data: append([]byte(nil), b[:n]...), due: next.Add(*delay)}
				select {
				case queue <- p:
				default:
					j.emit(map[string]any{"kind": "queue_drop", "dir": dir, "n": n})
				}
			}
		}(dir)
		go func(dir string) {
			defer wg.Done()
			for p := range queue {
				if !wait(ctx, p.due) {
					return
				}
				var e error
				if dir == "up" {
					_, e = back.Write(p.data)
				} else {
					mu.Lock()
					to := peer
					mu.Unlock()
					if to == nil {
						j.emit(map[string]any{"kind": "unbound_drop", "dir": dir, "n": len(p.data)})
						continue
					}
					_, e = front.WriteToUDP(p.data, to)
				}
				if e != nil {
					if ctx.Err() == nil {
						j.emit(map[string]any{"kind": "write_error", "dir": dir, "n": len(p.data)})
					}
					return
				}
				j.emit(map[string]any{"kind": "forwarded", "dir": dir, "n": len(p.data)})
			}
		}(dir)
	}
	if err := save(*ready, map[string]any{"address": front.LocalAddr().String()}); err != nil {
		return err
	}
	<-ctx.Done()
	front.Close()
	back.Close()
	wg.Wait()
	j.emit(map[string]any{"kind": "end", "wall_unix_ns": time.Now().UnixNano()})
	return j.err
}

type clientConfig struct {
	Mode           string  `json:"mode"`
	Address        string  `json:"address"`
	SOCKS          string  `json:"socks"`
	Origin         string  `json:"origin"`
	ServerName     string  `json:"server_name"`
	Pin            string  `json:"pin"`
	CAFile         string  `json:"ca_file"`
	ECHFile        string  `json:"ech_file"`
	Output         string  `json:"output"`
	DurationMS     int     `json:"duration_ms"`
	RPS            float64 `json:"rps"`
	HTTPBytes      int     `json:"http_bytes"`
	SSEIntervalMS  int     `json:"sse_interval_ms"`
	BackgroundMbps float64 `json:"background_mbps"`
	Seed           uint64  `json:"seed"`
}

func client(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	path := fs.String("config", "", "private experiment configuration")
	fs.Parse(args)
	b, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var c clientConfig
	if err = json.Unmarshal(b, &c); err != nil {
		return err
	}
	if c.DurationMS < 500 || c.RPS <= 0 || c.HTTPBytes < 1 || c.SSEIntervalMS < 5 || c.BackgroundMbps <= 0 {
		return errors.New("invalid workload")
	}
	j, file, err := openJournal(c.Output)
	if err != nil {
		return err
	}
	defer file.Close()
	var hc *http.Client
	var base string
	if c.Mode == "native" {
		ech, e := os.ReadFile(c.ECHFile)
		if e != nil {
			return e
		}
		pem, e := os.ReadFile(c.CAFile)
		if e != nil {
			return e
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("invalid fixture CA")
		}
		tc, e := carrier.WebClientTLS(carrier.WebTLSClientOptions{ServerName: c.ServerName, PinSHA256: c.Pin, RootCAs: roots, NextProtos: []string{"h3"}, ECHConfigList: ech})
		if e != nil {
			return e
		}
		dctx, cancel := context.WithTimeout(parent, 3*time.Second)
		conn, e := quic.DialAddr(dctx, c.Address, tc, carrier.WebQUICConfig())
		cancel()
		if e != nil {
			return e
		}
		defer conn.CloseWithError(0, "")
		tr := &http3.Transport{DisableCompression: true, MaxResponseHeaderBytes: 16 << 10}
		defer tr.Close()
		hc = &http.Client{Transport: tr.NewClientConn(conn)}
		base = "https://" + c.ServerName
		j.emit(map[string]any{"kind": "transport", "ech_accepted": conn.ConnectionState().TLS.ECHAccepted, "alpn": conn.ConnectionState().TLS.NegotiatedProtocol})
	} else if c.Mode == "proxy" {
		tr := &http.Transport{DisableCompression: true, MaxIdleConns: 16, MaxIdleConnsPerHost: 16,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return bench.DialSOCKS5(ctx, c.SOCKS, address, 3*time.Second)
			},
		}
		defer tr.CloseIdleConnections()
		hc = &http.Client{Transport: tr}
		base = c.Origin
	} else {
		return errors.New("mode must be native or proxy")
	}
	// Same readiness request for both applications; dataset excludes this phase.
	hctx, hcancel := context.WithTimeout(parent, 3*time.Second)
	hreq, _ := http.NewRequestWithContext(hctx, "GET", base+"/health", nil)
	resp, err := hc.Do(hreq)
	if err != nil {
		hcancel()
		return err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	hcancel()
	if err != nil || resp.StatusCode != 200 || string(body) != "pxbench fixture\n" {
		return errors.New("fixture health mismatch")
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(c.DurationMS)*time.Millisecond)
	defer cancel()
	start := time.Now()
	j.emit(map[string]any{"kind": "workload_start", "duration_ms": c.DurationMS, "seed": c.Seed, "rps": c.RPS, "http_bytes": c.HTTPBytes, "sse_interval_ms": c.SSEIntervalMS, "background_mbps": c.BackgroundMbps})
	var wg sync.WaitGroup
	var ops sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewPCG(c.Seed, 0x7139246))
		next := start
		for seq := 0; wait(ctx, next); seq++ {
			due := next
			next = next.Add(time.Duration((0.75 + rng.Float64()*.5) / c.RPS * float64(time.Second)))
			ops.Add(1)
			go func(seq int) {
				defer ops.Done()
				rctx, done := context.WithTimeout(ctx, 2*time.Second)
				defer done()
				req, _ := http.NewRequestWithContext(rctx, "POST", base+"/small?bytes="+strconv.Itoa(c.HTTPBytes), bytes.NewReader([]byte("probe")))
				began := time.Now()
				r, e := hc.Do(req)
				var n int
				ttfb := time.Since(began).Seconds() * 1000
				if e == nil {
					b, re := io.ReadAll(r.Body)
					r.Body.Close()
					e = re
					n = len(b)
					if e == nil && (r.StatusCode != 200 || n != c.HTTPBytes || !valid(b, 0)) {
						e = errors.New("response integrity mismatch")
					}
				}
				status := "success"
				if e != nil {
					status = "failure"
					if ctx.Err() != nil {
						status = "censored"
					} else if rctx.Err() != nil {
						status = "timeout"
					}
				}
				j.emit(map[string]any{"kind": "http", "seq": seq, "status": status, "bytes": n, "latency_ms": time.Since(began).Seconds() * 1000, "scheduled_latency_ms": time.Since(due).Seconds() * 1000, "ttfb_ms": ttfb})
			}(seq)
		}
	}()
	go func() {
		defer wg.Done()
		req, _ := http.NewRequestWithContext(ctx, "GET", base+"/sse?interval="+strconv.Itoa(c.SSEIntervalMS)+"ms", nil)
		began := time.Now()
		r, e := hc.Do(req)
		if e != nil {
			j.emit(map[string]any{"kind": "sse_connect", "status": "failure"})
			return
		}
		defer r.Body.Close()
		j.emit(map[string]any{"kind": "sse_connect", "status": "success", "latency_ms": time.Since(began).Seconds() * 1000})
		scan := bufio.NewScanner(r.Body)
		last := time.Now()
		expect := int64(0)
		for scan.Scan() {
			line := scan.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var tok struct {
				Seq              int64  `json:"seq"`
				Payload          string `json:"payload"`
				GeneratedElapsed int64  `json:"generated_elapsed_ns"`
			}
			if e := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &tok); e != nil {
				j.emit(map[string]any{"kind": "sse_integrity_error"})
				continue
			}
			payloadValid := tok.Payload == "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+-"
			if !payloadValid {
				j.emit(map[string]any{"kind": "sse_integrity_error"})
			}
			now := time.Now()
			j.emit(map[string]any{"kind": "sse_token", "seq": tok.Seq, "sequence_ok": tok.Seq == expect, "payload_valid": payloadValid, "bytes": len(tok.Payload), "gap_ms": now.Sub(last).Seconds() * 1000, "source_elapsed_ns": tok.GeneratedElapsed})
			expect = tok.Seq + 1
			last = now
		}
		status := "unexpected_end"
		if ctx.Err() != nil {
			status = "censored"
		}
		j.emit(map[string]any{"kind": "sse_end", "status": status, "terminal_gap_ms": time.Since(last).Seconds() * 1000})
	}()
	go func() {
		defer wg.Done()
		req, _ := http.NewRequestWithContext(ctx, "GET", base+"/download?mbps="+strconv.FormatFloat(c.BackgroundMbps, 'f', 3, 64), nil)
		r, e := hc.Do(req)
		if e != nil {
			j.emit(map[string]any{"kind": "download", "status": "failure", "bytes": 0})
			return
		}
		defer r.Body.Close()
		b := make([]byte, 32768)
		offset := int64(0)
		ok := true
		for {
			n, er := r.Body.Read(b)
			if n > 0 {
				if !valid(b[:n], offset) {
					ok = false
				}
				offset += int64(n)
			}
			if er != nil {
				break
			}
		}
		status := "unexpected_end"
		if ctx.Err() != nil {
			status = "censored"
		}
		if !ok {
			status = "integrity_error"
		}
		j.emit(map[string]any{"kind": "download", "status": status, "bytes": offset})
	}()
	wg.Wait()
	ops.Wait()
	j.emit(map[string]any{"kind": "workload_end", "elapsed_ms": time.Since(start).Seconds() * 1000, "wall_unix_ns": time.Now().UnixNano()})
	return j.err
}

func valid(b []byte, offset int64) bool {
	for i, v := range b {
		if v != byte((((offset+int64(i))%251)*31+17)%251) {
			return false
		}
	}
	return true
}

func wait(ctx context.Context, due time.Time) bool {
	if ctx.Err() != nil {
		return false
	}
	d := time.Until(due)
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return ctx.Err() == nil
	}
}
