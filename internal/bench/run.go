package bench

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type RunConfig struct {
	Proxy          string        `json:"proxy"`
	HTTPTarget     string        `json:"http_target"`
	EchoTarget     string        `json:"echo_target"`
	Duration       time.Duration `json:"duration_ns"`
	Timeout        time.Duration `json:"request_timeout_ns"`
	RPS            float64       `json:"http_rps"`
	HTTPMethod     string        `json:"http_method"`
	HTTPBytes      int           `json:"http_response_bytes"`
	Concurrency    int           `json:"http_max_concurrency"`
	EchoInterval   time.Duration `json:"echo_interval_ns"`
	SSEInterval    time.Duration `json:"sse_interval_ns"`
	Background     int           `json:"download_workers"`
	BackgroundMbps float64       `json:"download_mbps_per_worker"`
	Uploads        int           `json:"upload_workers"`
	UploadBytes    int64         `json:"upload_chunk_bytes"`
	Output         string        `json:"output"`
	Summary        string        `json:"summary,omitempty"`
	RunID          string        `json:"run_id"`
	CAFile         string        `json:"ca_file,omitempty"`
	InsecureTLS    bool          `json:"insecure_tls"`
	ColdHTTP       bool          `json:"cold_http"`
}

func (c RunConfig) Validate() error {
	if c.Proxy == "" {
		return errors.New("an explicit SOCKS5 -proxy is required (or use -proxy direct for a fixture self-test)")
	}
	if c.Proxy != "direct" {
		if _, _, err := net.SplitHostPort(c.Proxy); err != nil {
			return fmt.Errorf("proxy must be host:port: %w", err)
		}
	}
	u, err := url.Parse(c.HTTPTarget)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("http-target must be an http(s) URL without user information")
	}
	if _, _, err := net.SplitHostPort(c.EchoTarget); err != nil {
		return fmt.Errorf("echo-target must be host:port: %w", err)
	}
	if c.Duration < 100*time.Millisecond || c.Timeout < 10*time.Millisecond || c.Timeout > time.Minute {
		return errors.New("duration must be at least 100ms; timeout must be 10ms..1m")
	}
	if math.IsNaN(c.RPS) || math.IsInf(c.RPS, 0) || c.RPS < 0 || c.RPS > 1000 {
		return errors.New("rps must be 0..1000")
	}
	if c.HTTPMethod != http.MethodPost && c.HTTPMethod != http.MethodGet {
		return errors.New("http-method must be POST or GET")
	}
	if c.HTTPBytes < 1 || c.HTTPBytes > 1<<20 || c.Concurrency < 1 || c.Concurrency > 4096 {
		return errors.New("http-bytes must be 1..1048576; concurrency must be 1..4096")
	}
	if c.EchoInterval < 0 || c.SSEInterval < 0 || (c.SSEInterval > 0 && (c.SSEInterval < 5*time.Millisecond || c.SSEInterval > 10*time.Second)) {
		return errors.New("echo interval must be nonnegative; SSE interval must be 0 (disabled) or 5ms..10s")
	}
	if c.Background < 0 || c.Background > 64 || c.Uploads < 0 || c.Uploads > 64 || c.UploadBytes < 1 || c.UploadBytes > 256<<20 {
		return errors.New("bulk worker count must be 0..64; upload-bytes must be 1..268435456")
	}
	if math.IsNaN(c.BackgroundMbps) || math.IsInf(c.BackgroundMbps, 0) || c.BackgroundMbps < 0 || c.BackgroundMbps > 10000 {
		return errors.New("background-mbps must be 0..10000 (0 disables source pacing)")
	}
	if c.Output == "" || c.RunID == "" {
		return errors.New("output and run-id are required")
	}
	return nil
}

type runner struct {
	cfg       RunConfig
	r         *recorder
	dial      func(context.Context, string, string) (net.Conn, error)
	client    *http.Client
	bulk      *http.Client
	stream    *http.Client
	transport []*http.Transport
}

func Run(parent context.Context, cfg RunConfig) (Summary, error) {
	if cfg.HTTPMethod == "" {
		cfg.HTTPMethod = http.MethodPost
	}
	if err := cfg.Validate(); err != nil {
		return Summary{}, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureTLS} // explicit fixture-only flag
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return Summary{}, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return Summary{}, errors.New("CA file contains no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	r, err := newRecorder(cfg)
	if err != nil {
		return Summary{}, err
	}
	w := &runner{cfg: cfg, r: r}
	w.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("unsupported dial network %q", network)
		}
		if cfg.Proxy == "direct" {
			d := net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}
			return d.DialContext(ctx, "tcp", address)
		}
		return DialSOCKS5(ctx, cfg.Proxy, address, cfg.Timeout)
	}
	makeClient := func(cold bool) *http.Client {
		tr := &http.Transport{Proxy: nil, DialContext: w.dial, TLSClientConfig: tlsConfig.Clone(),
			TLSHandshakeTimeout: cfg.Timeout, ResponseHeaderTimeout: cfg.Timeout,
			MaxIdleConns: 128, MaxIdleConnsPerHost: 64, IdleConnTimeout: 30 * time.Second,
			DisableCompression: true, DisableKeepAlives: cold, ForceAttemptHTTP2: false,
			TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		}
		w.transport = append(w.transport, tr)
		return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	w.client, w.bulk, w.stream = makeClient(cfg.ColdHTTP), makeClient(false), makeClient(false)
	defer func() {
		for _, tr := range w.transport {
			tr.CloseIdleConnections()
		}
	}()
	ctx, cancel := context.WithTimeout(parent, cfg.Duration)
	defer cancel()
	r.record(Event{Kind: "run_start", Detail: map[string]any{
		"config": cfg, "go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH,
		"http_version": "HTTP/1.1", "source_clock_synchronized": false,
		"sse_source_gap_clock":    "monotonic_elapsed_ns",
		"payload_pattern":         "byte(((offset % 251) * 31 + 17) % 251)",
		"sse_source_queue_tokens": 256,
	}})
	var wg sync.WaitGroup
	launch := func(fn func()) { wg.Add(1); go func() { defer wg.Done(); fn() }() }
	if cfg.RPS > 0 {
		launch(func() { w.runHTTP(ctx) })
	}
	if cfg.EchoInterval > 0 {
		launch(func() { w.runEcho(ctx) })
	}
	if cfg.SSEInterval > 0 {
		launch(func() { w.runSSE(ctx) })
	}
	for i := 0; i < cfg.Background; i++ {
		launch(func() { w.runDownload(ctx, i) })
	}
	for i := 0; i < cfg.Uploads; i++ {
		launch(func() { w.runUpload(ctx, i) })
	}
	<-ctx.Done()
	wg.Wait()
	r.record(Event{Kind: "run_end", Status: "success", ElapsedSeconds: time.Since(r.start).Seconds(), Detail: map[string]any{"reason": ctx.Err().Error()}})
	return r.finish()
}

func (w *runner) endpoint(path string, query url.Values) string {
	u, _ := url.Parse(w.cfg.HTTPTarget)
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = query.Encode()
	return u.String()
}

func (w *runner) runHTTP(ctx context.Context) {
	period := time.Duration(float64(time.Second) / w.cfg.RPS)
	start := time.Now()
	limit := make(chan struct{}, w.cfg.Concurrency)
	var wg sync.WaitGroup
	defer wg.Wait()
	for seq := int64(0); ; seq++ {
		due := start.Add(time.Duration(seq) * period)
		if !waitUntil(ctx, due) {
			return
		}
		select {
		case limit <- struct{}{}:
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-limit }()
				w.httpOne(ctx, seq, due)
			}()
		default:
			w.r.record(Event{Kind: "http", Seq: seq, Status: "rejected", ScheduledNS: due.UnixNano(), Error: "client_concurrency_limit"})
		}
	}
}

func (w *runner) httpOne(parent context.Context, seq int64, due time.Time) {
	ctx, cancel := context.WithTimeout(parent, w.cfg.Timeout)
	defer cancel()
	start := time.Now()
	e := Event{Kind: "http", Seq: seq, ScheduledNS: due.UnixNano(), StartedNS: start.UnixNano(), QueueDelayMS: ms(start.Sub(due))}
	var traceMu sync.Mutex
	var firstByte time.Time
	var attempts int
	var reused bool
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { traceMu.Lock(); firstByte = time.Now(); traceMu.Unlock() },
		GotConn: func(info httptrace.GotConnInfo) {
			traceMu.Lock()
			attempts++
			reused = info.Reused
			a := attempts
			traceMu.Unlock()
			w.r.record(Event{Kind: "http_connection", Seq: seq, Connection: int64(a), HTTPReused: info.Reused, Status: "success"})
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			status, detail := outcome(parent, info.Err)
			w.r.record(Event{Kind: "http_write", Seq: seq, Status: status, Error: detail})
		},
	}
	ctx = httptrace.WithClientTrace(ctx, trace)
	// POST is the default even though this controlled fixture has no side
	// effects. net/http may retry GET on a failed reused connection; it will
	// not replay a POST after request bytes have been written. All connection
	// and write attempts are additionally retained as raw events.
	req, _ := http.NewRequestWithContext(ctx, w.cfg.HTTPMethod, w.endpoint("/small", url.Values{"bytes": {strconv.Itoa(w.cfg.HTTPBytes)}}), nil)
	resp, err := w.client.Do(req)
	if err == nil {
		var b []byte
		b, err = io.ReadAll(io.LimitReader(resp.Body, int64(w.cfg.HTTPBytes)+1))
		resp.Body.Close()
		e.Bytes = int64(len(b))
		if err == nil && (resp.StatusCode != 200 || len(b) != w.cfg.HTTPBytes || !validPayload(b, 0)) {
			err = fmt.Errorf("HTTP response integrity failure: status=%d bytes=%d", resp.StatusCode, len(b))
		}
	}
	end := time.Now()
	e.LatencyMS = ms(end.Sub(start))
	e.ScheduledLatencyMS = ms(end.Sub(due))
	traceMu.Lock()
	e.HTTPReused, e.Attempts = reused, attempts
	if !firstByte.IsZero() {
		e.TTFBMS = ms(firstByte.Sub(start))
	}
	traceMu.Unlock()
	e.Status, e.Error = outcome(parent, err)
	w.r.record(e)
}

func (w *runner) runEcho(ctx context.Context) {
	var c net.Conn
	defer func() {
		if c != nil {
			c.Close()
		}
	}()
	var connection int64
	for seq := int64(0); !contextEnded(ctx); seq++ {
		start := time.Now()
		e := Event{Kind: "echo", Seq: seq, StartedNS: start.UnixNano(), Connection: connection}
		opctx, cancel := context.WithTimeout(ctx, w.cfg.Timeout)
		var err error
		if c == nil {
			connection++
			e.Connection = connection
			c, err = w.dial(opctx, "tcp", w.cfg.EchoTarget)
			status, detail := outcome(ctx, err)
			w.r.record(Event{Kind: "echo_connect", Connection: connection, Status: status, Error: detail, LatencyMS: ms(time.Since(start))})
		}
		if err == nil {
			deadline, _ := opctx.Deadline()
			c.SetDeadline(deadline)
			conn := c
			stop := context.AfterFunc(opctx, func() { conn.Close() })
			payload := make([]byte, 64)
			fillPayload(payload, seq*64)
			binary.BigEndian.PutUint64(payload[:8], uint64(seq))
			err = writeAll(c, payload)
			if err == nil {
				got := make([]byte, len(payload))
				_, err = io.ReadFull(c, got)
				if err == nil && !bytes.Equal(payload, got) {
					err = errors.New("echo payload or sequence mismatch")
				}
			}
			stop()
			if err == nil {
				e.Bytes = int64(len(payload))
			}
		}
		cancel()
		e.LatencyMS = ms(time.Since(start))
		e.Status, e.Error = outcome(ctx, err)
		w.r.record(e)
		if err != nil && c != nil {
			c.Close()
			c = nil
		}
		if !waitUntil(ctx, start.Add(w.cfg.EchoInterval)) {
			return
		}
	}
}

func (w *runner) runSSE(ctx context.Context) {
	var connection int64
	var lastReceive time.Time
	streamStart := time.Now()
	defer func() {
		last := lastReceive
		if last.IsZero() {
			last = streamStart
		}
		w.r.record(Event{Kind: "sse_run_tail", Status: "censored", TerminalGapMS: ms(time.Since(last))})
	}()
	for !contextEnded(ctx) {
		connection++
		start := time.Now()
		sctx, cancel := context.WithCancel(ctx)
		var idleExpired atomic.Bool
		watchdog := time.AfterFunc(w.cfg.Timeout, func() { idleExpired.Store(true); cancel() })
		req, _ := http.NewRequestWithContext(sctx, http.MethodGet, w.endpoint("/sse", url.Values{"interval": {w.cfg.SSEInterval.String()}}), nil)
		resp, err := w.stream.Do(req)
		if err == nil && resp.StatusCode != 200 {
			err = fmt.Errorf("SSE response status %d", resp.StatusCode)
			resp.Body.Close()
		}
		status, detail := outcome(ctx, err)
		if err != nil && idleExpired.Load() && !contextEnded(ctx) {
			status, detail = "timeout", "SSE connect/header inactivity timeout"
		}
		w.r.record(Event{Kind: "sse_connect", Connection: connection, Status: status, Error: detail, LatencyMS: ms(time.Since(start))})
		if err == nil {
			watchdog.Reset(w.cfg.Timeout)
			scan := bufio.NewScanner(resp.Body)
			scan.Buffer(make([]byte, 4096), 64<<10)
			var expected, previousSource int64
			var lastThisConnection time.Time
			for scan.Scan() {
				line := scan.Text()
				if !strings.HasPrefix(line, "data: ") {
					continue
				}
				var token sourceToken
				if err = json.Unmarshal([]byte(line[6:]), &token); err != nil || token.Payload != tokenPayload || token.GeneratedElapsedNS < token.ScheduledElapsedNS || token.GeneratedElapsedNS <= 0 {
					err = errors.New("invalid SSE payload or explicit source error: " + line[6:])
					w.r.record(Event{Kind: "sse_source_error", Connection: connection, Status: "failure", Error: err.Error()})
					break
				}
				now := time.Now()
				e := Event{Kind: "sse_token", Seq: token.Seq, Connection: connection, Status: "success", AtNS: now.UnixNano(), Bytes: int64(len(token.Payload)),
					SourceScheduledNS: token.ScheduledNS, SourceGeneratedNS: token.GeneratedNS,
					SourceScheduledElapsedNS: token.ScheduledElapsedNS, SourceGeneratedElapsedNS: token.GeneratedElapsedNS,
					SourceDelayMS: float64(token.GeneratedElapsedNS-token.ScheduledElapsedNS) / 1e6}
				if token.Seq != expected {
					e.Status = "failure"
					e.Error = "SSE sequence mismatch"
					if token.Seq > expected {
						e.Missing = token.Seq - expected
					} else {
						e.Duplicate = true
					}
				}
				if !lastReceive.IsZero() {
					e.ReceiveGapMS = ms(now.Sub(lastReceive))
				}
				if previousSource != 0 {
					e.SourceGapMS = float64(token.GeneratedElapsedNS-previousSource) / 1e6
					e.ExcessGapMS = math.Max(0, e.ReceiveGapMS-e.SourceGapMS)
				} else if !lastReceive.IsZero() {
					e.Detail = map[string]any{"cross_connection_gap": true}
				}
				w.r.record(e)
				lastReceive, lastThisConnection, previousSource = now, now, token.GeneratedElapsedNS
				expected = token.Seq + 1
				watchdog.Reset(w.cfg.Timeout)
			}
			if err == nil {
				err = scan.Err()
			}
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			resp.Body.Close()
			status, detail = outcome(ctx, err)
			if idleExpired.Load() && !contextEnded(ctx) {
				status, detail = "timeout", "SSE inactivity timeout"
			}
			terminal := time.Since(start)
			if !lastThisConnection.IsZero() {
				terminal = time.Since(lastThisConnection)
			}
			w.r.record(Event{Kind: "sse_end", Connection: connection, Status: status, Error: detail, TerminalGapMS: ms(terminal)})
		}
		watchdog.Stop()
		cancel()
		if !waitUntil(ctx, time.Now().Add(100*time.Millisecond)) {
			return
		}
	}
}

func (w *runner) runDownload(ctx context.Context, worker int) {
	var connection int64
	for !contextEnded(ctx) {
		connection++
		start := time.Now()
		query := url.Values{}
		if w.cfg.BackgroundMbps > 0 {
			query.Set("mbps", strconv.FormatFloat(w.cfg.BackgroundMbps, 'g', -1, 64))
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, w.endpoint("/download", query), nil)
		resp, err := w.bulk.Do(req)
		var total, intervalBytes int64
		lastSample := start
		if err == nil && resp.StatusCode != 200 {
			err = fmt.Errorf("download response status %d", resp.StatusCode)
			resp.Body.Close()
		}
		if err == nil {
			b := make([]byte, 32<<10)
			for {
				var n int
				n, err = resp.Body.Read(b)
				if !validPayload(b[:n], total) {
					err = errors.New("download payload mismatch")
					break
				}
				total += int64(n)
				intervalBytes += int64(n)
				now := time.Now()
				if now.Sub(lastSample) >= time.Second {
					w.r.record(Event{Kind: "download_interval", Worker: worker, Connection: connection, Status: "success", Bytes: intervalBytes, ElapsedSeconds: now.Sub(lastSample).Seconds()})
					lastSample, intervalBytes = now, 0
				}
				if err != nil {
					break
				}
			}
			resp.Body.Close()
		}
		status, detail := outcome(ctx, err)
		w.r.record(Event{Kind: "download_end", Worker: worker, Connection: connection, Status: status, Error: detail, Bytes: total, LatencyMS: ms(time.Since(start)), ElapsedSeconds: time.Since(start).Seconds()})
		if !waitUntil(ctx, time.Now().Add(100*time.Millisecond)) {
			return
		}
	}
}

func (w *runner) runUpload(ctx context.Context, worker int) {
	for seq := int64(0); !contextEnded(ctx); seq++ {
		start := time.Now()
		// Upload completion timeout is proportional to chunk size at a
		// conservative 64 kbit/s, capped by the run context. It is not the
		// interactive request timeout.
		uctx, cancel := context.WithTimeout(ctx, w.cfg.Timeout+time.Duration(float64(w.cfg.UploadBytes)*8/64000*float64(time.Second)))
		req, _ := http.NewRequestWithContext(uctx, http.MethodPost, w.endpoint("/upload", nil), &payloadReader{left: w.cfg.UploadBytes})
		req.ContentLength = w.cfg.UploadBytes
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := w.bulk.Do(req)
		var reply struct {
			Bytes int64 `json:"bytes"`
			Valid bool  `json:"valid"`
		}
		if err == nil {
			err = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&reply)
			resp.Body.Close()
			if err == nil && (resp.StatusCode != 200 || !reply.Valid || reply.Bytes != w.cfg.UploadBytes) {
				err = errors.New("upload acknowledgement mismatch")
			}
		}
		cancel()
		status, detail := outcome(ctx, err)
		w.r.record(Event{Kind: "upload", Worker: worker, Seq: seq, Status: status, Error: detail, Bytes: reply.Bytes, LatencyMS: ms(time.Since(start))})
		if err != nil && !waitUntil(ctx, time.Now().Add(100*time.Millisecond)) {
			return
		}
	}
}

func outcome(parent context.Context, err error) (string, string) {
	if err == nil {
		return "success", ""
	}
	if contextEnded(parent) {
		return "censored", err.Error()
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return "timeout", err.Error()
	}
	return "failure", err.Error()
}

// A socket deadline can expire before the context timer goroutine publishes
// ctx.Err(). Deadline retains a monotonic component, so this check survives
// wall-clock steps and prevents false timeouts or new work after the run ends.
func contextEnded(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	deadline, ok := ctx.Deadline()
	return ok && time.Until(deadline) <= 0
}
