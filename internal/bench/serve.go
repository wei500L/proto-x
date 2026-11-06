package bench

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ServeConfig struct {
	HTTP  string
	HTTPS string
	Echo  string
	Cert  string
	Key   string
}

// Serve exposes controlled fixtures only. It never initiates traffic to other
// hosts. Bind to loopback unless access from an isolated lab is intentional.
func Serve(ctx context.Context, cfg ServeConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 3)
	var servers []*http.Server
	var listeners []net.Listener
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
		for _, s := range servers {
			s.Close()
		}
	}()
	for _, entry := range []struct {
		addr string
		tls  bool
	}{{cfg.HTTP, false}, {cfg.HTTPS, true}} {
		if entry.addr == "" {
			continue
		}
		if entry.tls && (cfg.Cert == "" || cfg.Key == "") {
			return errors.New("HTTPS fixture requires -cert and -key")
		}
		l, err := net.Listen("tcp", entry.addr)
		if err != nil {
			return err
		}
		listeners = append(listeners, l)
		s := &http.Server{Handler: FixtureHandler(), ReadHeaderTimeout: 3 * time.Second,
			IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
			BaseContext: func(net.Listener) context.Context { return ctx }}
		servers = append(servers, s)
		go func(tls bool) {
			if tls {
				errs <- s.ServeTLS(l, cfg.Cert, cfg.Key)
			} else {
				errs <- s.Serve(l)
			}
		}(entry.tls)
	}
	if cfg.Echo != "" {
		l, err := net.Listen("tcp", cfg.Echo)
		if err != nil {
			return err
		}
		listeners = append(listeners, l)
		go func() { errs <- ServeEcho(ctx, l) }()
	}
	if len(listeners) == 0 {
		return errors.New("at least one fixture listener is required")
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func ServeEcho(ctx context.Context, l net.Listener) error {
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	limit := make(chan struct{}, 128)
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		select {
		case limit <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-limit }()
			defer c.Close()
			stop := context.AfterFunc(ctx, func() { c.Close() })
			defer stop()
			io.Copy(c, c)
		}()
	}
}

func FixtureHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("pxbench fixture\n"))
	})
	small := func(w http.ResponseWriter, r *http.Request) {
		size, err := queryInt(r, "bytes", 1024, 1, 1<<20)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		io.Copy(w, &payloadReader{left: size})
	}
	mux.HandleFunc("GET /small", small)
	mux.HandleFunc("POST /small", small)
	mux.HandleFunc("GET /download", func(w http.ResponseWriter, r *http.Request) {
		size, err := queryInt(r, "bytes", 0, 0, 1<<40)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var mbps float64
		if q := r.URL.Query().Get("mbps"); q != "" {
			mbps, err = strconv.ParseFloat(q, 64)
			if err != nil || math.IsNaN(mbps) || math.IsInf(mbps, 0) || mbps < 0 || mbps > 10000 {
				http.Error(w, "mbps must be 0..10000", http.StatusBadRequest)
				return
			}
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		if size > 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		}
		// A bounded reusable buffer prevents fixture memory growth even when
		// clients stop reading. The request context cancels on disconnect.
		chunkSize := 32 << 10
		if mbps > 0 {
			chunkSize = 4 << 10
			w.Header().Set("X-PXBench-Source-Pacing-Mbps", strconv.FormatFloat(mbps, 'g', -1, 64))
		}
		b := make([]byte, chunkSize)
		var offset int64
		next := time.Now()
		for r.Context().Err() == nil && (size == 0 || offset < size) {
			if mbps > 0 && !waitUntil(r.Context(), next) {
				return
			}
			chunk := b
			if size > 0 && int64(len(chunk)) > size-offset {
				chunk = chunk[:size-offset]
			}
			fillPayload(chunk, offset)
			n, err := w.Write(chunk)
			offset += int64(n)
			if err != nil {
				return
			}
			if mbps > 0 {
				// Only one chunk is immediately eligible. Socket backpressure
				// does not accumulate credits that could burst after a pause.
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				next = time.Now().Add(time.Duration(float64(n) * 8 / (mbps * 1e6) * float64(time.Second)))
			}
		}
	})
	mux.HandleFunc("POST /upload", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 256<<20)
		b := make([]byte, 32<<10)
		var offset int64
		for {
			n, err := r.Body.Read(b)
			if !validPayload(b[:n], offset) {
				http.Error(w, "payload mismatch", http.StatusUnprocessableEntity)
				return
			}
			offset += int64(n)
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, "body read failed", http.StatusBadRequest)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"bytes": offset, "valid": true})
	})
	mux.HandleFunc("GET /sse", serveSSE)
	return mux
}

type sourceToken struct {
	Seq                int64  `json:"seq"`
	ScheduledNS        int64  `json:"scheduled_ns"`
	GeneratedNS        int64  `json:"generated_ns"`
	ScheduledElapsedNS int64  `json:"scheduled_elapsed_ns"`
	GeneratedElapsedNS int64  `json:"generated_elapsed_ns"`
	Payload            string `json:"payload"`
}

const tokenPayload = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+-"

func serveSSE(w http.ResponseWriter, r *http.Request) {
	interval := 50 * time.Millisecond
	if q := r.URL.Query().Get("interval"); q != "" {
		var err error
		interval, err = time.ParseDuration(q)
		if err != nil || interval < 5*time.Millisecond || interval > 10*time.Second {
			http.Error(w, "interval must be 5ms..10s", http.StatusBadRequest)
			return
		}
	}
	f, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	f.Flush()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	// Production cadence is independent of socket flushes for up to 256
	// queued tokens. Overflow is explicit; no source token is silently lost.
	q := make(chan sourceToken, 256)
	var state struct {
		sync.Mutex
		overflow bool
	}
	go func() {
		defer close(q)
		start := time.Now()
		for seq := int64(0); ; seq++ {
			due := start.Add(time.Duration(seq) * interval)
			if !waitUntil(ctx, due) {
				return
			}
			now := time.Now()
			t := sourceToken{Seq: seq, ScheduledNS: due.UnixNano(), GeneratedNS: now.UnixNano(),
				ScheduledElapsedNS: int64(due.Sub(start)), GeneratedElapsedNS: int64(now.Sub(start)), Payload: tokenPayload}
			select {
			case q <- t:
			case <-ctx.Done():
				return
			default:
				state.Lock()
				state.overflow = true
				state.Unlock()
				return
			}
		}
	}()
	for t := range q {
		b, _ := json.Marshal(t)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return
		}
		f.Flush()
	}
	state.Lock()
	overflow := state.overflow
	state.Unlock()
	if overflow {
		io.WriteString(w, "event: error\ndata: {\"error\":\"source_queue_overflow\"}\n\n")
		f.Flush()
	}
}

func queryInt(r *http.Request, key string, fallback, min, max int64) (int64, error) {
	q := strings.TrimSpace(r.URL.Query().Get(key))
	if q == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(q, 10, 64)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s must be %d..%d", key, min, max)
	}
	return n, nil
}

func waitUntil(ctx context.Context, due time.Time) bool {
	if contextEnded(ctx) {
		return false
	}
	d := time.Until(due)
	if d <= 0 {
		return true
	}
	if deadline, ok := ctx.Deadline(); ok {
		d = min(d, time.Until(deadline))
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return !contextEnded(ctx)
	case <-ctx.Done():
		return false
	}
}
