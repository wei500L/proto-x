package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"proto-x/internal/bench"
)

type connIDKey struct{}
type origin struct {
	ctx        context.Context
	cancel     context.CancelFunc
	http, echo net.Listener
	srv        *http.Server
	id         atomic.Int64
	logs       *eventLog
	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	wg         sync.WaitGroup
	once       sync.Once
}

func newOrigin(parent context.Context, logs *eventLog) (*origin, error) {
	return newOriginAt(parent, logs, "127.0.0.1:0", "127.0.0.1:0", "", "")
}

// newOriginAt also serves as the instrumented origin in the Linux namespaces.
// Target connection IDs survive carrier replacement and never leave this log.
func newOriginAt(parent context.Context, logs *eventLog, httpAddress, echoAddress, cert, key string) (*origin, error) {
	h, err := net.Listen("tcp4", httpAddress)
	if err != nil {
		return nil, err
	}
	if cert != "" {
		pair, e := tls.LoadX509KeyPair(cert, key)
		if e != nil {
			h.Close()
			return nil, e
		}
		h = tls.NewListener(h, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}})
	}
	e, err := net.Listen("tcp4", echoAddress)
	if err != nil {
		h.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	o := &origin{ctx: ctx, cancel: cancel, http: h, echo: e, logs: logs, conns: make(map[net.Conn]struct{})}
	fixture := bench.FixtureHandler()
	o.srv = &http.Server{ReadHeaderTimeout: 3 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }, ConnContext: func(c context.Context, conn net.Conn) context.Context {
		id := o.id.Add(1)
		logs.record("target_accept", map[string]any{"connection": id, "kind": "http"})
		return context.WithValue(c, connIDKey{}, id)
	}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Context().Value(connIDKey{})
		logs.record("target_request", map[string]any{"connection": id, "path": r.URL.Path, "method": r.Method})
		fixture.ServeHTTP(w, r)
		logs.record("target_request_end", map[string]any{"connection": id, "path": r.URL.Path})
	})}
	o.wg.Add(2)
	go func() { defer o.wg.Done(); _ = o.srv.Serve(h) }()
	go o.serveEcho()
	return o, nil
}
func (o *origin) httpAddress() string { return o.http.Addr().String() }
func (o *origin) echoAddress() string { return o.echo.Addr().String() }
func (o *origin) serveEcho() {
	defer o.wg.Done()
	for {
		c, err := o.echo.Accept()
		if err != nil {
			return
		}
		id := o.id.Add(1)
		o.logs.record("target_accept", map[string]any{"connection": id, "kind": "echo"})
		o.mu.Lock()
		o.conns[c] = struct{}{}
		o.mu.Unlock()
		o.wg.Add(1)
		go func() {
			defer o.wg.Done()
			defer c.Close()
			defer func() { o.mu.Lock(); delete(o.conns, c); o.mu.Unlock() }()
			n, err := io.Copy(c, c)
			o.logs.record("target_echo_end", map[string]any{"connection": id, "bytes": n, "clean_eof": err == nil})
		}()
	}
}
func (o *origin) close() {
	o.once.Do(func() {
		o.cancel()
		o.srv.Close()
		o.echo.Close()
		o.mu.Lock()
		for c := range o.conns {
			c.Close()
		}
		o.mu.Unlock()
		o.wg.Wait()
	})
}
