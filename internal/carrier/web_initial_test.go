package carrier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proto-x/internal/cover"
	"proto-x/internal/wire"
)

// The HTTP peer intentionally withholds 200 until the first application record
// arrives. This detects an extra request/response round trip (or deadlock) in
// control setup AND in new flow setup, independently of WebHub's flush order.
func TestWebInitialBodyDoesNotWaitForResponse(t *testing.T) {
	gate, err := cover.NewGate(make([]byte, 32), cover.Config{Path: "/api/sync"})
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan wire.Frame, 2)
	serverErrors := make(chan error, 2)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !gate.Authorize(r) {
			http.NotFound(w, r)
			return
		}
		codec := newWebLink("h2", false, 127)
		f, e := codec.readRecord(r.Body)
		if e != nil {
			serverErrors <- e
			return
		}
		observed <- f
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		if f.ID == 0 {
			_ = codec.writeRecord(w, wire.Frame{Kind: wire.Welcome, Payload: []byte("accepted")})
			_ = http.NewResponseController(w).Flush()
		}
		<-r.Context().Done()
	})
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	ts.StartTLS()
	defer ts.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ts.Certificate())
	cfg, err := WebClientTLS(WebTLSClientOptions{ServerName: "127.0.0.1", RootCAs: roots, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	hello := wire.Frame{Kind: wire.Hello, Payload: []byte("hello")}
	l, err := DialWeb(ctx, WebOptions{Network: "h2", Address: strings.TrimPrefix(ts.URL, "https://"),
		Authority: "127.0.0.1", Path: "/api/sync", TLSConfig: cfg, Gate: gate, Padding: 127, Initial: &hello})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.SetHandshakeDeadline(time.Now().Add(time.Second))
	if f, e := l.HandshakeRead(); e != nil || f.Kind != wire.Welcome {
		t.Fatalf("initial HELLO: kind=%d err=%v", f.Kind, e)
	}
	l.SetHandshakeDeadline(time.Time{})
	l.Start()
	done := make(chan error, 1)
	go func() { done <- l.Send(wire.Frame{Kind: wire.Open, ID: 1, Payload: []byte("unused.test:80")}) }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("OPEN waited for HTTP response instead of being sent in the request")
	}
	for _, want := range []uint8{wire.Hello, wire.Open} {
		select {
		case f := <-observed:
			if f.Kind != want {
				t.Fatalf("got first kind %d, want %d", f.Kind, want)
			}
		case e := <-serverErrors:
			t.Fatal(e)
		default:
			t.Fatal(io.ErrUnexpectedEOF)
		}
	}
}
