package cover

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testPath = "/api/sync"
	testURI  = "https://cover.example/api/sync?carrier=0123456789abcdef0123456789abcdef&stream=1"
	testTime = int64(1_700_000_000)
)

// Use actual handshakes: a manually populated tls.ConnectionState does not
// contain the private exporter state and cannot test connection binding.
func tlsPair(t testing.TB) (client, server tls.ConnectionState) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"cover.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cl := tls.Client(a, &tls.Config{
		ServerName: "cover.example", RootCAs: roots,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
	})
	srv := tls.Server(b, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
		SessionTicketsDisabled: true,
	})
	done := make(chan error, 1)
	go func() { done <- srv.HandshakeContext(ctx) }()
	if err := cl.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	client, server = cl.ConnectionState(), srv.ConnectionState()
	ck, err := keyMaterial(&client)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := keyMaterial(&server)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ck, sk) {
		t.Fatal("client and server exporters differ")
	}
	return client, server
}

func newTestGate(t testing.TB, cfg Config) *Gate {
	t.Helper()
	if cfg.Path == "" {
		cfg.Path = testPath
	}
	g, err := NewGate(bytes.Repeat([]byte{0x42}, 32), cfg)
	if err != nil {
		t.Fatal(err)
	}
	g.now = func() time.Time { return time.Unix(testTime, 0) }
	return g
}

func clientRequest(t testing.TB) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, testURI, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func signedRequest(t testing.TB, g *Gate, state *tls.ConnectionState) *http.Request {
	t.Helper()
	r := clientRequest(t)
	if err := g.SignRequest(r, state); err != nil {
		t.Fatal(err)
	}
	return r
}

// Model the URL and :authority fields produced by a real origin HTTP server.
func serverRequest(r *http.Request, state *tls.ConnectionState) *http.Request {
	s := r.Clone(context.Background())
	if s.Host == "" {
		s.Host = s.URL.Host
	}
	s.URL.Scheme, s.URL.Host = "", ""
	s.RequestURI = s.URL.RequestURI()
	s.TLS = state
	return s
}

func TestGateExplicitTLSStateAndKeyCopy(t *testing.T) {
	client, server := tlsPair(t)
	key := bytes.Repeat([]byte{0x42}, 32)
	signer, err := NewGate(key, Config{Path: testPath})
	if err != nil {
		t.Fatal(err)
	}
	signer.now = func() time.Time { return time.Unix(testTime, 0) }
	key[0] ^= 0xff
	gate := newTestGate(t, Config{})
	r := clientRequest(t)
	r.Host = "" // The client may let its transport derive :authority from URL.Host.
	if r.TLS != nil {
		t.Fatal("client request unexpectedly has TLS state")
	}
	if err := signer.SignRequest(r, &client); err != nil {
		t.Fatal(err)
	}
	if !gate.Authorize(serverRequest(r, &server)) {
		t.Fatal("matched real exporter states did not authenticate")
	}
	if gate.Authorize(serverRequest(r, &server)) {
		t.Fatal("replayed header authenticated")
	}
	if len(r.Header.Get(AuthorizationHeader)) != 83 {
		t.Fatal("unexpected authentication header wire length")
	}
}

func TestGateExporterRejectsOtherConnection(t *testing.T) {
	client, server := tlsPair(t)
	_, otherServer := tlsPair(t)
	g := newTestGate(t, Config{})
	r := signedRequest(t, g, &client)
	if g.Authorize(serverRequest(r, &otherServer)) {
		t.Fatal("captured header authenticated on another TLS connection")
	}
	if len(g.nonces) != 0 || !g.Authorize(serverRequest(r, &server)) {
		t.Fatal("failed connection binding consumed the legitimate nonce")
	}
}

func TestGateRejectsAnotherKey(t *testing.T) {
	client, server := tlsPair(t)
	signer := newTestGate(t, Config{})
	r := serverRequest(signedRequest(t, signer, &client), &server)
	other, err := NewGate(bytes.Repeat([]byte{0x43}, 32), Config{Path: testPath})
	if err != nil {
		t.Fatal(err)
	}
	other.now = signer.now
	if other.Authorize(r) || len(other.nonces) != 0 {
		t.Fatal("another key authenticated or consumed replay state")
	}
}

func TestGateConcurrentReplayAdmitsExactlyOnce(t *testing.T) {
	client, server := tlsPair(t)
	g := newTestGate(t, Config{})
	r := serverRequest(signedRequest(t, g, &client), &server)
	var admitted atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if g.Authorize(r) {
				admitted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := admitted.Load(); got != 1 {
		t.Fatalf("concurrent replay admitted %d requests, want 1", got)
	}
}

func changePayload(t testing.TB, r *http.Request, change func([]byte)) {
	t.Helper()
	p, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(r.Header.Get(AuthorizationHeader), authPrefix))
	if err != nil {
		t.Fatal(err)
	}
	change(p)
	r.Header.Set(AuthorizationHeader, authPrefix+base64.RawURLEncoding.EncodeToString(p))
}

type unreadBody struct{ reads atomic.Int32 }

func (b *unreadBody) Read([]byte) (int, error) {
	b.reads.Add(1)
	return 0, errors.New("authentication must not read the request body")
}
func (*unreadBody) Close() error { return nil }

func TestGateRejectsTamperingBeforeNonceAdmission(t *testing.T) {
	client, server := tlsPair(t)
	signer := newTestGate(t, Config{})
	original := serverRequest(signedRequest(t, signer, &client), &server)
	cases := []struct {
		name string
		edit func(*http.Request)
	}{
		{"method", func(r *http.Request) { r.Method = http.MethodGet }},
		{"authority", func(r *http.Request) { r.Host = "other.example" }},
		{"authority-case", func(r *http.Request) { r.Host = "COVER.example" }},
		{"authority-port", func(r *http.Request) { r.Host += ":443" }},
		{"empty-authority", func(r *http.Request) { r.Host = "" }},
		{"oversized-authority", func(r *http.Request) { r.Host = strings.Repeat("x", maxAuthority+1) }},
		{"non-ascii-authority", func(r *http.Request) { r.Host = "café.example" }},
		{"authority-userinfo", func(r *http.Request) { r.Host = "user@cover.example" }},
		{"query-value", func(r *http.Request) { r.URL.RawQuery += "0"; r.RequestURI = r.URL.RequestURI() }},
		{"query-order", func(r *http.Request) {
			r.URL.RawQuery = "stream=1&carrier=0123456789abcdef0123456789abcdef"
			r.RequestURI = r.URL.RequestURI()
		}},
		{"query-encoding", func(r *http.Request) {
			r.URL.RawQuery = strings.ReplaceAll(r.URL.RawQuery, "stream=1", "stream=%31")
			r.RequestURI = r.URL.RequestURI()
		}},
		{"path", func(r *http.Request) { r.URL.Path += "/"; r.RequestURI = r.URL.RequestURI() }},
		{"escaped-path", func(r *http.Request) { r.URL.RawPath = "/api/%73ync"; r.RequestURI = r.URL.RequestURI() }},
		{"mismatched-request-uri", func(r *http.Request) { r.RequestURI += "&extra=1" }},
		{"fragment", func(r *http.Request) { r.URL.Fragment = "fragment" }},
		{"userinfo", func(r *http.Request) { r.URL.User = url.User("user") }},
		{"opaque-uri", func(r *http.Request) { r.URL.Opaque = "//cover.example/other" }},
		{"oversized-query", func(r *http.Request) { r.URL.RawQuery = strings.Repeat("x", maxRequestURI+1) }},
		{"oversized-raw-path", func(r *http.Request) { r.URL.RawPath = strings.Repeat("x", maxRequestURI+1) }},
		{"nil-url", func(r *http.Request) { r.URL = nil }},
		{"missing-header", func(r *http.Request) { r.Header.Del(AuthorizationHeader) }},
		{"duplicate-header", func(r *http.Request) { r.Header.Add(AuthorizationHeader, r.Header.Get(AuthorizationHeader)) }},
		{"oversized-header", func(r *http.Request) { r.Header.Set(AuthorizationHeader, strings.Repeat("x", 1<<20)) }},
		{"wrong-scheme", func(r *http.Request) {
			r.Header.Set(AuthorizationHeader, "Basic  "+strings.TrimPrefix(r.Header.Get(AuthorizationHeader), authPrefix))
		}},
		{"non-base64", func(r *http.Request) {
			r.Header.Set(AuthorizationHeader, authPrefix+strings.Repeat("!", authValueSize-len(authPrefix)))
		}},
		{"version", func(r *http.Request) { changePayload(t, r, func(p []byte) { p[0]++ }) }},
		{"timestamp", func(r *http.Request) { changePayload(t, r, func(p []byte) { p[8] ^= 1 }) }},
		{"nonce", func(r *http.Request) { changePayload(t, r, func(p []byte) { p[9] ^= 1 }) }},
		{"mac", func(r *http.Request) { changePayload(t, r, func(p []byte) { p[len(p)-1] ^= 1 }) }},
		{"nil-tls", func(r *http.Request) { r.TLS = nil }},
		{"incomplete-tls", func(r *http.Request) { s := *r.TLS; s.HandshakeComplete = false; r.TLS = &s }},
		{"tls-1.2", func(r *http.Request) { s := *r.TLS; s.Version = tls.VersionTLS12; r.TLS = &s }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGate(t, Config{})
			r := original.Clone(context.Background())
			body := &unreadBody{}
			r.Body = body
			tc.edit(r)
			if g.Authorize(r) {
				t.Fatal("tampered request authenticated")
			}
			if body.reads.Load() != 0 || len(g.nonces) != 0 || len(g.expires) != 0 {
				t.Fatal("rejected request read the body or consumed replay state")
			}
			if !g.Authorize(original) {
				t.Fatal("rejected request prevented the original from authenticating")
			}
		})
	}
	if newTestGate(t, Config{}).Authorize(nil) {
		t.Fatal("nil request authenticated")
	}
}

func TestGateClockWindow(t *testing.T) {
	client, server := tlsPair(t)
	for _, offset := range []int64{-31, -30, -1, 0, 1, 30, 31} {
		t.Run((time.Duration(offset) * time.Second).String(), func(t *testing.T) {
			signer := newTestGate(t, Config{})
			signer.now = func() time.Time { return time.Unix(testTime+offset, 0) }
			g := newTestGate(t, Config{})
			r := serverRequest(signedRequest(t, signer, &client), &server)
			want := offset >= -30 && offset <= 30
			if got := g.Authorize(r); got != want {
				t.Fatalf("offset %d: admitted=%v, want %v", offset, got, want)
			}
		})
	}
}

func TestGateCapacityExpiryAndClockRollback(t *testing.T) {
	client, server := tlsPair(t)
	signer := newTestGate(t, Config{})
	g := newTestGate(t, Config{MaxNonces: 2})
	requests := make([]*http.Request, 3)
	for i := range requests {
		requests[i] = serverRequest(signedRequest(t, signer, &client), &server)
	}
	if !g.Authorize(requests[0]) || !g.Authorize(requests[1]) {
		t.Fatal("cache did not admit requests up to capacity")
	}
	if g.Authorize(requests[2]) || g.Authorize(requests[0]) || g.Authorize(requests[1]) {
		t.Fatal("full cache admitted a new request or evicted a live replay entry")
	}
	if len(g.nonces) != 2 || len(g.expires) != 2 {
		t.Fatal("cache exceeded configured capacity")
	}
	g.now = func() time.Time { return time.Unix(testTime+30, 0) }
	if g.Authorize(requests[2]) {
		t.Fatal("inclusive expiry boundary evicted a still-valid entry")
	}
	g.now = func() time.Time { return time.Unix(testTime+31, 0) }
	signer.now = g.now
	fresh := serverRequest(signedRequest(t, signer, &client), &server)
	if !g.Authorize(fresh) || len(g.nonces) != 1 || len(g.expires) != 1 {
		t.Fatal("expired cache entries did not free capacity")
	}
	g.now = func() time.Time { return time.Unix(testTime, 0) }
	if g.Authorize(requests[0]) || g.Authorize(requests[2]) {
		t.Fatal("wall-clock rollback resurrected a removed or previously rejected nonce")
	}
	if len(g.nonces) != 1 {
		t.Fatal("rollback admitted replay state")
	}
}

func TestGateFreshNoncesAndDistinctQueries(t *testing.T) {
	client, server := tlsPair(t)
	g := newTestGate(t, Config{})
	seen := make(map[string]bool)
	for range 128 {
		r := signedRequest(t, g, &client)
		h := r.Header.Get(AuthorizationHeader)
		if seen[h] {
			t.Fatal("signing identical fields reused a nonce")
		}
		seen[h] = true
		if !g.Authorize(serverRequest(r, &server)) {
			t.Fatal("fresh request did not authenticate")
		}
	}
	for _, query := range []string{"carrier=0123456789abcdef0123456789abcdef&stream=0", "stream=18446744073709551615&carrier=abcd", "x=%2f&x=%2F", ""} {
		r := clientRequest(t)
		r.URL.RawQuery = query
		if err := g.SignRequest(r, &client); err != nil {
			t.Fatal(err)
		}
		if !g.Authorize(serverRequest(r, &server)) {
			t.Fatal("query was not bound byte-for-byte")
		}
	}
}

func TestGateRejectsInvalidConfigurationAndSigningState(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewGate(make([]byte, n), Config{Path: testPath}); err == nil {
			t.Fatalf("accepted %d-byte key", n)
		}
	}
	for _, path := range []string{"", "/", "relative", "/a/../b", "/a//b", "/a/", "/a?b", "/a#b", "/%61", "/a\\b", "/a b", "/é", "/a[b", "/a\"b", "/" + strings.Repeat("x", 1024)} {
		if _, err := NewGate(key, Config{Path: path}); err == nil {
			t.Fatalf("accepted invalid path %q", path)
		}
	}
	for _, window := range []time.Duration{-time.Second, time.Millisecond, 1500 * time.Millisecond, 301 * time.Second} {
		if _, err := NewGate(key, Config{Path: testPath, Window: window}); err == nil {
			t.Fatalf("accepted invalid window %s", window)
		}
	}
	for _, n := range []int{-1, MaxNonces + 1} {
		if _, err := NewGate(key, Config{Path: testPath, MaxNonces: n}); err == nil {
			t.Fatalf("accepted invalid nonce capacity %d", n)
		}
	}
	g := newTestGate(t, Config{})
	for _, state := range []*tls.ConnectionState{nil, {}, {Version: tls.VersionTLS12, HandshakeComplete: true}} {
		if err := g.SignRequest(clientRequest(t), state); err == nil {
			t.Fatal("signed without a completed TLS 1.3 connection")
		}
	}
	client, _ := tlsPair(t)
	if err := g.SignRequest(nil, &client); err == nil {
		t.Fatal("signed a nil request")
	}
	g.now = func() time.Time { return time.Unix(-1, 0) }
	if err := g.SignRequest(clientRequest(t), &client); err == nil {
		t.Fatal("signed a pre-epoch timestamp")
	}
}

func TestGateRejectsAuthenticatedTimestampOverflow(t *testing.T) {
	client, server := tlsPair(t)
	g := newTestGate(t, Config{})
	r := signedRequest(t, g, &client)
	exporter, err := keyMaterial(&client)
	if err != nil {
		t.Fatal(err)
	}
	changePayload(t, r, func(p []byte) {
		binary.BigEndian.PutUint64(p[1:9], ^uint64(0))
		copy(p[25:], g.mac(p[:25], exporter, r.Method, r.Host, r.URL.RequestURI()))
	})
	if g.Authorize(serverRequest(r, &server)) || len(g.nonces) != 0 {
		t.Fatal("authenticated timestamp overflow was admitted")
	}
}

func FuzzGateAuthorizationHeader(f *testing.F) {
	client, server := tlsPair(f)
	signer := newTestGate(f, Config{})
	original := serverRequest(signedRequest(f, signer, &client), &server)
	valid := original.Header.Get(AuthorizationHeader)
	for _, value := range []string{"", "Bearer ", valid, valid + "=", strings.Replace(valid, "Bearer", "bearer", 1), authPrefix + strings.Repeat("!", 76)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		g := newTestGate(t, Config{})
		r := original.Clone(context.Background())
		body := &unreadBody{}
		r.Body = body
		r.Header.Set(AuthorizationHeader, value)
		if got := g.Authorize(r); got != (value == valid) {
			t.Fatalf("unexpected authentication outcome for %d-byte header", len(value))
		}
		if body.reads.Load() != 0 {
			t.Fatal("authentication read the body")
		}
		if value != valid && (len(g.nonces) != 0 || len(g.expires) != 0) {
			t.Fatal("rejected input consumed replay state")
		}
	})
}
