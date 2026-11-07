package carrier

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const webInnerName = "origin.hidden.test"
const webPublicName = "front.cover.test"

type webTestPKI struct {
	root *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newWebTestPKI(t *testing.T) webTestPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Local web TLS test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return webTestPKI{root: root, key: key, pool: pool}
}

func (p webTestPKI) certificate(t *testing.T, expired bool, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if expired {
		tmpl.NotAfter = time.Now().Add(-time.Minute)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.root, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, p.root.Raw}, PrivateKey: key}
}

func webTestPin(cert tls.Certificate) string {
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:])
}

func mustWebClient(t *testing.T, opts WebTLSClientOptions) *tls.Config {
	t.Helper()
	config, err := WebClientTLS(opts)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func mustWebServer(t *testing.T, opts WebTLSServerOptions) *tls.Config {
	t.Helper()
	config, err := WebServerTLS(opts)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

type webRecordingConn struct {
	net.Conn
	mu   sync.Mutex
	sent []byte
}

func (c *webRecordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.sent = append(c.sent, p[:n]...)
	c.mu.Unlock()
	return n, err
}

type webTestExchange struct {
	clientState, serverState         tls.ConnectionState
	clientHandshake, serverHandshake error
	clientIO, serverIO               error
	clientWritten, serverRead        int
	wire                             []byte
}

// webTLSExchange uses real TCP and crypto/tls. The small echo is a TLS-layer
// check; TestWebECHHTTP2 separately verifies an actual HTTP/2 exchange.
func webTLSExchange(t *testing.T, clientConfig, serverConfig *tls.Config) webTestExchange {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	message := []byte("web TLS exact echo")
	serverDone := make(chan webTestExchange, 1)
	go func() {
		var result webTestExchange
		conn, err := ln.Accept()
		if err != nil {
			result.serverHandshake = err
			serverDone <- result
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		server := tls.Server(conn, serverConfig)
		result.serverHandshake = server.HandshakeContext(ctx)
		result.serverState = server.ConnectionState()
		if result.serverHandshake == nil {
			buf := make([]byte, len(message))
			result.serverRead, result.serverIO = io.ReadFull(server, buf)
			if result.serverIO == nil {
				_, result.serverIO = server.Write(buf)
			}
		}
		serverDone <- result
	}()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	recorder := &webRecordingConn{Conn: conn}
	client := tls.Client(recorder, clientConfig)
	var result webTestExchange
	result.clientHandshake = client.HandshakeContext(ctx)
	result.clientState = client.ConnectionState()
	if result.clientHandshake == nil {
		result.clientWritten, result.clientIO = client.Write(message)
		if result.clientIO == nil {
			buf := make([]byte, len(message))
			_, result.clientIO = io.ReadFull(client, buf)
			if result.clientIO == nil && !bytes.Equal(buf, message) {
				result.clientIO = errors.New("TLS echo bytes changed")
			}
		}
	}
	_ = conn.Close()
	select {
	case serverResult := <-serverDone:
		result.serverState, result.serverHandshake = serverResult.serverState, serverResult.serverHandshake
		result.serverRead, result.serverIO = serverResult.serverRead, serverResult.serverIO
	case <-ctx.Done():
		t.Fatal("TLS fixture did not stop:", ctx.Err())
	}
	recorder.mu.Lock()
	result.wire = bytes.Clone(recorder.sent)
	recorder.mu.Unlock()
	return result
}

func requireWebSuccess(t *testing.T, result webTestExchange, ech bool) {
	t.Helper()
	if result.clientHandshake != nil || result.serverHandshake != nil || result.clientIO != nil || result.serverIO != nil {
		t.Fatalf("handshake client=%v server=%v; application client=%v server=%v",
			result.clientHandshake, result.serverHandshake, result.clientIO, result.serverIO)
	}
	if result.clientWritten == 0 || result.clientWritten != result.serverRead {
		t.Fatalf("application byte mismatch: sent=%d received=%d", result.clientWritten, result.serverRead)
	}
	for _, state := range []tls.ConnectionState{result.clientState, result.serverState} {
		if state.Version != tls.VersionTLS13 || state.ECHAccepted != ech || state.NegotiatedProtocol != "h2" {
			t.Fatalf("TLS state: version=%x ALPN=%q ECH=%v", state.Version, state.NegotiatedProtocol, state.ECHAccepted)
		}
	}
}

func TestWebTLSCertificatePolicy(t *testing.T) {
	pki := newWebTestPKI(t)
	cert := pki.certificate(t, false, webInnerName)
	expired := pki.certificate(t, true, webInnerName)
	for _, tc := range []struct {
		name    string
		cert    tls.Certificate
		roots   *x509.CertPool
		host    string
		pin     string
		pinOnly bool
		wantErr string
	}{
		{name: "CA and hostname", cert: cert, roots: pki.pool, host: webInnerName},
		{name: "CA hostname and pin", cert: cert, roots: pki.pool, host: webInnerName, pin: webTestPin(cert)},
		{name: "wrong extra pin", cert: cert, roots: pki.pool, host: webInnerName, pin: strings.Repeat("00", 32), wantErr: "pin mismatch"},
		{name: "pin does not replace CA", cert: cert, roots: x509.NewCertPool(), host: webInnerName, pin: webTestPin(cert), wantErr: "unknown authority"},
		{name: "pin does not replace hostname", cert: cert, roots: pki.pool, host: "wrong.hidden.test", pin: webTestPin(cert), wantErr: "certificate is valid for"},
		{name: "pin does not replace validity", cert: expired, roots: pki.pool, host: webInnerName, pin: webTestPin(expired), wantErr: "expired"},
		{name: "explicit pin only", cert: expired, roots: x509.NewCertPool(), host: "wrong.hidden.test", pin: webTestPin(expired), pinOnly: true},
		{name: "pin only still checks pin", cert: cert, host: webInnerName, pin: strings.Repeat("00", 32), pinOnly: true, wantErr: "pin mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := mustWebClient(t, WebTLSClientOptions{ServerName: tc.host, RootCAs: tc.roots, PinSHA256: tc.pin, ExperimentalPinOnly: tc.pinOnly, NextProtos: []string{"h2"}})
			server := mustWebServer(t, WebTLSServerOptions{Certificates: []tls.Certificate{tc.cert}, NextProtos: []string{"h2"}})
			result := webTLSExchange(t, client, server)
			if tc.wantErr == "" {
				requireWebSuccess(t, result, false)
			} else if result.clientHandshake == nil || !strings.Contains(result.clientHandshake.Error(), tc.wantErr) || result.serverRead != 0 {
				t.Fatalf("wanted %q and zero application bytes, got client=%v serverRead=%d", tc.wantErr, result.clientHandshake, result.serverRead)
			}
		})
	}
}

func TestWebTLSResumptionStillChecksPin(t *testing.T) {
	pki := newWebTestPKI(t)
	cert := pki.certificate(t, false, webInnerName)
	server := mustWebServer(t, WebTLSServerOptions{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	opts := WebTLSClientOptions{ServerName: webInnerName, RootCAs: pki.pool, PinSHA256: webTestPin(cert), NextProtos: []string{"h2"}}
	client := mustWebClient(t, opts)
	client.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	first := webTLSExchange(t, client, server)
	requireWebSuccess(t, first, false)
	second := webTLSExchange(t, client, server)
	requireWebSuccess(t, second, false)
	if !second.clientState.DidResume || !second.serverState.DidResume {
		t.Fatal("fixture did not exercise TLS resumption")
	}
	opts.PinSHA256 = strings.Repeat("00", 32)
	wrongPin := mustWebClient(t, opts)
	wrongPin.ClientSessionCache = client.ClientSessionCache
	rejected := webTLSExchange(t, wrongPin, server)
	if rejected.clientHandshake == nil || !strings.Contains(rejected.clientHandshake.Error(), "pin mismatch") || rejected.serverRead != 0 {
		t.Fatalf("resumed pin bypass: client=%v serverRead=%d", rejected.clientHandshake, rejected.serverRead)
	}
	t.Log("TLS resumption succeeded with the original pin and failed with a changed pin; zero rejected application bytes")
}

// Independently read the observed TLS record and ClientHello vectors. These
// assertions inspect sent bytes, rather than the server's decrypted hello.
func webObservedHello(t *testing.T, wire []byte) (string, bool, []byte) {
	t.Helper()
	var handshake []byte
	for len(wire) >= 5 {
		n := int(binary.BigEndian.Uint16(wire[3:5]))
		if len(wire) < 5+n {
			t.Fatal("incomplete captured TLS record")
		}
		if wire[0] == 22 {
			handshake = append(handshake, wire[5:5+n]...)
		}
		wire = wire[5+n:]
		if len(handshake) >= 4 {
			n = int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if len(handshake) >= n+4 {
				handshake = handshake[:n+4]
				break
			}
		}
	}
	if len(handshake) < 38 || handshake[0] != 1 {
		t.Fatal("no complete ClientHello captured")
	}
	r := bytes.NewReader(handshake[4:])
	var header [34]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		t.Fatal(err)
	}
	_ = webObservedVector(t, r, 1) // legacy session id
	_ = webObservedVector(t, r, 2) // cipher suites
	_ = webObservedVector(t, r, 1) // compression
	extensions := bytes.NewReader(webObservedVector(t, r, 2))
	var name string
	var ech bool
	for extensions.Len() > 0 {
		var kind uint16
		if err := binary.Read(extensions, binary.BigEndian, &kind); err != nil {
			t.Fatal(err)
		}
		data := webObservedVector(t, extensions, 2)
		if kind == 0xfe0d {
			ech = true
		}
		if kind == 0 {
			names := bytes.NewReader(webObservedVector(t, bytes.NewReader(data), 2))
			nameType, err := names.ReadByte()
			if err != nil || nameType != 0 {
				t.Fatal("unexpected SNI name type")
			}
			name = string(webObservedVector(t, names, 2))
		}
	}
	return name, ech, handshake
}

func webObservedVector(t *testing.T, r *bytes.Reader, width int) []byte {
	t.Helper()
	var size uint16
	if width == 1 {
		value, err := r.ReadByte()
		if err != nil {
			t.Fatal(err)
		}
		size = uint16(value)
	} else if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestWebECHTLSAcceptanceRejectionAndVisibleName(t *testing.T) {
	pki := newWebTestPKI(t)
	cert := pki.certificate(t, false, webInnerName, webPublicName)
	list, key, err := GenerateWebECH(webPublicName)
	if err != nil {
		t.Fatal(err)
	}
	clientOpts := WebTLSClientOptions{ServerName: webInnerName, RootCAs: pki.pool, NextProtos: []string{"h2"}, ECHConfigList: list}
	serverOpts := WebTLSServerOptions{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}, ECHKeys: []tls.EncryptedClientHelloKey{key}}
	t.Run("accepted and outer name visible", func(t *testing.T) {
		result := webTLSExchange(t, mustWebClient(t, clientOpts), mustWebServer(t, serverOpts))
		requireWebSuccess(t, result, true)
		outerName, echExtension, hello := webObservedHello(t, result.wire)
		if outerName != webPublicName || !echExtension || bytes.Contains(hello, []byte(webInnerName)) {
			t.Fatalf("visible hello: outerName=%q ECH=%v privateNameVisible=%v", outerName, echExtension, bytes.Contains(hello, []byte(webInnerName)))
		}
		if result.serverState.ServerName != webInnerName {
			t.Fatalf("server did not recover the inner name: %q", result.serverState.ServerName)
		}
		t.Logf("TLS 1.3 ECH accepted on both endpoints; visible outer SNI=%s, inner SNI=%s only after decryption; echoed=%d bytes", outerName, result.serverState.ServerName, result.serverRead)
	})
	t.Run("ordinary visitor stays ordinary", func(t *testing.T) {
		opts := clientOpts
		opts.ECHConfigList = nil
		result := webTLSExchange(t, mustWebClient(t, opts), mustWebServer(t, serverOpts))
		requireWebSuccess(t, result, false)
		name, _, hello := webObservedHello(t, result.wire)
		if name != webInnerName || !bytes.Contains(hello, []byte(webInnerName)) {
			t.Fatal("ordinary TLS control did not expose its SNI")
		}
	})
	t.Run("rejection and explicit encrypted retry", func(t *testing.T) {
		newList, newKey, err := GenerateWebECH(webPublicName)
		if err != nil {
			t.Fatal(err)
		}
		opts := serverOpts
		opts.ECHKeys = []tls.EncryptedClientHelloKey{newKey}
		result := webTLSExchange(t, mustWebClient(t, clientOpts), mustWebServer(t, opts))
		var rejection *tls.ECHRejectionError
		if !errors.As(result.clientHandshake, &rejection) || result.serverRead != 0 || result.clientWritten != 0 {
			t.Fatalf("wanted terminal ECH rejection and zero application bytes: err=%v sent=%d read=%d", result.clientHandshake, result.clientWritten, result.serverRead)
		}
		if !bytes.Equal(rejection.RetryConfigList, newList) {
			t.Fatal("authenticated retry config differs from server's advertised config")
		}
		updated := clientOpts
		updated.ECHConfigList = rejection.RetryConfigList
		retry := webTLSExchange(t, mustWebClient(t, updated), mustWebServer(t, opts))
		requireWebSuccess(t, retry, true)
		t.Log("stale ECH key rejected with zero application bytes; a separate caller-supplied encrypted retry succeeded")
	})
	t.Run("no ECH keys never downgrades", func(t *testing.T) {
		opts := serverOpts
		opts.ECHKeys = nil
		result := webTLSExchange(t, mustWebClient(t, clientOpts), mustWebServer(t, opts))
		var rejection *tls.ECHRejectionError
		if !errors.As(result.clientHandshake, &rejection) || len(rejection.RetryConfigList) != 0 || result.serverRead != 0 {
			t.Fatalf("unexpected rejection: %v, read=%d", result.clientHandshake, result.serverRead)
		}
	})
	t.Run("outer CA checked even with experimental pin only", func(t *testing.T) {
		cOpts, sOpts := clientOpts, serverOpts
		cOpts.RootCAs = x509.NewCertPool()
		cOpts.PinSHA256, cOpts.ExperimentalPinOnly = webTestPin(cert), true
		sOpts.ECHKeys = nil
		result := webTLSExchange(t, mustWebClient(t, cOpts), mustWebServer(t, sOpts))
		var unknown x509.UnknownAuthorityError
		if !errors.As(result.clientHandshake, &unknown) || result.serverRead != 0 {
			t.Fatalf("outer CA verification bypassed: %v", result.clientHandshake)
		}
	})
	t.Run("outer hostname checked", func(t *testing.T) {
		opts := serverOpts
		opts.ECHKeys = nil
		opts.Certificates = []tls.Certificate{pki.certificate(t, false, webInnerName)}
		result := webTLSExchange(t, mustWebClient(t, clientOpts), mustWebServer(t, opts))
		var hostname x509.HostnameError
		if !errors.As(result.clientHandshake, &hostname) || hostname.Host != webPublicName || result.serverRead != 0 {
			t.Fatalf("outer hostname verification bypassed: %v", result.clientHandshake)
		}
	})
	t.Run("inner hostname checked after ECH acceptance", func(t *testing.T) {
		opts := serverOpts
		opts.Certificates = []tls.Certificate{pki.certificate(t, false, webPublicName)}
		result := webTLSExchange(t, mustWebClient(t, clientOpts), mustWebServer(t, opts))
		var hostname x509.HostnameError
		if !errors.As(result.clientHandshake, &hostname) || hostname.Host != webInnerName || result.serverRead != 0 {
			t.Fatalf("inner hostname verification bypassed: %v", result.clientHandshake)
		}
	})
	t.Run("server can require ECH", func(t *testing.T) {
		cOpts, sOpts := clientOpts, serverOpts
		cOpts.ECHConfigList = nil
		sOpts.RequireECH = true
		result := webTLSExchange(t, mustWebClient(t, cOpts), mustWebServer(t, sOpts))
		if result.serverHandshake == nil || !strings.Contains(result.serverHandshake.Error(), "accepted ECH") || result.serverRead != 0 {
			t.Fatalf("server accepted non-ECH application data: err=%v bytes=%d", result.serverHandshake, result.serverRead)
		}
	})
	t.Run("removing configured ECH cannot silently succeed", func(t *testing.T) {
		client := mustWebClient(t, clientOpts)
		client.EncryptedClientHelloConfigList = nil // Simulate a caller incorrectly stripping ECH.
		result := webTLSExchange(t, client, mustWebServer(t, serverOpts))
		if result.clientHandshake == nil || !strings.Contains(result.clientHandshake.Error(), "accepted ECH") || result.serverRead != 0 {
			t.Fatalf("ECH requirement was stripped: %v", result.clientHandshake)
		}
	})
}

func TestWebECHHTTP2(t *testing.T) {
	pki := newWebTestPKI(t)
	cert := pki.certificate(t, false, webInnerName, webPublicName)
	list, key, err := GenerateWebECH(webPublicName)
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan bool, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.ProtoMajor == 2 && r.TLS != nil && r.TLS.ECHAccepted && r.TLS.ServerName == webInnerName
		_, _ = io.WriteString(w, "actual HTTP/2 over accepted ECH")
	}))
	server.TLS = mustWebServer(t, WebTLSServerOptions{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}, ECHKeys: []tls.EncryptedClientHelloKey{key}, RequireECH: true})
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{
		TLSClientConfig:   mustWebClient(t, WebTLSClientOptions{ServerName: webInnerName, RootCAs: pki.pool, NextProtos: []string{"h2"}, ECHConfigList: list}),
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	response, err := client.Get("https://" + webInnerName + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "actual HTTP/2 over accepted ECH" || response.ProtoMajor != 2 || response.TLS == nil || !response.TLS.ECHAccepted {
		t.Fatalf("HTTP/2 result: protocol=%s body=%q error=%v", response.Proto, data, err)
	}
	if !<-observed {
		t.Fatal("HTTP/2 handler did not observe accepted ECH and the inner name")
	}
	t.Logf("actual %s response completed with ECHAccepted=true, status=%d", response.Proto, response.StatusCode)
}

func TestWebTLSOrdinaryHTTP1WithoutALPN(t *testing.T) {
	pki := newWebTestPKI(t)
	cert := pki.certificate(t, false, webInnerName, webPublicName)
	list, key, err := GenerateWebECH(webPublicName)
	if err != nil {
		t.Fatal(err)
	}
	ordinary := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: pki.pool, ServerName: webInnerName} // Intentionally omit ALPN.
	for _, ech := range []bool{false, true} {
		t.Run(fmt.Sprintf("actual HTTP1 ECH=%v", ech), func(t *testing.T) {
			observed := make(chan bool, 1)
			const content = "ordinary HTTP/1.1 visitor without ALPN"
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				observed <- r.ProtoMajor == 1 && r.ProtoMinor == 1 && r.TLS != nil &&
					r.TLS.Version == tls.VersionTLS13 && r.TLS.NegotiatedProtocol == "" && r.TLS.ECHAccepted == ech
				_, _ = io.WriteString(w, content)
			}))
			opts := WebTLSServerOptions{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
			clientConfig := ordinary.Clone()
			if ech {
				opts.ECHKeys = []tls.EncryptedClientHelloKey{key}
				opts.RequireECH = true
				clientConfig.EncryptedClientHelloConfigList = bytes.Clone(list)
			}
			server.TLS = mustWebServer(t, opts)
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			dialer := tls.Dialer{Config: clientConfig}
			conn, err := dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
			state := conn.(*tls.Conn).ConnectionState()
			if state.NegotiatedProtocol != "" || state.ECHAccepted != ech {
				t.Fatalf("ordinary visitor TLS: ALPN=%q ECH=%v", state.NegotiatedProtocol, state.ECHAccepted)
			}
			request, err := http.NewRequest(http.MethodGet, "https://"+webInnerName+"/ordinary", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Close = true
			if err := request.Write(conn); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || response.Proto != "HTTP/1.1" || string(body) != content {
				t.Fatalf("ordinary response: status=%d protocol=%s body=%q error=%v", response.StatusCode, response.Proto, body, err)
			}
			if !<-observed {
				t.Fatal("HTTP handler did not observe TLS 1.3 without ALPN and the expected ECH state")
			}
			t.Logf("actual HTTP/1.1 status=200, ALPN omitted, ECHAccepted=%v", ech)
		})
	}
	t.Run("RequireECH still rejects ordinary non-ECH", func(t *testing.T) {
		server := mustWebServer(t, WebTLSServerOptions{Certificates: []tls.Certificate{cert},
			NextProtos: []string{"h2", "http/1.1"}, ECHKeys: []tls.EncryptedClientHelloKey{key}, RequireECH: true})
		result := webTLSExchange(t, ordinary.Clone(), server)
		if result.serverHandshake == nil || result.serverRead != 0 {
			t.Fatalf("omitted ALPN bypassed required ECH: handshake=%v delivered=%d", result.serverHandshake, result.serverRead)
		}
	})
	t.Run("h2-only server still rejects omitted ALPN", func(t *testing.T) {
		server := mustWebServer(t, WebTLSServerOptions{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
		result := webTLSExchange(t, ordinary.Clone(), server)
		if result.serverHandshake == nil || result.serverRead != 0 {
			t.Fatalf("h2-only server admitted an unspecified protocol: handshake=%v delivered=%d", result.serverHandshake, result.serverRead)
		}
	})
	for _, proto := range []string{"h2", "h3"} {
		t.Run(proto+" client still requires ALPN", func(t *testing.T) {
			protos := []string{proto}
			if proto == "h2" {
				protos = append(protos, "http/1.1")
			}
			client := mustWebClient(t, WebTLSClientOptions{ServerName: webInnerName, RootCAs: pki.pool, NextProtos: protos})
			// A valid TLS peer without the server helper isolates client policy.
			server := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
			result := webTLSExchange(t, client, server)
			if result.clientHandshake == nil || result.clientWritten != 0 || result.serverRead != 0 {
				t.Fatalf("client accepted omitted ALPN: handshake=%v written=%d delivered=%d", result.clientHandshake, result.clientWritten, result.serverRead)
			}
		})
	}
}

func TestWebECHQUIC(t *testing.T) {
	pki := newWebTestPKI(t)
	cert := pki.certificate(t, false, webInnerName, webPublicName)
	list, key, err := GenerateWebECH(webPublicName)
	if err != nil {
		t.Fatal(err)
	}
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject=%v", reject), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			serverOpts := WebTLSServerOptions{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, ECHKeys: []tls.EncryptedClientHelloKey{key}}
			if reject {
				serverOpts.ECHKeys = nil
			}
			listener, err := quic.ListenAddr("127.0.0.1:0", mustWebServer(t, serverOpts), &quic.Config{Allow0RTT: false})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			clientConfig := mustWebClient(t, WebTLSClientOptions{ServerName: webInnerName, RootCAs: pki.pool, NextProtos: []string{"h3"}, ECHConfigList: list})
			client, err := quic.DialAddr(ctx, listener.Addr().String(), clientConfig, &quic.Config{})
			if reject {
				if err == nil {
					_ = client.CloseWithError(0, "unexpected acceptance")
					t.Fatal("QUIC silently downgraded ECH")
				}
				t.Logf("QUIC ECH rejection is terminal: %v", err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseWithError(0, "done")
			server, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer server.CloseWithError(0, "done")
			stream, err := client.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_ = stream.SetDeadline(time.Now().Add(4 * time.Second))
			message := []byte("real QUIC encrypted ECH test")
			if _, err := stream.Write(message); err != nil {
				t.Fatal(err)
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			incoming, err := server.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_ = incoming.SetDeadline(time.Now().Add(4 * time.Second))
			got, err := io.ReadAll(incoming)
			if err != nil || !bytes.Equal(got, message) {
				t.Fatalf("QUIC server bytes=%q err=%v", got, err)
			}
			if _, err := incoming.Write(got); err != nil {
				t.Fatal(err)
			}
			if err := incoming.Close(); err != nil {
				t.Fatal(err)
			}
			got, err = io.ReadAll(stream)
			if err != nil || !bytes.Equal(got, message) {
				t.Fatalf("QUIC client bytes=%q err=%v", got, err)
			}
			for _, conn := range []*quic.Conn{client, server} {
				state := conn.ConnectionState()
				if !state.TLS.ECHAccepted || state.TLS.Version != tls.VersionTLS13 || state.TLS.NegotiatedProtocol != "h3" || state.Used0RTT {
					t.Fatalf("unexpected QUIC TLS/early-data state: %+v", state)
				}
			}
			t.Logf("real QUIC stream echoed %d bytes; TLS 1.3, ALPN=h3, ECHAccepted=true at both endpoints, 0-RTT=false; this is not an HTTP/3 framing test", len(got))
		})
	}
}

func TestWebECHHTTP3(t *testing.T) {
	pki := newWebTestPKI(t)
	cert := pki.certificate(t, false, webInnerName, webPublicName)
	list, key, err := GenerateWebECH(webPublicName)
	if err != nil {
		t.Fatal(err)
	}
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject=%v", reject), func(t *testing.T) {
			socket, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int64
			observed := make(chan bool, 1)
			serverOpts := WebTLSServerOptions{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, ECHKeys: []tls.EncryptedClientHelloKey{key}}
			if reject {
				serverOpts.ECHKeys = nil
			}
			server := &http3.Server{
				TLSConfig:  mustWebServer(t, serverOpts),
				QUICConfig: &quic.Config{Allow0RTT: false},
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					observed <- r.ProtoMajor == 3 && r.TLS != nil && r.TLS.ECHAccepted && r.TLS.ServerName == webInnerName
					_, _ = io.WriteString(w, "actual HTTP/3 over accepted ECH")
				}),
			}
			serverDone := make(chan error, 1)
			go func() { serverDone <- server.Serve(socket) }()
			defer func() {
				_ = server.Close()
				_ = socket.Close()
				select {
				case <-serverDone:
				case <-time.After(4 * time.Second):
					t.Error("HTTP/3 fixture did not stop")
				}
			}()
			transport := &http3.Transport{
				TLSClientConfig: mustWebClient(t, WebTLSClientOptions{ServerName: webInnerName, RootCAs: pki.pool, NextProtos: []string{"h3"}, ECHConfigList: list}),
				QUICConfig:      &quic.Config{Allow0RTT: false},
				Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
					// DialAddr waits for TLS/ECH acceptance; no early-data request.
					return quic.DialAddr(ctx, socket.LocalAddr().String(), tlsConfig, quicConfig)
				},
			}
			defer transport.Close()
			client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
			response, err := client.Get("https://" + webInnerName + "/")
			if reject {
				if err == nil {
					response.Body.Close()
					t.Fatal("HTTP/3 request succeeded after ECH rejection")
				}
				if requests.Load() != 0 || !strings.Contains(err.Error(), "server rejected ECH") {
					t.Fatalf("HTTP/3 rejection: err=%v handler requests=%d", err, requests.Load())
				}
				t.Log("actual HTTP/3 transport returned ECH rejection; application handler received zero requests")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			data, err := io.ReadAll(response.Body)
			if err != nil || string(data) != "actual HTTP/3 over accepted ECH" || response.ProtoMajor != 3 || response.TLS == nil || !response.TLS.ECHAccepted {
				t.Fatalf("HTTP/3 result: protocol=%s body=%q error=%v", response.Proto, data, err)
			}
			if !<-observed || requests.Load() != 1 {
				t.Fatal("HTTP/3 handler did not observe exactly one request with accepted ECH")
			}
			t.Logf("actual %s response completed with ECHAccepted=true, status=%d", response.Proto, response.StatusCode)
		})
	}
}

func TestWebTLSConfigurationValidationAndOwnership(t *testing.T) {
	pki := newWebTestPKI(t)
	cert := pki.certificate(t, false, webInnerName, webPublicName)
	for _, opts := range []WebTLSClientOptions{
		{NextProtos: []string{"h2"}},
		{ServerName: webInnerName},
		{ServerName: webInnerName, NextProtos: []string{"proto-x/1"}},
		{ServerName: webInnerName, NextProtos: []string{"h2", "h2"}},
		{ServerName: webInnerName, NextProtos: []string{"h2"}, PinSHA256: "not hex"},
		{ServerName: webInnerName, NextProtos: []string{"h2"}, PinSHA256: "00"},
		{ServerName: webInnerName, NextProtos: []string{"h2"}, ExperimentalPinOnly: true},
		{ServerName: webInnerName, NextProtos: []string{"h2"}, ECHConfigList: []byte{}},
		{ServerName: webInnerName, NextProtos: []string{"h2"}, ECHConfigList: []byte{0, 0}},
	} {
		if _, err := WebClientTLS(opts); err == nil {
			t.Fatalf("accepted invalid client options: %+v", opts)
		}
	}
	for _, name := range []string{"", "localhost", "127.0.0.1", "::1", "bad_name.test", "name.test.", "*.test", "русский.test", strings.Repeat("a", 64) + ".test"} {
		if _, _, err := GenerateWebECH(name); err == nil {
			t.Fatalf("generated unusable ECH public name %q", name)
		}
	}
	list, key, err := GenerateWebECH(webPublicName)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(list); n++ {
		if err := validateWebECHList(list[:n]); err == nil {
			t.Fatalf("accepted truncated ECHConfigList at byte %d", n)
		}
	}
	for n := 0; n < len(key.Config); n++ {
		truncated := key
		truncated.Config = key.Config[:n]
		if err := validateWebECHKey(truncated); err == nil {
			t.Fatalf("accepted truncated ECHConfig at byte %d", n)
		}
	}
	_, anotherKey, err := GenerateWebECH(webPublicName)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := key
	wrongKey.PrivateKey = anotherKey.PrivateKey
	for _, opts := range []WebTLSServerOptions{
		{NextProtos: []string{"h2"}},
		{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}, RequireECH: true},
		{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}, ECHKeys: []tls.EncryptedClientHelloKey{}},
		{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}, ECHKeys: []tls.EncryptedClientHelloKey{wrongKey}},
	} {
		if _, err := WebServerTLS(opts); err == nil {
			t.Fatal("accepted missing certificate, missing required ECH key, or mismatched ECH key")
		}
	}

	// No caller mutation of slices can disable already-configured ECH, alter
	// the chosen ALPN, or corrupt an already-configured certificate/key.
	protos := []string{"h2"}
	client := mustWebClient(t, WebTLSClientOptions{ServerName: webInnerName, RootCAs: pki.pool, NextProtos: protos, ECHConfigList: list})
	server := mustWebServer(t, WebTLSServerOptions{Certificates: []tls.Certificate{cert}, NextProtos: protos, ECHKeys: []tls.EncryptedClientHelloKey{key}})
	protos[0] = "proto-x/1"
	clear(list)
	clear(key.Config)
	clear(key.PrivateKey)
	clear(cert.Certificate[0])
	requireWebSuccess(t, webTLSExchange(t, client, server), true)
}

func TestWebTLSUnsupportedECHAndNegotiationFailClosed(t *testing.T) {
	pki := newWebTestPKI(t)
	cert := pki.certificate(t, false, webInnerName)
	opts := WebTLSClientOptions{ServerName: webInnerName, RootCAs: pki.pool, NextProtos: []string{"h2"}}
	serverOpts := WebTLSServerOptions{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}}
	t.Run("unsupported ECH version", func(t *testing.T) {
		cOpts := opts
		cOpts.ECHConfigList = []byte{0, 4, 0xff, 0xff, 0, 0}
		result := webTLSExchange(t, mustWebClient(t, cOpts), mustWebServer(t, serverOpts))
		if result.clientHandshake == nil || len(result.wire) != 0 || result.serverRead != 0 {
			t.Fatalf("unsupported ECH became network traffic: err=%v wireBytes=%d read=%d", result.clientHandshake, len(result.wire), result.serverRead)
		}
	})
	t.Run("missing ALPN", func(t *testing.T) {
		server := mustWebServer(t, serverOpts)
		server.NextProtos = nil
		result := webTLSExchange(t, mustWebClient(t, opts), server)
		if result.clientHandshake == nil || result.serverRead != 0 {
			t.Fatalf("missing HTTP ALPN accepted: %v", result.clientHandshake)
		}
	})
	t.Run("TLS 1.2 only peer", func(t *testing.T) {
		server := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}}
		result := webTLSExchange(t, mustWebClient(t, opts), server)
		if result.clientHandshake == nil || result.serverRead != 0 {
			t.Fatalf("TLS version downgraded: %v", result.clientHandshake)
		}
	})
	t.Run("root pool snapshot", func(t *testing.T) {
		roots := x509.NewCertPool()
		cOpts := opts
		cOpts.RootCAs = roots
		client := mustWebClient(t, cOpts)
		roots.AddCert(pki.root)
		result := webTLSExchange(t, client, mustWebServer(t, serverOpts))
		var unknown x509.UnknownAuthorityError
		if !errors.As(result.clientHandshake, &unknown) {
			t.Fatalf("caller mutated the installed root policy: %v", result.clientHandshake)
		}
	})
}
