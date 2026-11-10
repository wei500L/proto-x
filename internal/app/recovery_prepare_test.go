package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proto-x/internal/carrier"
	"proto-x/internal/cover"
	"proto-x/internal/session"
)

const prepareInnerName = "recovery.origin.test"
const prepareOuterName = "recovery.cover.test"

// Use a real private CA and name validation, plus a leaf pin and accepted ECH.
// This is a loopback transport/continuity test, not a public-PKI deployment.
func preparedTestCertificate(t *testing.T, dir string) (tls.Certificate, string, string) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Recovery test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{prepareInnerName, prepareOuterName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "recovery-test-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0600); err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(leafDER)
	return tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}, caFile, hex.EncodeToString(pin[:])
}

func preparedTestServer(t *testing.T) (*Server, Config, *Client) {
	t.Helper()
	dir, sc, cc := webClientConfigPair(t)
	cert, caFile, pin := preparedTestCertificate(t, dir)
	cc.CAFile, cc.Pin, cc.ExperimentalPinOnly = caFile, pin, false
	if err := GenerateECH(dir, prepareOuterName); err != nil {
		t.Fatal(err)
	}
	sc.ECHKeysFile = filepath.Join(dir, "ech-keys.json")
	cc.ECHConfigFile = filepath.Join(dir, "ech-config.bin")
	sc.ACKCoalesce, cc.ACKCoalesce = true, true
	cc.RecoveryMode = "adaptive"
	cc.DialTimeoutMS = 2000
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sc.WebListen = tcp.Addr().String()
	_ = tcp.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sc.HTTP3Listen = udp.LocalAddr().String()
	_ = udp.Close()
	token, err := Token(sc.TokenFile)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{cfg: sc, token: token, sessions: make(map[string]*session.Session), slots: make(chan struct{}, 8)}
	ctx, cancel := context.WithCancel(t.Context())
	closers, err := srv.serveWeb(ctx, cert, make(chan error, 4))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		for _, close := range closers {
			close()
		}
		srv.mu.Lock()
		defer srv.mu.Unlock()
		for _, ss := range srv.sessions {
			ss.Close(context.Canceled)
		}
	})
	key, _ := hex.DecodeString(token)
	gate, err := cover.NewGate(key, cover.Config{Path: cc.WebPath})
	if err != nil {
		t.Fatal(err)
	}
	return srv, sc, &Client{cfg: cc, token: token, gate: gate}
}

func prepareEndpoint(sc Config, kind string) Endpoint {
	address := sc.WebListen
	if kind == "h3" {
		address = sc.HTTP3Listen
	}
	return Endpoint{Network: kind, Address: address, ServerName: prepareInnerName}
}

func requirePreparedECH(t *testing.T, ctx context.Context, c *Client, ep Endpoint) *carrier.PreparedWeb {
	t.Helper()
	o, err := c.webOptions(ep)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := carrier.PrepareWeb(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	state := prepared.ConnectionState()
	if !state.HandshakeComplete || !state.ECHAccepted || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != ep.Network {
		_ = prepared.Close()
		t.Fatalf("preparation missing negotiated TLS/ECH/ALPN: complete=%v ECH=%v version=%x ALPN=%s", state.HandshakeComplete, state.ECHAccepted, state.Version, state.NegotiatedProtocol)
	}
	t.Cleanup(func() { _ = prepared.Close() })
	return prepared
}

func requirePreparedEcho(t *testing.T, ctx context.Context, f *session.Flow, message []byte) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		if _, err := f.Write(message); err != nil {
			done <- err
			return
		}
		got := make([]byte, len(message))
		_, err := io.ReadFull(f, got)
		if err == nil && !bytes.Equal(got, message) {
			err = errors.New("prepared recovery changed application bytes")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("existing flow stopped during preparation/activation")
	}
}

func TestPreparedRecoveryKeepsOriginAndOutlivesDialContexts(t *testing.T) {
	for _, first := range []string{"h2", "h3"} {
		t.Run(first, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
			defer cancel()
			srv, sc, client := preparedTestServer(t)
			origin := startWebClientOrigin(t)
			id, err := RandomID()
			if err != nil {
				t.Fatal(err)
			}
			s := session.New(id, false, client.cfg.Session())
			defer s.Close(context.Canceled)
			firstEP := prepareEndpoint(sc, first)
			pctx, pcancel := context.WithCancel(ctx)
			initial := requirePreparedECH(t, pctx, client, firstEP)
			pcancel() // A completed preparation is owned by its caller.
			old, err := client.connectCarrier(ctx, s, firstEP, false, initial)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Attach(old); err != nil {
				t.Fatal(err)
			}
			f, err := s.Open(ctx, origin.listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			requirePreparedEcho(t, ctx, f, []byte("original application connection"))
			srv.mu.Lock()
			ss := srv.sessions[id]
			srv.mu.Unlock()
			if ss == nil {
				t.Fatal("server lost the original session")
			}
			serverOld, generation, _ := ss.Current()
			if generation != 1 {
				t.Fatalf("unexpected initial server generation: %d", generation)
			}
			assertOriginal := func() {
				t.Helper()
				got, gen, _ := ss.Current()
				if got != serverOld || gen != generation || origin.accepts.Load() != 1 {
					t.Fatal("unactivated preparation changed the session or target socket")
				}
				srv.mu.Lock()
				count := len(srv.sessions)
				srv.mu.Unlock()
				if count != 1 {
					t.Fatalf("preparation allocated another session: %d", count)
				}
				select {
				case <-old.Done():
					t.Fatal("unactivated preparation closed original client path")
				default:
				}
			}
			second := "h3"
			if first == second {
				second = "h2"
			}
			alternate := prepareEndpoint(sc, second)
			prepareCtx, prepareCancel := context.WithCancel(ctx)
			discarded := requirePreparedECH(t, prepareCtx, client, alternate)
			assertOriginal()
			prepareCancel()
			_ = discarded.Close()
			assertOriginal()
			requirePreparedEcho(t, ctx, f, []byte("same connection after discarded TLS preparation"))
			// A failed/canceled preparation also has no HELLO side effects.
			canceled, stop := context.WithCancel(ctx)
			stop()
			o, err := client.webOptions(alternate)
			if err != nil {
				t.Fatal(err)
			}
			bad, err := carrier.PrepareWeb(canceled, o)
			if bad != nil {
				_ = bad.Close()
			}
			if err == nil {
				t.Fatal("canceled preparation unexpectedly succeeded")
			}
			assertOriginal()
			prepareCtx, prepareCancel = context.WithCancel(ctx)
			prepared := requirePreparedECH(t, prepareCtx, client, alternate)
			prepareCancel()
			assertOriginal()
			activateCtx, activateCancel := context.WithCancel(ctx)
			next, err := client.connectCarrier(activateCtx, s, alternate, true, prepared)
			activateCancel() // Success must not retain either short-lived context.
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Attach(next); err != nil {
				t.Fatal(err)
			}
			if extra, err := prepared.Activate(ctx, nil); err == nil || extra != nil {
				t.Fatal("consumed preparation activated twice")
			}
			requirePreparedEcho(t, ctx, f, []byte("original flow after authenticated carrier replacement and canceled dial contexts"))
			_, gen, _ := ss.Current()
			if gen != 2 || origin.accepts.Load() != 1 {
				t.Fatalf("replacement gen=%d origin_accepts=%d", gen, origin.accepts.Load())
			}
			// Cross multiple bounded windows and check exact EOF/half-close on
			// the same application flow after the contexts have been canceled.
			payload := make([]byte, 192<<10)
			for i := range payload {
				payload[i] = byte((i*71 + i/19) % 251)
			}
			written := make(chan error, 1)
			go func() {
				_, err := f.Write(payload)
				if err == nil {
					err = f.CloseWrite()
				}
				written <- err
			}()
			read := make(chan error, 1)
			go func() {
				got, err := io.ReadAll(f)
				if err == nil && !bytes.Equal(got, payload) {
					err = errors.New("recovered bytes or EOF did not match")
				}
				read <- err
			}()
			for _, done := range []<-chan error{written, read} {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("recovered flow failed to drain and half-close")
				}
			}
			if origin.accepts.Load() != 1 {
				t.Fatal("recovery opened a second target TCP connection")
			}
			t.Logf("%s to %s: accepted ECH, discarded preparation left generation 1, generation 2 kept one origin socket and exact %d-byte half-close", first, second, len(payload))
		})
	}
}
