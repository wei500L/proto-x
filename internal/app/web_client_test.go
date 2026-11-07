package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proto-x/internal/carrier"
	"proto-x/internal/cover"
	"proto-x/internal/session"
	"proto-x/internal/wire"
)

// These tests exercise the public client entry point and actual SOCKS traffic.
// Cancellation checks a live SOCKS connection, listener ownership and the
// specific management goroutines created by this client, not global counts.
func TestRunWebClientSOCKSBytesAndShutdown(t *testing.T) {
	for _, kind := range []string{"h2", "h3"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			sc, cc := webTestServer(t, ctx)
			selectWebClientEndpoint(&cc, sc, kind)
			origin := startWebClientOrigin(t)
			client := startRunWebClient(t, cc)
			conn := requestWebSOCKS(t, client.address, origin.listener.Addr().String())
			requireWebSOCKSSuccess(t, conn)
			payload := make([]byte, (256<<10)+37)
			for i := range payload {
				payload[i] = byte((i*71 + i/29) % 251)
			}
			written := make(chan error, 1)
			go func() {
				_, err := io.Copy(conn, bytes.NewReader(payload))
				if err == nil {
					err = conn.CloseWrite()
				}
				written <- err
			}()
			got, err := io.ReadAll(io.LimitReader(conn, int64(len(payload)+1)))
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("SOCKS bytes/EOF: received=%d want=%d equal=%v error=%v", len(got), len(payload), bytes.Equal(got, payload), err)
			}
			if err := <-written; err != nil {
				t.Fatalf("SOCKS upload/half-close: %v", err)
			}
			_ = conn.Close()
			if origin.accepts.Load() != 1 {
				t.Fatalf("one SOCKS request opened %d origin sockets", origin.accepts.Load())
			}

			active := requestWebSOCKS(t, client.address, origin.listener.Addr().String())
			requireWebSOCKSSuccess(t, active)
			probe := []byte("still active before client cancellation")
			if _, err := active.Write(probe); err != nil {
				t.Fatal(err)
			}
			echo := make([]byte, len(probe))
			if _, err := io.ReadFull(active, echo); err != nil || !bytes.Equal(echo, probe) {
				t.Fatalf("active SOCKS echo: equal=%v error=%v", bytes.Equal(echo, probe), err)
			}
			client.stopAndCheck(t)
			requireWebSocketClosed(t, active)
			t.Logf("%s: %d bytes exact through SOCKS, half-close preserved, active socket/listener/manager stopped", kind, len(payload))
		})
	}
}

func TestRunWebClientWrongTokenHasNoOriginSideEffects(t *testing.T) {
	for _, kind := range []string{"h2", "h3"} {
		t.Run(kind, func(t *testing.T) {
			server, sc, cc := startObservedWebServer(t)
			selectWebClientEndpoint(&cc, sc, kind)
			origin := startWebClientOrigin(t)
			goodToken, err := Token(cc.TokenFile)
			if err != nil {
				t.Fatal(err)
			}
			badToken, _ := hex.DecodeString(goodToken)
			badToken[0] ^= 1
			cc.TokenFile = filepath.Join(t.TempDir(), "wrong-token")
			if err := os.WriteFile(cc.TokenFile, []byte(hex.EncodeToString(badToken)), 0600); err != nil {
				t.Fatal(err)
			}

			// An explicit rejected HTTP response proves the listener and TLS path
			// work; a connection refusal cannot make this negative test pass.
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			link, err := carrier.DialWeb(ctx, webClientDialOptions(t, cc))
			cancel()
			if link != nil {
				_ = link.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "request was not accepted") {
				t.Fatalf("wrong HTTP credential was not rejected by a reachable server: %v", err)
			}

			client := startRunWebClient(t, cc)
			conn := requestWebSOCKS(t, client.address, origin.listener.Addr().String())
			if err := conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var reply [10]byte
			_, err = io.ReadFull(conn, reply[:])
			if err == nil && reply[1] == 0 {
				t.Fatal("wrong token received a successful SOCKS CONNECT response")
			}
			// A bounded wait is expected while the unauthenticated client tries
			// its configured endpoint. No completed session or target is allowed.
			requireNoWebServerSideEffects(t, server, origin)
			client.stopAndCheck(t)
			requireWebSocketClosed(t, conn)
			requireNoWebServerSideEffects(t, server, origin)
			t.Logf("%s: wrong-token HTTP rejection observed; real SOCKS attempt created 0 sessions and 0 origin sockets", kind)
		})
	}
}

// A correct connection-bound HTTP credential must not bypass the second,
// session-level HELLO validation. Exercise a real carrier rather than invoking
// Server.handshake with a synthetic reader.
func TestWebClientBadHelloHasNoSessionSideEffects(t *testing.T) {
	for _, kind := range []string{"h2", "h3"} {
		t.Run(kind, func(t *testing.T) {
			server, sc, cc := startObservedWebServer(t)
			selectWebClientEndpoint(&cc, sc, kind)
			token, err := Token(cc.TokenFile)
			if err != nil {
				t.Fatal(err)
			}
			for _, malformed := range []bool{false, true} {
				t.Run(fmt.Sprintf("malformed=%v", malformed), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
					defer cancel()
					link, err := carrier.DialWeb(ctx, webClientDialOptions(t, cc))
					if err != nil {
						t.Fatalf("valid HTTP authentication: %v", err)
					}
					defer link.Close()
					stop := context.AfterFunc(ctx, func() { _ = link.Close() })
					defer stop()
					wrong := []byte(token)
					if wrong[0] == '0' {
						wrong[0] = '1'
					} else {
						wrong[0] = '0'
					}
					payload, _ := json.Marshal(hello{Version: wire.Version, Session: strings.Repeat("a", 32), Token: string(wrong), Window: cc.Window})
					if malformed {
						payload = []byte("{invalid JSON")
					}
					if err := link.HandshakeWrite(wire.Frame{Kind: wire.Hello, Payload: payload}); err != nil {
						t.Fatalf("sending invalid HELLO: %v", err)
					}
					frame, err := link.HandshakeRead()
					if !stop() || ctx.Err() != nil {
						t.Fatal("invalid HELLO was not rejected before the test timeout")
					}
					if err == nil {
						var response welcome
						if frame.Kind != wire.Welcome || json.Unmarshal(frame.Payload, &response) != nil || response.OK {
							t.Fatal("invalid HELLO was not rejected")
						}
					}
					server.mu.Lock()
					count := len(server.sessions)
					server.mu.Unlock()
					if count != 0 {
						t.Fatalf("invalid HELLO allocated %d sessions", count)
					}
				})
			}
		})
	}
}

func TestWebClientAndServerRejectUnsafeStartupConfiguration(t *testing.T) {
	for _, role := range []string{"client", "server"} {
		t.Run(role, func(t *testing.T) {
			for _, setting := range []string{"wrong ECH role", "negative padding", "unsupported padding", "oversize padding"} {
				t.Run(setting, func(t *testing.T) {
					dir, sc, cc := webClientConfigPair(t)
					cfg := cc
					run := RunClient
					if role == "server" {
						cfg = sc
						run = RunServer
					}
					want := "padding"
					switch setting {
					case "wrong ECH role":
						if err := GenerateECH(dir, "front.example.test"); err != nil {
							t.Fatal(err)
						}
						if role == "client" {
							cfg.ECHKeysFile = filepath.Join(dir, "ech-keys.json")
						} else {
							cfg.ECHConfigFile = filepath.Join(dir, "ech-config.bin")
						}
						want = "ech"
					case "negative padding":
						cfg.WebPadding = -1
					case "unsupported padding":
						cfg.WebPadding = 64
					case "oversize padding":
						cfg.WebPadding = 256
					}
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					defer cancel()
					err := run(ctx, cfg)
					if err == nil || !strings.Contains(strings.ToLower(err.Error()), want) {
						t.Fatalf("%s accepted %s or failed for an unrelated reason: %v", role, setting, err)
					}
					if ctx.Err() != nil {
						t.Fatal("invalid configuration was not rejected until cancellation")
					}
				})
			}
		})
	}
}

type runningWebClient struct {
	address  string
	cancel   context.CancelFunc
	done     chan struct{}
	err      error // published by closing done
	managers map[string]bool
}

func startRunWebClient(t *testing.T, cfg Config) *runningWebClient {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.SOCKSListen = ln.Addr().String()
	_ = ln.Close()
	before := webClientManagerIDs()
	ctx, cancel := context.WithCancel(t.Context())
	c := &runningWebClient{address: cfg.SOCKSListen, cancel: cancel, done: make(chan struct{}), managers: make(map[string]bool)}
	go func() { c.err = RunClient(ctx, cfg); close(c.done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-c.done:
		case <-time.After(2 * time.Second):
			t.Error("web client did not return during cleanup")
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-c.done:
			t.Fatalf("web client stopped before SOCKS startup: %v", c.err)
		default:
		}
		conn, err := net.DialTimeout("tcp", c.address, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			for id := range webClientManagerIDs() {
				if !before[id] {
					c.managers[id] = true
				}
			}
			if len(c.managers) > 0 {
				return c
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("web client listener or management goroutine did not start")
	return nil
}

func (c *runningWebClient) stopAndCheck(t *testing.T) {
	t.Helper()
	c.cancel()
	select {
	case <-c.done:
		if c.err != nil {
			t.Fatalf("RunClient cancellation: %v", c.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunClient failed to join its management goroutine")
	}
	for id := range webClientManagerIDs() {
		if c.managers[id] {
			t.Errorf("client management goroutine %s survived RunClient return", id)
		}
	}
	ln, err := net.Listen("tcp", c.address)
	if err != nil {
		t.Fatalf("SOCKS port still owned after RunClient returned: %v", err)
	}
	_ = ln.Close()
}

func webClientManagerIDs() map[string]bool {
	buf := make([]byte, 64<<10)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, len(buf)*2)
	}
	ids := make(map[string]bool)
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if !strings.Contains(stack, "proto-x/internal/app.(*Client).manage(") {
			continue
		}
		fields := strings.Fields(stack)
		if len(fields) > 1 && fields[0] == "goroutine" {
			ids[fields[1]] = true
		}
	}
	return ids
}

func requestWebSOCKS(t *testing.T, address, target string) *net.TCPConn {
	t.Helper()
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := c.(*net.TCPConn)
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var hello [2]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil || hello != [2]byte{5, 0} {
		t.Fatalf("SOCKS negotiation: response=%v error=%v", hello, err)
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	pn, err := strconv.Atoi(port)
	if err != nil || pn < 1 || pn > 65535 {
		t.Fatal("invalid test origin port")
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatal("test origin must use numeric IPv4 loopback")
	}
	request := append([]byte{5, 1, 0, 1}, ip...)
	request = binary.BigEndian.AppendUint16(request, uint16(pn))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	return conn
}

func requireWebSOCKSSuccess(t *testing.T, conn net.Conn) {
	t.Helper()
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[0] != 5 || reply[1] != 0 || reply[2] != 0 || reply[3] != 1 {
		t.Fatalf("SOCKS CONNECT: response=%v error=%v", reply, err)
	}
}

func requireWebSocketClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [32]byte
	for {
		_, err := conn.Read(b[:])
		if err == nil {
			continue // A failed CONNECT reply may precede the close.
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatalf("SOCKS connection survived client shutdown: %v", err)
		}
		return
	}
}

type webClientOrigin struct {
	listener net.Listener
	accepts  atomic.Int32
}

func startWebClientOrigin(t *testing.T) *webClientOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &webClientOrigin{listener: ln}
	var mu sync.Mutex
	connections := make(map[net.Conn]bool)
	accepted := make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(accepted)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			o.accepts.Add(1)
			mu.Lock()
			connections[conn] = true
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
				mu.Lock()
				delete(connections, conn)
				mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-accepted // All worker Add calls have completed before Wait.
		mu.Lock()
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return o
}

func webClientConfigPair(t *testing.T) (string, Config, Config) {
	t.Helper()
	dir := t.TempDir()
	if err := InitWeb(dir, "127.0.0.1", "localhost", 14443, 14443); err != nil {
		t.Fatal(err)
	}
	sc, err := Load(filepath.Join(dir, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	cc, err := Load(filepath.Join(dir, "client.json"))
	if err != nil {
		t.Fatal(err)
	}
	sc.WebListen, sc.HTTP3Listen = "127.0.0.1:0", "127.0.0.1:0"
	sc.AllowPrivate = true
	sc.RateMbps, cc.RateMbps = 0, 0
	cc.SOCKSListen = "127.0.0.1:0"
	return dir, sc, cc
}

func selectWebClientEndpoint(cc *Config, sc Config, kind string) {
	address := sc.WebListen
	if kind == "h3" {
		address = sc.HTTP3Listen
	}
	cc.Endpoints = []Endpoint{{Network: kind, Address: address, ServerName: "localhost"}}
	cc.DialTimeoutMS = 1000
}

func startObservedWebServer(t *testing.T) (*Server, Config, Config) {
	t.Helper()
	_, sc, cc := webClientConfigPair(t)
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
	cert, err := tls.LoadX509KeyPair(sc.CertFile, sc.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	token, err := Token(sc.TokenFile)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: sc, token: token, sessions: make(map[string]*session.Session), slots: make(chan struct{}, 8)}
	ctx, cancel := context.WithCancel(t.Context())
	closers, err := s.serveWeb(ctx, cert, make(chan error, 4))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		for _, close := range closers {
			close()
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, ss := range s.sessions {
			ss.Close(context.Canceled)
		}
	})
	return s, sc, cc
}

func webClientDialOptions(t *testing.T, cfg Config) carrier.WebOptions {
	t.Helper()
	ep := cfg.Endpoints[0]
	tlsConfig, err := cfg.webTLS(ep)
	if err != nil {
		t.Fatal(err)
	}
	token, err := Token(cfg.TokenFile)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString(token)
	gate, err := cover.NewGate(key, cover.Config{Path: cfg.WebPath})
	if err != nil {
		t.Fatal(err)
	}
	return carrier.WebOptions{Network: ep.Network, Address: ep.Address, Authority: ep.ServerName,
		Path: cfg.WebPath, TLSConfig: tlsConfig, Gate: gate, Padding: cfg.WebPadding}
}

func requireNoWebServerSideEffects(t *testing.T, s *Server, origin *webClientOrigin) {
	t.Helper()
	s.mu.Lock()
	sessions := len(s.sessions)
	s.mu.Unlock()
	if sessions != 0 || origin.accepts.Load() != 0 {
		t.Fatalf("rejected credential had side effects: sessions=%d origin_accepts=%d", sessions, origin.accepts.Load())
	}
}
