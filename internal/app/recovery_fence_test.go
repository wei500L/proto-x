package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proto-x/internal/carrier"
	"proto-x/internal/session"
	"proto-x/internal/wire"
)

// This fault fixture models a locally successful WELCOME write whose bytes do
// not reach the client. It tests distributed handshake ordering, not packet
// loss, TLS integrity or transport retransmission.
type withheldWelcome struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
}

func (c *withheldWelcome) Write(p []byte) (int, error) {
	if c.entered != nil {
		close(c.entered)
		c.entered = nil
	}
	if c.release != nil {
		<-c.release
		c.release = nil
	}
	return len(p), nil
}

func fencedServer(t *testing.T) (*Server, *session.Session, *carrier.Link) {
	t.Helper()
	cfg := Defaults()
	cfg.RateMbps = 0
	sc := cfg.Session()
	sc.Heartbeat, sc.DeadAfter, sc.ResumeTTL = time.Hour, 2*time.Hour, 3*time.Hour
	sc.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	ss := session.New(strings.Repeat("a", 32), true, sc)
	peer, conn := net.Pipe()
	old := carrier.AcceptTLS(conn)
	if err := ss.AttachAttempt(old, 1); err != nil {
		t.Fatal(err)
	}
	srv := &Server{cfg: cfg, token: strings.Repeat("b", 64), sessions: map[string]*session.Session{ss.ID: ss}}
	t.Cleanup(func() { ss.Close(context.Canceled); _ = peer.Close() })
	return srv, ss, old
}

func resumeThroughPipe(t *testing.T, srv *Server, ss *session.Session, attempt uint64, wrap func(net.Conn) net.Conn) (*carrier.Link, *carrier.Link, <-chan struct{}) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	if wrap != nil {
		serverConn = wrap(serverConn)
	}
	client, server := carrier.AcceptTLS(clientConn), carrier.AcceptTLS(serverConn)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	done := make(chan struct{})
	go func() { defer close(done); srv.handshake(context.Background(), server) }()
	client.SetHandshakeDeadline(time.Now().Add(time.Second))
	b, _ := json.Marshal(hello{Version: wire.Version, Session: ss.ID, Token: srv.token, Resume: true, Window: srv.cfg.Window, Attempt: attempt})
	if err := client.HandshakeWrite(wire.Frame{Kind: wire.Hello, Payload: b}); err != nil {
		t.Fatal(err)
	}
	return client, server, done
}

func awaitHandshake(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server handshake did not finish")
	}
}

func TestRecoveryDelayedWelcomeCannotReplaceNewerAttempt(t *testing.T) {
	srv, ss, _ := fencedServer(t)
	release, entered := make(chan struct{}), make(chan struct{})
	// Ensure a failed assertion cannot leave the server stuck in the fixture.
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	_, older, olderDone := resumeThroughPipe(t, srv, ss, 2, func(c net.Conn) net.Conn {
		return &withheldWelcome{Conn: c, entered: entered, release: release}
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("older candidate never reached WELCOME")
	}
	client, newest, newestDone := resumeThroughPipe(t, srv, ss, 3, nil)
	frame, err := client.HandshakeRead()
	var w welcome
	if err != nil || json.Unmarshal(frame.Payload, &w) != nil || !w.OK || w.Attempt != 3 || !w.Resumed {
		t.Fatalf("newest candidate WELCOME: %+v %v", w, err)
	}
	awaitHandshake(t, newestDone)
	close(release)
	awaitHandshake(t, olderDone)
	got, gen, _ := ss.Current()
	if got != newest || gen != 2 {
		t.Fatalf("delayed older attempt replaced generation: current=%v generation=%d", got == newest, gen)
	}
	select {
	case <-older.Done():
	default:
		t.Fatal("rejected candidate was left open")
	}
	select {
	case <-newest.Done():
		t.Fatal("rejected older attempt closed the current path")
	default:
	}
}

// The fence orders retries; it does not make WELCOME delivery an atomic
// two-host commit. Preserve this explicit boundary in the regression suite.
func TestRecoveryLostWelcomeLeavesUncertainClientAndCanRetry(t *testing.T) {
	srv, ss, old := fencedServer(t)
	client, candidate, done := resumeThroughPipe(t, srv, ss, 2, func(c net.Conn) net.Conn { return &withheldWelcome{Conn: c} })
	awaitHandshake(t, done)
	client.SetHandshakeDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := client.HandshakeRead(); err == nil {
		t.Fatal("withheld WELCOME unexpectedly arrived")
	}
	got, gen, _ := ss.Current()
	if got != candidate || gen != 2 {
		t.Fatal("expected server commit after locally successful WELCOME write")
	}
	select {
	case <-old.Done():
	default:
		t.Fatal("this fixture should expose the original path eviction boundary")
	}
	// A newer retry can safely take over even while the uncertain prior link
	// remains at the server. This does not redial or replay an origin request.
	retryClient, retry, retryDone := resumeThroughPipe(t, srv, ss, 3, nil)
	if _, err := retryClient.HandshakeRead(); err != nil {
		t.Fatal(err)
	}
	awaitHandshake(t, retryDone)
	got, gen, _ = ss.Current()
	if got != retry || gen != 3 {
		t.Fatal("newer retry failed after WELCOME loss")
	}
}

func TestRecoveryClientRequiresExactAttemptEcho(t *testing.T) {
	for _, mode := range []string{"missing", "wrong", "exact"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := Init(dir, "127.0.0.1", 14443, 14443); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(filepath.Join(dir, "client.json"))
			if err != nil {
				t.Fatal(err)
			}
			cfg.RecoveryMode = "adaptive"
			cfg.DialTimeoutMS = 1000
			cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"))
			if err != nil {
				t.Fatal(err)
			}
			ln, err := tls.Listen("tcp", "127.0.0.1:0", carrier.TLSConfig(cert))
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			serverDone := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				l := carrier.AcceptTLS(conn)
				defer l.Close()
				l.SetHandshakeDeadline(time.Now().Add(time.Second))
				frame, err := l.HandshakeRead()
				var h hello
				if err != nil || json.Unmarshal(frame.Payload, &h) != nil || h.Attempt != 1 {
					serverDone <- errors.New("client did not send initial fenced attempt")
					return
				}
				w := welcome{OK: true}
				if mode == "wrong" {
					w.Attempt = h.Attempt + 1
				} else if mode == "exact" {
					w.Attempt = h.Attempt
				}
				body, _ := json.Marshal(w)
				if err := l.HandshakeWrite(wire.Frame{Kind: wire.Welcome, Payload: body}); err != nil {
					serverDone <- err
					return
				}
				_, _ = l.HandshakeRead() // Wait for caller cleanup after acceptance or rejection.
				serverDone <- nil
			}()
			token, err := Token(cfg.TokenFile)
			if err != nil {
				t.Fatal(err)
			}
			c := &Client{cfg: cfg, token: token}
			ss := session.New(strings.Repeat("a", 32), false, cfg.Session())
			defer ss.Close(context.Canceled)
			ep := Endpoint{Network: "tls", Address: ln.Addr().String(), ServerName: "proto-x.local"}
			l, err := c.connectCarrier(context.Background(), ss, ep, false, nil)
			if mode == "exact" {
				if err != nil || l == nil {
					t.Fatalf("exact echo rejected: %v", err)
				}
				_ = l.Close()
			} else if err == nil || l != nil || !strings.Contains(err.Error(), "fenced recovery") {
				t.Fatalf("inexact echo accepted: link=%v err=%v", l, err)
			}
			select {
			case err := <-serverDone:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("client did not close the handshake transport")
			}
		})
	}
}
