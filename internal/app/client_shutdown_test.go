package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"proto-x/internal/carrier"
	"proto-x/internal/wire"
)

// Reading HELLO proves the client owns a real TLS carrier but has not attached
// it to its session: this peer deliberately never sends WELCOME. Cancellation
// must interrupt that handshake and close the carrier before RunClient returns.
// The long handshake deadline prevents the old detached cleanup goroutine from
// passing merely because the pending handshake happened to time out first.
func TestRunClientCancelClosesPendingTLSHandshake(t *testing.T) {
	c := startShutdownTLSClient(t)
	c.cancelAndRequireClosed(t)
}

// A matching PONG proves the new carrier was attached and the session receive
// loop processed traffic. Cover normal active-session shutdown as well as the
// harder pending-handshake case above.
func TestRunClientCancelClosesAttachedTLSCarrier(t *testing.T) {
	c := startShutdownTLSClient(t)
	b, err := json.Marshal(welcome{OK: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.Write(c.peer, wire.Frame{Kind: wire.Welcome, Payload: b}); err != nil {
		t.Fatal(err)
	}
	const probe = 731
	if err := wire.Write(c.peer, wire.Frame{Kind: wire.Ping, Offset: probe}); err != nil {
		t.Fatal(err)
	}
	for {
		frame, err := wire.Read(c.peer)
		if err != nil {
			t.Fatalf("waiting for attached session PONG: %v", err)
		}
		if frame.Kind == wire.Pong && frame.Offset == probe {
			break
		}
		if frame.Kind != wire.Ping || frame.ID != 0 {
			t.Fatalf("unexpected frame before PONG: kind=%d id=%d", frame.Kind, frame.ID)
		}
		if err := wire.Write(c.peer, wire.Frame{Kind: wire.Pong, Offset: frame.Offset}); err != nil {
			t.Fatal(err)
		}
	}
	c.cancelAndRequireClosed(t)
}

type shutdownTLSClient struct {
	peer   net.Conn
	cancel context.CancelFunc
	done   chan struct{}
	err    error // written before done closes; read only after receiving done
}

func startShutdownTLSClient(t *testing.T) *shutdownTLSClient {
	t.Helper()
	dir := t.TempDir()
	if err := Init(dir, "127.0.0.1", 14443, 14443); err != nil {
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
	cert, err := tls.LoadX509KeyPair(sc.CertFile, sc.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", carrier.TLSConfig(cert))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cc.SOCKSListen = "127.0.0.1:0"
	cc.Endpoints = []Endpoint{{Network: "tls", Address: ln.Addr().String(), ServerName: "proto-x.local"}}
	cc.DialTimeoutMS = 5000
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	c := &shutdownTLSClient{cancel: cancel, done: make(chan struct{})}
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		if c.peer != nil {
			_ = c.peer.Close()
		}
		select {
		case <-c.done:
		case <-time.After(2 * time.Second):
			t.Error("RunClient did not stop during test cleanup")
		}
	})
	go func() {
		c.err = RunClient(ctx, cc)
		close(c.done)
	}()
	type acceptance struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptance)
	go func() {
		conn, err := ln.Accept()
		select {
		case accepted <- acceptance{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatal(result.err)
		}
		c.peer = result.conn
	case <-c.done:
		t.Fatalf("RunClient returned before dialing its endpoint: %v", c.err)
	case <-ctx.Done():
		t.Fatalf("waiting for client TLS connection: %v", ctx.Err())
	}
	deadline, _ := ctx.Deadline()
	if err := c.peer.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	frame, err := wire.Read(c.peer)
	if err != nil {
		t.Fatalf("reading client HELLO: %v", err)
	}
	var h hello
	if frame.Kind != wire.Hello || json.Unmarshal(frame.Payload, &h) != nil ||
		h.Version != wire.Version || h.Resume || h.Window != cc.Window || len(h.Session) != 32 {
		t.Fatal("client did not send a valid initial HELLO")
	}
	token, err := Token(cc.TokenFile)
	if err != nil || h.Token != token {
		t.Fatal("client HELLO did not carry the fixture token")
	}
	return c
}

func (c *shutdownTLSClient) cancelAndRequireClosed(t *testing.T) {
	t.Helper()
	c.cancel()
	select {
	case <-c.done:
		if c.err != nil {
			t.Fatalf("RunClient cancellation: %v", c.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunClient cancellation waited for the 5-second handshake deadline")
	}
	// Read after the return boundary, allowing only bounded loopback delivery
	// of the close. A pending pre-fix handshake remains open for about 5 seconds;
	// waiting for its ordinary deadline here would conceal the regression.
	if err := c.peer.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	for {
		frame, err := wire.Read(c.peer)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatalf("RunClient returned before its TLS carrier closed: %v", err)
		}
		// A control record queued before cancellation may precede the close.
		if frame.ID != 0 || (frame.Kind != wire.Ping && frame.Kind != wire.Pong) {
			t.Fatalf("unexpected record after cancellation: kind=%d id=%d", frame.Kind, frame.ID)
		}
	}
}
