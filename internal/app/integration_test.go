package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"proto-x/internal/carrier"
	"proto-x/internal/session"
	"proto-x/internal/wire"
)

// This crosses the real QUIC/TLS implementations and authenticates both links.
// The origin must accept exactly once even though the carrier family changes.
func TestQUICToTLSRetainsOriginAndBytes(t *testing.T) {
	dir := t.TempDir()
	if e := Init(dir, "127.0.0.1", 14443, 14443); e != nil {
		t.Fatal(e)
	}
	sc, e := Load(filepath.Join(dir, "server.json"))
	if e != nil {
		t.Fatal(e)
	}
	cc, e := Load(filepath.Join(dir, "client.json"))
	if e != nil {
		t.Fatal(e)
	}
	freeTCP, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	sc.TLSListen = freeTCP.Addr().String()
	_ = freeTCP.Close()
	freeUDP, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	sc.QUICListen = freeUDP.LocalAddr().String()
	_ = freeUDP.Close()
	sc.AllowPrivate = true
	sc.RateMbps = 0
	cc.RateMbps = 0
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	errServer := make(chan error, 1)
	go func() { errServer <- RunServer(ctx, sc) }()
	defer func() {
		cancel()
		select {
		case e := <-errServer:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	}()
	origin, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer origin.Close()
	var accepts atomic.Int32
	go func() {
		for {
			c, e := origin.Accept()
			if e != nil {
				return
			}
			accepts.Add(1)
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	id, e := RandomID()
	if e != nil {
		t.Fatal(e)
	}
	s := session.New(id, false, cc.Session())
	defer s.Close(context.Canceled)
	token, e := Token(cc.TokenFile)
	if e != nil {
		t.Fatal(e)
	}
	attach := func(kind, addr string, resume bool) *carrier.Link {
		t.Helper()
		tc, e := carrier.ClientTLS(cc.Pin, "proto-x.local")
		if e != nil {
			t.Fatal(e)
		}
		var l *carrier.Link
		for i := 0; i < 20; i++ {
			dctx, dc := context.WithTimeout(ctx, 200*time.Millisecond)
			l, e = carrier.Dial(dctx, kind, addr, tc)
			dc()
			if e == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if e != nil {
			t.Fatal(e)
		}
		l.SetHandshakeDeadline(time.Now().Add(2 * time.Second))
		b, _ := json.Marshal(hello{Version: wire.Version, Session: id, Token: token, Resume: resume, Window: cc.Window})
		if e = l.HandshakeWrite(wire.Frame{Kind: wire.Hello, Payload: b}); e != nil {
			t.Fatal(e)
		}
		p, e := l.HandshakeRead()
		if e != nil {
			t.Fatal(e)
		}
		var w welcome
		if e = json.Unmarshal(p.Payload, &w); e != nil || !w.OK || w.Resumed != resume {
			t.Fatalf("unexpected welcome %+v %v", w, e)
		}
		l.SetHandshakeDeadline(time.Time{})
		if e = s.Attach(l); e != nil {
			t.Fatal(e)
		}
		return l
	}
	first := attach("quic", sc.QUICListen, false)
	f, e := s.Open(ctx, origin.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	payload := make([]byte, 512<<10)
	for i := range payload {
		payload[i] = byte((i*71 + i/113) % 251)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, e := f.Write(payload)
		if e == nil {
			e = f.CloseWrite()
		}
		writeDone <- e
	}()
	got := make([]byte, len(payload))
	if _, e = io.ReadFull(f, got[:32<<10]); e != nil {
		t.Fatal(e)
	}
	s.Drop(first)
	attach("tls", sc.TLSListen, true)
	readDone := make(chan error, 1)
	go func() {
		_, e := io.ReadFull(f, got[32<<10:])
		if e == nil {
			var rest [1]byte
			_, e = f.Read(rest[:])
			if e == io.EOF {
				e = nil
			}
		}
		readDone <- e
	}()
	select {
	case e = <-readDone:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("read stalled across carrier replacement")
	}
	if e = <-writeDone; e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("data changed during resume")
	}
	if accepts.Load() != 1 {
		t.Fatalf("origin accepted %d times", accepts.Load())
	}
}
