package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proto-x/internal/carrier"
	"proto-x/internal/cover"
	"proto-x/internal/session"
	"proto-x/internal/wire"
)

func TestWebCarriersResumeAndRetire(t *testing.T) {
	for _, first := range []string{"h3", "h2"} {
		t.Run(first, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			sc, cc := webTestServer(t, ctx)
			origin, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			var accepts atomic.Int32
			go func() {
				for {
					c, err := origin.Accept()
					if err != nil {
						return
					}
					accepts.Add(1)
					go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
				}
			}()
			id, err := RandomID()
			if err != nil {
				t.Fatal(err)
			}
			s := session.New(id, false, cc.Session())
			defer s.Close(context.Canceled)
			one := attachWebTest(t, ctx, cc, sc, s, first, false)
			f, err := s.Open(ctx, origin.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			payload := make([]byte, 384<<10)
			for i := range payload {
				payload[i] = byte((i*43 + i/17) % 251)
			}
			write := make(chan error, 1)
			go func() {
				_, e := f.Write(payload)
				if e == nil {
					e = f.CloseWrite()
				}
				write <- e
			}()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(f, got[:16<<10]); err != nil {
				t.Fatal(err)
			}
			s.Drop(one)
			second := "h2"
			if first == second {
				second = "h3"
			}
			attachWebTest(t, ctx, cc, sc, s, second, true)
			done := make(chan error, 1)
			go func() {
				_, e := io.ReadFull(f, got[16<<10:])
				if e == nil {
					var extra [1]byte
					_, e = f.Read(extra[:])
					if e == io.EOF {
						e = nil
					}
				}
				done <- e
			}()
			select {
			case e := <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-ctx.Done():
				t.Fatal("web recovery stalled")
			}
			if e := <-write; e != nil || !bytes.Equal(payload, got) || accepts.Load() != 1 {
				t.Fatalf("recovery: write=%v equal=%v origin_accepts=%d", e, bytes.Equal(payload, got), accepts.Load())
			}
			// Repeated groups cross HTTP stream retirement and prevent a leaked
			// response body / request writer from hiding behind one successful flow.
			for group := 0; group < 5; group++ {
				t.Logf("starting short-flow group %d", group)
				var wg sync.WaitGroup
				errs := make(chan error, 8)
				for n := 0; n < 8; n++ {
					wg.Add(1)
					go func(n int) {
						defer wg.Done()
						x, e := s.Open(ctx, origin.Addr().String())
						if e != nil {
							errs <- e
							return
						}
						defer x.Close()
						p := []byte(fmt.Sprintf("small request %d/%d", group, n))
						if _, e = x.Write(p); e == nil {
							e = x.CloseWrite()
						}
						if e == nil {
							var out []byte
							out, e = io.ReadAll(x)
							if e == nil && !bytes.Equal(out, p) {
								e = fmt.Errorf("small request bytes changed")
							}
						}
						errs <- e
					}(n)
				}
				wg.Wait()
				close(errs)
				for e := range errs {
					if e != nil {
						t.Fatal(e)
					}
				}
				// Flow retirement runs on the session heartbeat. Wait for actual
				// retirement instead of exceeding MaxFlows between sweep ticks.
				until := time.Now().Add(2 * time.Second)
				for s.FlowCount() != 0 && time.Now().Before(until) {
					time.Sleep(10 * time.Millisecond)
				}
				if s.FlowCount() != 0 {
					t.Fatalf("group %d leaked %d session flows", group, s.FlowCount())
				}
			}
		})
	}
}

func webTestServer(t *testing.T, ctx context.Context) (Config, Config) {
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sc.WebListen = ln.Addr().String()
	_ = ln.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sc.HTTP3Listen = udp.LocalAddr().String()
	_ = udp.Close()
	sc.AllowPrivate = true
	sc.RateMbps, cc.RateMbps = 0, 0
	sctx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- RunServer(sctx, sc) }()
	t.Cleanup(func() {
		stop()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(2 * time.Second):
			t.Error("web server did not stop")
		}
	})
	return sc, cc
}

func attachWebTest(t *testing.T, ctx context.Context, cc, sc Config, s *session.Session, kind string, resume bool) *carrier.Link {
	t.Helper()
	addr := sc.WebListen
	if kind == "h3" {
		addr = sc.HTTP3Listen
	}
	ep := Endpoint{Network: kind, Address: addr, ServerName: "localhost"}
	tc, err := cc.webTLS(ep)
	if err != nil {
		t.Fatal(err)
	}
	token, err := Token(cc.TokenFile)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString(token)
	gate, err := cover.NewGate(key, cover.Config{Path: cc.WebPath})
	if err != nil {
		t.Fatal(err)
	}
	var l *carrier.Link
	for i := 0; i < 20; i++ {
		dctx, cancel := context.WithTimeout(ctx, time.Second)
		l, err = carrier.DialWeb(dctx, carrier.WebOptions{Network: kind, Address: addr, Authority: ep.ServerName,
			TLSConfig: tc, Gate: gate, Path: cc.WebPath, Padding: cc.WebPadding})
		cancel() // successful HTTP bodies must survive the dial context
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	l.SetHandshakeDeadline(time.Now().Add(2 * time.Second))
	b, _ := json.Marshal(hello{Version: wire.Version, Session: s.ID, Token: token, Resume: resume, Window: cc.Window})
	if err := l.HandshakeWrite(wire.Frame{Kind: wire.Hello, Payload: b}); err != nil {
		t.Fatal(err)
	}
	p, err := l.HandshakeRead()
	if err != nil {
		t.Fatal(err)
	}
	var w welcome
	if err := json.Unmarshal(p.Payload, &w); err != nil || p.Kind != wire.Welcome || !w.OK || w.Resumed != resume {
		t.Fatalf("welcome %+v: %v", w, err)
	}
	l.SetHandshakeDeadline(time.Time{})
	if err := s.Attach(l); err != nil {
		t.Fatal(err)
	}
	return l
}
