package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proto-x/internal/carrier"
	"proto-x/internal/wire"
)

func testConfig() Config {
	return Config{Window: 16 << 10, MaxFlows: 16, Heartbeat: 100 * time.Millisecond,
		DeadAfter: time.Second, ResumeTTL: 2 * time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

type memorySessions struct {
	client, server *Session
	cl, sl         *carrier.Link
	dials          atomic.Int64
}

func newMemorySessions(t *testing.T, cfg Config) *memorySessions {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p := &memorySessions{}
	scfg := cfg
	scfg.Dial = func(ctx context.Context, target string) (net.Conn, error) {
		p.dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", target)
	}
	p.client = New("test-session", false, cfg)
	p.server = New("test-session", true, scfg)
	t.Cleanup(func() {
		p.client.Close(context.Canceled)
		p.server.Close(context.Canceled)
	})
	p.attach(t)
	return p
}

// AcceptTLS here deliberately wraps an in-memory byte pipe, not a TLS socket.
// These tests exercise the session protocol independently of cryptography and
// the network. Carrier package tests cover actual TLS/QUIC separately.
func (p *memorySessions) attach(t *testing.T) {
	t.Helper()
	c, s := net.Pipe()
	p.cl, p.sl = carrier.AcceptTLS(c), carrier.AcceptTLS(s)
	if err := p.server.Attach(p.sl); err != nil {
		t.Fatal(err)
	}
	if err := p.client.Attach(p.cl); err != nil {
		t.Fatal(err)
	}
}

func (p *memorySessions) drop() {
	p.client.Drop(p.cl)
	p.server.Drop(p.sl)
}

type origin struct {
	address string
	count   atomic.Int64
}

func listenOrigin(t *testing.T, handle func(*net.TCPConn)) *origin {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &origin{address: l.Addr().String()}
	var mu sync.Mutex
	connections := make(map[*net.TCPConn]struct{})
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		defer mu.Unlock()
		for c := range connections {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			tcp := c.(*net.TCPConn)
			mu.Lock()
			connections[tcp] = struct{}{}
			mu.Unlock()
			o.count.Add(1)
			go func() {
				defer tcp.Close()
				defer func() { mu.Lock(); delete(connections, tcp); mu.Unlock() }()
				handle(tcp)
			}()
		}
	}()
	return o
}

func openTestFlow(t *testing.T, s *Session, target string) *Flow {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	f, err := s.Open(ctx, target)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return f
}

func deterministicBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func waitCondition(t *testing.T, timeout time.Duration, description string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	var stacks bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&stacks, 2)
	t.Fatalf("timed out waiting for %s\n%s", description, stacks.String())
}

func TestBidirectionalBytesAndTCPHalfClose(t *testing.T) {
	request := deterministicBytes(2<<20, 10)
	reply := deterministicBytes((1<<20)+31, 11)
	originErr := make(chan error, 1)
	o := listenOrigin(t, func(c *net.TCPConn) {
		body, err := io.ReadAll(c)
		if err == nil && !bytes.Equal(body, request) {
			err = errors.New("origin request bytes differ")
		}
		if err == nil {
			_, err = c.Write(reply)
		}
		if err == nil {
			err = c.CloseWrite()
		}
		originErr <- err
	})
	p := newMemorySessions(t, testConfig())
	f := openTestFlow(t, p.client, o.address)
	result := make(chan error, 1)
	go func() {
		_, err := f.Write(request)
		if err == nil {
			err = f.CloseWrite()
		}
		if err == nil {
			var body []byte
			body, err = io.ReadAll(f)
			if err == nil && !bytes.Equal(body, reply) {
				err = errors.New("reply differs or was truncated")
			}
		}
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("bidirectional transfer/half-close stalled")
	}
	if err := <-originErr; err != nil {
		t.Fatal(err)
	}
	f.Close()
	waitCondition(t, 2*time.Second, "both clean flows to retire", func() bool { return p.client.FlowCount() == 0 && p.server.FlowCount() == 0 })
	select {
	case <-f.done:
	default:
		t.Fatal("clean flow was removed without terminating its sender")
	}
	if p.dials.Load() != 1 || o.count.Load() != 1 {
		t.Fatalf("expected exactly one origin socket, got dials=%d accepts=%d", p.dials.Load(), o.count.Load())
	}
}

func TestCarrierReplacementPreservesOriginalSocketAndBytes(t *testing.T) {
	payload := deterministicBytes(2<<20, 20)
	reached := make(chan struct{})
	gate := make(chan struct{})
	var gateOnce sync.Once
	openGate := func() { gateOnce.Do(func() { close(gate) }) }
	t.Cleanup(openGate)
	o := listenOrigin(t, func(c *net.TCPConn) {
		b := make([]byte, 8192)
		var nTotal int
		paused := false
		for {
			n, err := c.Read(b)
			if n > 0 {
				if _, e := c.Write(b[:n]); e != nil {
					return
				}
				nTotal += n
				if !paused && nTotal >= 128<<10 {
					paused = true
					close(reached)
					<-gate
				}
			}
			if err != nil {
				c.CloseWrite()
				return
			}
		}
	})
	p := newMemorySessions(t, testConfig())
	f := openTestFlow(t, p.client, o.address)
	p.server.mu.Lock()
	serverFlow := p.server.flows[f.id]
	p.server.mu.Unlock()
	serverFlow.mu.Lock()
	originalSocket := serverFlow.socket
	serverFlow.mu.Unlock()
	writeResult := make(chan error, 1)
	readResult := make(chan error, 1)
	go func() {
		_, err := f.Write(payload)
		if err == nil {
			err = f.CloseWrite()
		}
		writeResult <- err
	}()
	go func() {
		got, err := io.ReadAll(f)
		if err == nil && !bytes.Equal(got, payload) {
			err = errors.New("resumed stream contains missing, duplicated or changed bytes")
		}
		readResult <- err
	}()
	select {
	case <-reached:
	case <-time.After(3 * time.Second):
		t.Fatal("transfer never reached interruption point")
	}
	p.drop()
	// Both session buffers must remain bounded while their carrier is gone.
	time.Sleep(30 * time.Millisecond)
	for _, flow := range []*Flow{f, serverFlow} {
		flow.mu.Lock()
		tx, rx := len(flow.txBuf), len(flow.rxBuf)
		flow.mu.Unlock()
		if tx > p.client.cfg.Window || rx > p.client.cfg.Window {
			t.Fatalf("unbounded detached buffer tx=%d rx=%d", tx, rx)
		}
	}
	select {
	case err := <-readResult:
		t.Fatalf("carrier loss was exposed as application completion: %v", err)
	default:
	}
	p.attach(t)
	openGate()
	for name, ch := range map[string]<-chan error{"writer": writeResult, "reader": readResult} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		case <-time.After(8 * time.Second):
			t.Fatalf("%s did not recover", name)
		}
	}
	serverFlow.mu.Lock()
	stillSameSocket := serverFlow.socket == originalSocket
	serverFlow.mu.Unlock()
	if !stillSameSocket || p.dials.Load() != 1 || o.count.Load() != 1 {
		t.Fatalf("resume redialed origin: same=%v dials=%d accepts=%d", stillSameSocket, p.dials.Load(), o.count.Load())
	}
	f.Close()
	waitCondition(t, 2*time.Second, "resumed flows to retire", func() bool { return p.client.FlowCount() == 0 && p.server.FlowCount() == 0 })
}

func TestDetachedExpiryUnblocksReadersAndWriters(t *testing.T) {
	o := listenOrigin(t, func(c *net.TCPConn) { io.Copy(io.Discard, c) })
	cfg := testConfig()
	cfg.Window = 4096
	cfg.DeadAfter = 200 * time.Millisecond
	cfg.ResumeTTL = 300 * time.Millisecond
	p := newMemorySessions(t, cfg)
	f := openTestFlow(t, p.client, o.address)
	p.drop()
	readResult := make(chan error, 1)
	writeResult := make(chan error, 1)
	go func() { _, err := f.Read(make([]byte, 1)); readResult <- err }()
	go func() { _, err := f.Write(make([]byte, 8<<10)); writeResult <- err }()
	for name, ch := range map[string]<-chan error{"reader": readResult, "writer": writeResult} {
		select {
		case err := <-ch:
			if !errors.Is(err, ErrSessionLost) {
				t.Fatalf("%s got %v, want ErrSessionLost", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s stayed blocked after session expiry", name)
		}
	}
	if p.dials.Load() != 1 {
		t.Fatal("expiry replayed a target connection")
	}
	c, peer := net.Pipe()
	defer peer.Close()
	l := carrier.AcceptTLS(c)
	defer l.Close()
	if err := p.client.Attach(l); !errors.Is(err, ErrSessionLost) {
		t.Fatalf("expired session accepted a new carrier: %v", err)
	}
}

func TestDuplicateDataAndFlowControlValidation(t *testing.T) {
	s := New("validation", false, testConfig())
	defer s.Close(context.Canceled)
	f := newFlow(s, 1, "127.0.0.1:1")
	f.opened = true
	for _, p := range []wire.Frame{
		{Kind: wire.Data, ID: 1, Offset: 0, Payload: []byte("abc")},
		{Kind: wire.Data, ID: 1, Offset: 0, Payload: []byte("abc")},
		{Kind: wire.Data, ID: 1, Offset: 1, Payload: []byte("bcdef")},
	} {
		if err := f.receive(p); err != nil {
			t.Fatal(err)
		}
	}
	b := make([]byte, 6)
	if n, err := f.Read(b); err != nil || n != 6 || string(b) != "abcdef" || s.DuplicateBytes.Load() != 5 {
		t.Fatalf("deduplication failed: n=%d err=%v body=%q duplicates=%d", n, err, b, s.DuplicateBytes.Load())
	}
	if err := f.receive(wire.Frame{Kind: wire.Fin, ID: 1, Offset: 6}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read(b); err != io.EOF {
		t.Fatalf("missing EOF: %v", err)
	}
	for _, p := range []wire.Frame{
		{Kind: wire.Data, ID: 1, Offset: 6, Payload: []byte("x")},
		{Kind: wire.Data, ID: 1, Offset: ^uint64(0), Payload: []byte("x")},
		{Kind: wire.Fin, ID: 1, Offset: 7},
		{Kind: wire.Ack, ID: 1, Offset: 1, Limit: 1},
		{Kind: wire.Ack, ID: 1, Offset: 0, Limit: uint64(s.cfg.Window) + 1},
		{Kind: wire.Ack, ID: 1, Flags: wire.FlagFIN},
	} {
		if err := f.receive(p); !errors.Is(err, ErrProtocol) {
			t.Errorf("accepted invalid frame %+v: %v", p, err)
		}
	}
	full := newFlow(s, 3, "127.0.0.1:1")
	full.opened = true
	if err := full.receive(wire.Frame{Kind: wire.Data, ID: 3, Payload: make([]byte, s.cfg.Window)}); err != nil {
		t.Fatal(err)
	}
	if err := full.receive(wire.Frame{Kind: wire.Data, ID: 3, Offset: uint64(s.cfg.Window), Payload: []byte{0}}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("receive-window overflow was accepted: %v", err)
	}
}

func TestNormalFlowsRetireSendersAndPruneOldTombstones(t *testing.T) {
	o := listenOrigin(t, func(c *net.TCPConn) { io.Copy(io.Discard, c); c.CloseWrite() })
	p := newMemorySessions(t, testConfig())
	var closed []*Flow
	for batch := 0; batch < 3; batch++ {
		for i := 0; i < 8; i++ {
			f := openTestFlow(t, p.client, o.address)
			f.CloseWrite()
			if _, err := io.ReadAll(f); err != nil {
				t.Fatal(err)
			}
			f.Close()
			closed = append(closed, f)
		}
		waitCondition(t, 2*time.Second, "clean batch retirement", func() bool { return p.client.FlowCount() == 0 && p.server.FlowCount() == 0 })
	}
	for _, f := range closed {
		select {
		case <-f.done:
		default:
			t.Fatalf("flow %d retained its send loop", f.id)
		}
	}
	// Jump the monotonic ID frontier rather than spend thousands of sockets
	// exercising the identical cleanup path. Existing closed IDs must then be
	// pruned on both endpoints, and replay must not recreate their sockets.
	p.client.mu.Lock()
	p.client.nextID = 20001
	p.client.mu.Unlock()
	f := openTestFlow(t, p.client, o.address)
	f.CloseWrite()
	if _, err := io.ReadAll(f); err != nil {
		t.Fatal(err)
	}
	f.Close()
	waitCondition(t, 2*time.Second, "tombstone frontier pruning", func() bool {
		p.client.mu.Lock()
		cn := len(p.client.tombs)
		p.client.mu.Unlock()
		p.server.mu.Lock()
		sn := len(p.server.tombs)
		p.server.mu.Unlock()
		return p.client.FlowCount() == 0 && p.server.FlowCount() == 0 && cn == 1 && sn == 1
	})
	before := p.dials.Load()
	if err := p.cl.Send(wire.Frame{Kind: wire.Open, ID: 1, Payload: []byte(o.address)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if p.dials.Load() != before {
		t.Fatal("a pruned old flow ID opened a new target socket")
	}
	// Channel retirement is deterministic. Stack sampling additionally detects
	// the previous bug where retired Flow objects left blocked sendLoop goroutines.
	runtime.Gosched()
	waitCondition(t, time.Second, "all flow sender goroutines to exit", func() bool {
		var stacks bytes.Buffer
		pprof.Lookup("goroutine").WriteTo(&stacks, 2)
		return !strings.Contains(stacks.String(), "proto-x/internal/session.(*Flow).sendLoop(")
	})
}

func TestCloseWriteUnblocksAFullSendBuffer(t *testing.T) {
	cfg := testConfig()
	cfg.Window = 4096
	s := New("half-close-blocked-writer", false, cfg)
	defer s.Close(context.Canceled)
	f := newFlow(s, 1, "127.0.0.1:1")
	s.mu.Lock()
	s.flows[f.id] = f
	s.mu.Unlock()
	result := make(chan error, 1)
	go func() { _, err := f.Write(make([]byte, cfg.Window*2)); result <- err }()
	waitCondition(t, time.Second, "writer to fill its bounded send buffer", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.txBuf) == cfg.Window
	})
	f.CloseWrite()
	select {
	case err := <-result:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("blocked Write got %v after CloseWrite", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("CloseWrite did not wake a writer blocked on its full send buffer")
	}
}

type filteredWriteConn struct {
	net.Conn
	drop func(wire.Frame) bool
}

func (c *filteredWriteConn) Write(b []byte) (int, error) {
	f, err := wire.Read(bytes.NewReader(b))
	if err == nil && c.drop(f) {
		// Fault injection at the carrier's accepted-write boundary: a frame
		// that the writer accepted but that the lost carrier never delivered.
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func TestCompletedTombstoneRecoversAnUndeliveredFinalFINAck(t *testing.T) {
	request, reply := []byte("request bytes"), []byte("reply bytes")
	originErr := make(chan error, 1)
	o := listenOrigin(t, func(c *net.TCPConn) {
		b, err := io.ReadAll(c)
		if err == nil && !bytes.Equal(b, request) {
			err = errors.New("origin request mismatch")
		}
		if err == nil {
			_, err = c.Write(reply)
		}
		c.CloseWrite()
		originErr <- err
	})
	p := newMemorySessions(t, testConfig())
	p.drop()
	left, right := net.Pipe()
	var dropped atomic.Int64
	filtered := &filteredWriteConn{Conn: right, drop: func(f wire.Frame) bool {
		if f.Kind == wire.Ack && f.Flags&wire.FlagFIN != 0 {
			dropped.Add(1)
			return true
		}
		return false
	}}
	p.cl, p.sl = carrier.AcceptTLS(left), carrier.AcceptTLS(filtered)
	if err := p.server.Attach(p.sl); err != nil {
		t.Fatal(err)
	}
	if err := p.client.Attach(p.cl); err != nil {
		t.Fatal(err)
	}
	f := openTestFlow(t, p.client, o.address)
	if _, err := f.Write(request); err != nil {
		t.Fatal(err)
	}
	f.CloseWrite()
	got, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(got, reply) {
		t.Fatalf("initial reply: %q %v", got, err)
	}
	if err := <-originErr; err != nil {
		t.Fatal(err)
	}
	waitCondition(t, time.Second, "only server flow to retire after final ACK write", func() bool {
		return p.server.FlowCount() == 0 && p.client.FlowCount() == 1 && dropped.Load() > 0
	})
	f.mu.Lock()
	ackedBefore := f.txFinAck
	f.mu.Unlock()
	if ackedBefore {
		t.Fatal("fault injection did not withhold the FIN acknowledgement")
	}
	p.drop()
	p.attach(t)
	waitCondition(t, time.Second, "tombstone to complete the surviving peer's FIN state", func() bool { return p.client.FlowCount() == 0 })
	f.mu.Lock()
	finalErr, ackedAfter := f.err, f.txFinAck
	f.mu.Unlock()
	if finalErr != nil || !ackedAfter || p.dials.Load() != 1 || o.count.Load() != 1 {
		t.Fatalf("tombstone resume failed: err=%v ack=%v dials=%d accepts=%d", finalErr, ackedAfter, p.dials.Load(), o.count.Load())
	}
}

func TestSimultaneousControlResponsesDoNotBlockSessionReceivers(t *testing.T) {
	p := newMemorySessions(t, testConfig())
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	gate := make(chan struct{})
	for i, l := range []*carrier.Link{p.cl, p.sl} {
		s := []*Session{p.client, p.server}[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			for i := 0; i < 32; i++ {
				if err := l.Send(wire.Frame{Kind: wire.Ping, Offset: uint64(time.Since(s.started))}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	close(gate)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("symmetric control traffic blocked both receivers")
	}
	select {
	case err := <-errs:
		t.Fatal(err)
	default:
	}
	waitCondition(t, 500*time.Millisecond, "bidirectional Pong reception", func() bool { return p.client.RTTNanos.Load() > 0 && p.server.RTTNanos.Load() > 0 })
	if l, _, _ := p.client.Current(); l != p.cl {
		t.Fatal("control pressure detached a healthy carrier")
	}
	if l, _, _ := p.server.Current(); l != p.sl {
		t.Fatal("control pressure detached a healthy carrier")
	}
}
