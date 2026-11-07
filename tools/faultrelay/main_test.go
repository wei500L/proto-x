package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type observedPacket struct {
	data []byte
	from *net.UDPAddr
}

type ownedOrigin struct {
	conn *net.UDPConn
	seen chan observedPacket
}

func echoOrigin(t *testing.T) *ownedOrigin {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	o := &ownedOrigin{conn: c, seen: make(chan observedPacket, 32)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var b [65536]byte
		for {
			n, addr, err := c.ReadFromUDP(b[:])
			if err != nil {
				return
			}
			o.seen <- observedPacket{append([]byte(nil), b[:n]...), addr}
			_, _ = c.WriteToUDP(b[:n], addr)
		}
	}()
	t.Cleanup(func() { c.Close(); <-done })
	return o
}

func (o *ownedOrigin) next(t *testing.T) observedPacket {
	t.Helper()
	select {
	case p := <-o.seen:
		return p
	case <-time.After(time.Second):
		t.Fatal("origin did not receive expected datagram")
		return observedPacket{}
	}
}

type harness struct {
	r      *relay
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

func launch(t *testing.T, origin *ownedOrigin, change func(*options)) *harness {
	t.Helper()
	o := options{listen: "127.0.0.1:0", target: origin.conn.LocalAddr().String(), fault: "rebind",
		after: 10 * time.Second, duration: 20 * time.Second, maxDatagram: 2048,
		events: filepath.Join(t.TempDir(), "events.jsonl")}
	if change != nil {
		change(&o)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r, err := newRelay(ctx, o)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	h := &harness{r: r, cancel: cancel, done: make(chan struct{})}
	go func() { h.err = r.run(ctx); close(h.done) }()
	t.Cleanup(func() { h.stop(t) })
	return h
}

func (h *harness) stop(t *testing.T) {
	t.Helper()
	h.cancel()
	select {
	case <-h.done:
		if h.err != nil {
			t.Errorf("relay run failed: %v", h.err)
		}
	case <-time.After(3 * time.Second):
		t.Error("relay shutdown did not finish")
	}
}

func udpClient(t *testing.T, addr *net.UDPAddr) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func echo(t *testing.T, c *net.UDPConn, payload []byte) {
	t.Helper()
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 65536)
	n, err := c.Read(b)
	if err != nil {
		t.Fatalf("echo failed: %v", err)
	}
	if !bytes.Equal(payload, b[:n]) {
		t.Fatal("datagram bytes changed")
	}
}

func noDatagram(t *testing.T, c *net.UDPConn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	var b [65536]byte
	if _, err := c.Read(b[:]); err == nil {
		t.Fatal("received a datagram that should have been dropped")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("expected timeout, got %v", err)
	}
}

func eventually(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true")
}

func snapshot(r *relay) counters {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

func readEvents(path string) ([]event, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	var es []event
	for {
		var e event
		if err = d.Decode(&e); err == io.EOF {
			return es, nil
		} else if err != nil {
			return es, err
		}
		es = append(es, e)
	}
}

func finalEvents(t *testing.T, h *harness) []event {
	t.Helper()
	h.stop(t)
	es, err := readEvents(h.r.o.events)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) < 2 || es[0].Event != "start" || es[len(es)-1].Event != "end" {
		t.Fatal("missing start/end event")
	}
	for i, e := range es {
		if e.ElapsedNS < 0 || (i > 0 && e.ElapsedNS < es[i-1].ElapsedNS) {
			t.Fatal("event clock is not monotonic")
		}
	}
	last := es[len(es)-1].Counters
	if last == nil {
		t.Fatal("final counters missing")
	}
	for _, c := range []directionCounters{last.Up, last.Down} {
		if c.Received.Packets != c.Forwarded.Packets+c.Dropped.Packets || c.Received.Bytes != c.Forwarded.Bytes+c.Dropped.Bytes {
			t.Fatal("final packet/byte counters do not conserve received traffic")
		}
	}
	b, _ := os.ReadFile(h.r.o.events)
	if strings.Contains(string(b), h.r.o.target) || strings.Contains(string(b), "127.0.0.1") {
		t.Fatal("target address leaked into event log")
	}
	return es
}

func TestBytePreservingForwardingAndClientPortHandoff(t *testing.T) {
	o := echoOrigin(t)
	h := launch(t, o, nil)
	c1 := udpClient(t, h.r.listener.LocalAddr().(*net.UDPAddr))
	c2 := udpClient(t, h.r.listener.LocalAddr().(*net.UDPAddr))
	for _, payload := range [][]byte{nil, []byte("small interactive datagram"), bytes.Repeat([]byte{0, 255, 42, 17}, 500)} {
		echo(t, c1, payload)
	}
	echo(t, c2, []byte("new local client port"))
	stats := snapshot(h.r)
	if stats.Up.Forwarded.Packets != 4 || stats.Down.Forwarded.Packets != 4 || stats.ClientSwitches != 1 {
		t.Fatalf("unexpected counters: %+v", stats)
	}
	finalEvents(t, h)
}

func TestBlackholeBothDirectionsAndRecovery(t *testing.T) {
	o := echoOrigin(t)
	h := launch(t, o, func(o *options) {
		o.fault = "blackhole"
		o.after = 100 * time.Millisecond
		o.forTime = 180 * time.Millisecond
		o.duration = 3 * time.Second
	})
	c := udpClient(t, h.r.listener.LocalAddr().(*net.UDPAddr))
	echo(t, c, []byte("before"))
	first := o.next(t)
	eventually(t, func() bool { h.r.mu.Lock(); defer h.r.mu.Unlock(); return h.r.blackhole })
	if _, err := c.Write([]byte("drop-up")); err != nil {
		t.Fatal(err)
	}
	if _, err := o.conn.WriteToUDP([]byte("drop-down"), first.from); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { s := snapshot(h.r); return s.Up.Blackhole.Packets == 1 && s.Down.Blackhole.Packets == 1 })
	noDatagram(t, c)
	select {
	case <-o.seen:
		t.Fatal("blackholed uplink reached origin")
	default:
	}
	eventually(t, func() bool { h.r.mu.Lock(); defer h.r.mu.Unlock(); return !h.r.blackhole })
	echo(t, c, []byte("after"))
	second := o.next(t)
	if first.from.Port != second.from.Port {
		t.Fatal("blackhole unexpectedly changed upstream socket")
	}
	es := finalEvents(t, h)
	var began, ended int64
	for _, e := range es {
		if e.Event == "fault_start" {
			began = e.ElapsedNS
		}
		if e.Event == "fault_end" {
			ended = e.ElapsedNS
		}
	}
	if began < int64(h.r.o.after) || ended-began < int64(h.r.o.forTime) {
		t.Fatal("fault window events are shorter than the actual requested window")
	}
}

func TestScheduledRebindChangesObservedPort(t *testing.T) {
	o := echoOrigin(t)
	h := launch(t, o, func(o *options) { o.after = 100 * time.Millisecond; o.duration = 3 * time.Second })
	listen := h.r.listener.LocalAddr().(*net.UDPAddr)
	c := udpClient(t, listen)
	echo(t, c, []byte("before-rebind"))
	first := o.next(t)
	eventually(t, func() bool { return snapshot(h.r).Rebinds == 1 })
	echo(t, c, []byte("after-rebind"))
	second := o.next(t)
	if first.from.Port == second.from.Port {
		t.Fatal("origin observed unchanged source port")
	}
	if h.r.listener.LocalAddr().String() != listen.String() {
		t.Fatal("client-facing listener changed")
	}
	es := finalEvents(t, h)
	for _, e := range es {
		if e.Event == "fault_start" && (e.PreviousSourcePort != first.from.Port || e.SourcePort != second.from.Port || e.ElapsedNS < int64(h.r.o.after)) {
			t.Fatal("rebind event disagrees with origin observations")
		}
	}
}

func TestOversizedDatagramsDiscardedBothDirections(t *testing.T) {
	o := echoOrigin(t)
	h := launch(t, o, func(o *options) { o.maxDatagram = 1200 })
	c := udpClient(t, h.r.listener.LocalAddr().(*net.UDPAddr))
	echo(t, c, []byte("prime"))
	first := o.next(t)
	// macOS commonly caps outgoing UDP payloads below 16 KiB. Four KiB is
	// still well above both this test's 1200-byte limit and the 2048 default.
	large := bytes.Repeat([]byte("x"), 4096)
	if _, err := c.Write(large); err != nil {
		t.Fatal(err)
	}
	if _, err := o.conn.WriteToUDP(large, first.from); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { s := snapshot(h.r); return s.Up.Oversize.Packets == 1 && s.Down.Oversize.Packets == 1 })
	noDatagram(t, c)
	select {
	case <-o.seen:
		t.Fatal("oversized uplink reached origin")
	default:
	}
	echo(t, c, []byte("small-after-oversize"))
	s := snapshot(h.r)
	if s.Up.Oversize.Bytes != uint64(len(large)) || s.Down.Oversize.Bytes != uint64(len(large)) {
		t.Fatal("oversized datagram byte counts are wrong")
	}
	finalEvents(t, h)
}

func TestDifferentClientIPRejected(t *testing.T) {
	o := echoOrigin(t)
	h := launch(t, o, nil)
	c1 := udpClient(t, h.r.listener.LocalAddr().(*net.UDPAddr))
	echo(t, c1, []byte("bind-first-ip"))
	c2, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)}, h.r.listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Skip("host does not expose a second loopback source IP")
	}
	defer c2.Close()
	if _, err := c2.Write([]byte("foreign-client")); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return snapshot(h.r).Up.ForeignClient.Packets == 1 })
	noDatagram(t, c2)
	echo(t, c1, []byte("original-still-active"))
	finalEvents(t, h)
}

func TestDurationStopsAndClosesSockets(t *testing.T) {
	o := echoOrigin(t)
	h := launch(t, o, func(o *options) {
		o.fault = "blackhole"
		o.after = 5 * time.Millisecond
		o.forTime = 10 * time.Millisecond
		o.duration = 40 * time.Millisecond
	})
	addr := h.r.listener.LocalAddr().(*net.UDPAddr)
	select {
	case <-h.done:
	case <-time.After(time.Second):
		t.Fatal("duration did not stop relay")
	}
	es := finalEvents(t, h)
	last := es[len(es)-1]
	if last.Reason != "duration" || last.ElapsedNS < int64(h.r.o.duration) {
		t.Fatal("unexpected duration completion")
	}
	check, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatal("listener remained bound after completion")
	}
	check.Close()
	if _, err := h.r.upstream.Write([]byte("closed")); err == nil {
		t.Fatal("upstream remained open after completion")
	}
}

func TestRejectsUnsafeListenersAndInvalidLimits(t *testing.T) {
	base := options{listen: "127.0.0.1:0", target: "127.0.0.1:1234", fault: "blackhole", after: time.Second, forTime: time.Second, duration: 3 * time.Second, maxDatagram: 2048, events: "-"}
	for _, addr := range []string{"0.0.0.0:1234", ":1234", "localhost:1234", "192.0.2.1:1234", "[::]:1234", "127.0.0.1:-1"} {
		o := base
		o.listen = addr
		if validateOptions(o) == nil {
			t.Errorf("accepted unsafe listener %q", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0"} {
		o := base
		o.listen = addr
		if err := validateOptions(o); err != nil {
			t.Errorf("rejected loopback listener %q", addr)
		}
	}
	o := base
	o.forTime = 4 * time.Second
	if validateOptions(o) == nil {
		t.Fatal("accepted fault longer than relay lifetime")
	}
	_, err := parseOptions([]string{"-target", "secret.example.invalid:443", "-bad-flag"}, io.Discard)
	if err == nil {
		t.Fatal("accepted unknown flag")
	}
}

func TestSignalHelper(t *testing.T) {
	if os.Getenv("PROTOX_FAULTRELAY_SIGNAL_HELPER") != "1" {
		return
	}
	for i, a := range os.Args {
		if a == "--" {
			os.Args = append([]string{"faultrelay"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func TestSIGTERMFlushesEndCountersDuringBlackhole(t *testing.T) {
	o := echoOrigin(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signal.jsonl")
	cmd := exec.Command(executable, "-test.run=^TestSignalHelper$", "--", "-target", o.conn.LocalAddr().String(), "-listen", "127.0.0.1:0", "-fault", "blackhole", "-after", "150ms", "-for", "5s", "-duration", "10s", "-events", path)
	cmd.Env = append(os.Environ(), "PROTOX_FAULTRELAY_SIGNAL_HELPER=1")
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	var port int
	eventually(t, func() bool {
		es, _ := readEvents(path)
		if len(es) > 0 {
			port = es[0].ListenPort
		}
		return port != 0
	})
	c := udpClient(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	echo(t, c, []byte("signal-test"))
	eventually(t, func() bool {
		es, _ := readEvents(path)
		for _, e := range es {
			if e.Event == "fault_start" {
				return true
			}
		}
		return false
	})
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("signal shutdown failed: %v; %s", err, output.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SIGTERM did not stop process promptly")
	}
	es, err := readEvents(path)
	if err != nil {
		t.Fatal("signal left incomplete JSONL:", err)
	}
	if len(es) < 2 {
		t.Fatal("signal lost event log")
	}
	last := es[len(es)-1]
	if last.Event != "end" || last.Reason != "context_cancelled" || last.Counters == nil || last.Counters.Up.Forwarded.Packets != 1 || last.Counters.Down.Forwarded.Packets != 1 {
		t.Fatal("signal lost final counters")
	}
	if es[len(es)-2].Event != "fault_end" || es[len(es)-2].Reason != "shutdown_before_restore" {
		t.Fatal("interrupted blackhole not recorded")
	}
}
