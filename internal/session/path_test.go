package session

import (
	"context"
	"net"
	"testing"
	"time"

	"proto-x/internal/carrier"
	"proto-x/internal/wire"
)

func TestPathMonitorRequiresMatchedRoundTrip(t *testing.T) {
	var m pathMonitor
	for i := 1; i <= 3; i++ {
		at := time.Duration(i) * time.Second
		m.sent(at)
		if rtt, ok := m.replied(at, at+40*time.Millisecond); !ok || rtt != 40*time.Millisecond {
			t.Fatal("matched probe did not record a round trip")
		}
	}
	m.sent(4 * time.Second)
	if _, ok := m.replied(1, 5*time.Second); ok || m.proof != 3 || m.npending != 1 {
		t.Fatal("unsolicited PONG manufactured progress")
	}
	for i := 5; i < 100; i++ {
		m.sent(time.Duration(i) * time.Second)
	}
	if m.npending != len(m.pending) || m.pending[0] != 4*time.Second {
		t.Fatal("bounded pending history lost the oldest unanswered probe")
	}
}

func TestPathPatienceScalesWithRTTAndJitter(t *testing.T) {
	var slow, fast, jitter pathMonitor
	for i := 0; i < 32; i++ {
		at := time.Duration(i+1) * time.Second
		for _, v := range []struct {
			m   *pathMonitor
			rtt time.Duration
		}{
			{&fast, 40 * time.Millisecond}, {&slow, 900 * time.Millisecond},
			{&jitter, time.Duration(40+(i%4)*40) * time.Millisecond},
		} {
			v.m.sent(at)
			v.m.replied(at, at+v.rtt)
		}
	}
	if fast.threshold(2*time.Second) != 150*time.Millisecond {
		t.Fatal("fast stable path did not reach minimum patience")
	}
	if slow.threshold(2*time.Second) <= 900*time.Millisecond || jitter.threshold(2*time.Second) <= fast.threshold(2*time.Second) {
		t.Fatal("slow or variable path was treated like a fast path")
	}
}

func TestPathDemandAndUnidirectionalProgress(t *testing.T) {
	cfg := testConfig()
	cfg.RecoveryMode = "adaptive"
	s := New("path-unit", false, cfg)
	defer s.Close(context.Canceled)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	l := carrier.AcceptTLS(a)
	defer l.Close()
	// A deterministic state fixture; no transport is started by this test.
	s.mu.Lock()
	s.link = l
	s.gen = 1
	s.path.nsamples = 3
	s.path.next = 3
	s.path.rtts[0], s.path.rtts[1], s.path.rtts[2] = 40*time.Millisecond, 40*time.Millisecond, 40*time.Millisecond
	s.path.sent(time.Millisecond)
	state := s.pathStateLocked(l, time.Second)
	s.mu.Unlock()
	if state.Suspect || state.Demand {
		t.Fatal("idle application triggered speculative connection")
	}
	s.mu.Lock()
	f := newFlow(s, 1, "unused.test:443")
	s.flows[1] = f
	state = s.pathStateLocked(l, time.Second)
	f.opened = true
	s.mu.Unlock()
	if !state.Confirmed {
		t.Fatal("pending OPEN did not create actionable demand")
	}
	if err := s.receiveFrame(l, wire.Frame{Kind: wire.Data, ID: 1, Payload: []byte("stream data")}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	state = s.pathStateLocked(l, 400*time.Millisecond)
	s.mu.Unlock()
	if !state.Confirmed || state.Proof != 0 {
		t.Fatal("downstream DATA hid unanswered upstream probes")
	}
}

func TestPathHistoryExpiresQueueSpikesWithoutLearningFromSilence(t *testing.T) {
	aged := pathMonitor{}
	count := pathMonitor{countHistory: true}
	// A representative trace from the pilot's failure: three old queue spikes
	// survive in a count window while subsequent successful replies are steady.
	for i := 0; i < 26; i++ {
		rtt := 102 * time.Millisecond
		if i == 2 {
			rtt = 206 * time.Millisecond
		}
		if i == 3 {
			rtt = 210 * time.Millisecond
		}
		if i == 4 {
			rtt = 332 * time.Millisecond
		}
		at := time.Second + time.Duration(i)*350*time.Millisecond
		for _, m := range []*pathMonitor{&aged, &count} {
			m.sent(at)
			m.replied(at, at+rtt)
		}
	}
	if got := count.threshold(2 * time.Second); got != 622*time.Millisecond {
		t.Fatalf("count-history reference = %s", got)
	}
	before, horizon, n := aged.tail(2 * time.Second)
	if before != 150*time.Millisecond || horizon != 2*time.Second || n >= count.nsamples || n < 3 {
		t.Fatalf("stale spike retained: threshold=%s horizon=%s samples=%d", before, horizon, n)
	}
	// Timeouts and unanswered probes cannot erase the evidence for an outage.
	for i := 0; i < 40; i++ {
		aged.sent(time.Hour + time.Duration(i)*time.Second)
	}
	if after := aged.threshold(2 * time.Second); after != before {
		t.Fatalf("silence altered the detector: %s -> %s", before, after)
	}
}
