package session

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"proto-x/internal/carrier"
	"proto-x/internal/wire"
)

func fenceSession(t *testing.T) *Session {
	t.Helper()
	cfg := testConfig()
	cfg.Heartbeat, cfg.DeadAfter, cfg.ResumeTTL = time.Hour, 2*time.Hour, 3*time.Hour
	s := New("fence-test", true, cfg)
	t.Cleanup(func() { s.Close(context.Canceled) })
	return s
}

// These links use net.Pipe to isolate the attachment state machine from TLS
// and packet recovery. Web integration tests exercise the actual transports.
func fenceLink(t *testing.T) *carrier.Link {
	t.Helper()
	peer, conn := net.Pipe()
	l := carrier.AcceptTLS(conn)
	t.Cleanup(func() { _ = l.Close(); _ = peer.Close() })
	return l
}

func TestRecoveryAttemptFenceAndLegacyCompatibility(t *testing.T) {
	s := fenceSession(t)
	if err := s.Attach(fenceLink(t)); err != nil {
		t.Fatal(err)
	}
	if err := s.Attach(fenceLink(t)); err != nil {
		t.Fatalf("legacy sessions must retain legacy recovery: %v", err)
	}
	newest := fenceLink(t)
	if err := s.AttachAttempt(newest, 9); err != nil {
		t.Fatal(err)
	}
	_, generation, _ := s.Current()
	for _, attempt := range []uint64{8, 9, 0, 1} {
		if err := s.AttachAttempt(fenceLink(t), attempt); !errors.Is(err, ErrStaleAttempt) {
			t.Fatalf("attempt %d: got %v, want stale", attempt, err)
		}
		got, gen, _ := s.Current()
		if got != newest || gen != generation {
			t.Fatal("rejected attempt replaced the current carrier")
		}
	}
	if err := s.Attach(fenceLink(t)); !errors.Is(err, ErrStaleAttempt) {
		t.Fatalf("legacy Attach bypassed fence: %v", err)
	}
	closed := fenceLink(t)
	_ = closed.Close()
	if err := s.AttachAttempt(closed, 100); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("closed candidate: %v", err)
	}
	if err := s.AttachAttempt(fenceLink(t), 10); err != nil {
		t.Fatalf("failed closed candidate consumed sequence: %v", err)
	}
	s.Close(context.Canceled)
	if err := s.AttachAttempt(fenceLink(t), 11); !errors.Is(err, ErrSessionLost) {
		t.Fatalf("closed session accepted candidate: %v", err)
	}
}

func TestRecoveryConcurrentAttemptsCannotRollBack(t *testing.T) {
	s := fenceSession(t)
	const count = 32
	links := make([]*carrier.Link, count)
	for i := range links {
		links[i] = fenceLink(t)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, l := range links {
		wg.Add(1)
		go func(attempt uint64, l *carrier.Link) {
			defer wg.Done()
			<-start
			if err := s.AttachAttempt(l, attempt); err != nil && !errors.Is(err, ErrStaleAttempt) {
				t.Errorf("attempt %d: %v", attempt, err)
			}
		}(uint64(i+1), l)
	}
	close(start)
	wg.Wait()
	got, _, _ := s.Current()
	if got != links[count-1] {
		t.Fatal("a delayed smaller attempt replaced the greatest committed attempt")
	}
	select {
	case <-got.Done():
		t.Fatal("greatest committed attempt was closed by stale attachment cleanup")
	default:
	}
}

func TestRecoveryAttemptSequenceNeverReusesOrWraps(t *testing.T) {
	s := fenceSession(t)
	const count = 64
	values := make(chan uint64, count)
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := s.NextAttempt()
			if err != nil {
				t.Error(err)
			}
			values <- n
		}()
	}
	wg.Wait()
	close(values)
	seen := make(map[uint64]bool)
	for n := range values {
		if n == 0 || n > count || seen[n] {
			t.Fatalf("invalid or repeated attempt %d", n)
		}
		seen[n] = true
	}
	s.mu.Lock()
	s.nextAttempt = ^uint64(0) - 1
	s.mu.Unlock()
	if n, err := s.NextAttempt(); n != ^uint64(0) || err != nil {
		t.Fatalf("last valid sequence: %d %v", n, err)
	}
	for range 2 {
		if n, err := s.NextAttempt(); n != 0 || !errors.Is(err, ErrSessionLost) {
			t.Fatalf("sequence wrapped: %d %v", n, err)
		}
	}
}

func TestRecoveryOldFramesCannotMutateNewGeneration(t *testing.T) {
	s := fenceSession(t)
	old, current := fenceLink(t), fenceLink(t)
	if err := s.AttachAttempt(old, 1); err != nil {
		t.Fatal(err)
	}
	f := newFlow(s, 1, "example.test:443")
	f.opened, f.txBuf, f.txEnd = true, []byte("payload"), 7
	s.mu.Lock()
	s.flows[f.id] = f
	s.mu.Unlock()
	if err := s.AttachAttempt(current, 2); err != nil {
		t.Fatal(err)
	}
	for _, frame := range []wire.Frame{
		{Kind: wire.Reset, ID: f.id},
		{Kind: wire.Fin, ID: f.id},
		{Kind: wire.Data, ID: f.id, Payload: []byte("stale")},
		{Kind: wire.Ack, ID: f.id, Offset: 7, Limit: 7 + uint64(s.cfg.Window)},
		{Kind: wire.Open, ID: 3, Payload: []byte("other.test:443")},
	} {
		if err := s.receiveFrame(old, frame); !errors.Is(err, errStaleCarrier) {
			t.Fatalf("old frame kind=%d accepted: %v", frame.Kind, err)
		}
	}
	s.Drop(old)
	got, gen, _ := s.Current()
	if got != current || gen != 2 {
		t.Fatal("old carrier drop detached the new carrier")
	}
	f.mu.Lock()
	if f.err != nil || f.rxEOF || len(f.rxBuf) != 0 || f.txBase != 0 || string(f.txBuf) != "payload" {
		t.Error("old frame changed new-generation flow state")
	}
	f.mu.Unlock()
	if s.FlowCount() != 1 {
		t.Fatal("old OPEN created a target flow")
	}
	if err := s.receiveFrame(current, wire.Frame{Kind: wire.Data, ID: f.id, Payload: []byte("new")}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(f, buf); err != nil || string(buf) != "new" {
		t.Fatalf("new carrier no longer delivers: %q %v", buf, err)
	}
}

// A count window and an age window must both preserve genuinely slow paths.
// Sparse samples deliberately exceed every tested horizon, so the minimum
// history is exercised before and after several circular-buffer wraps.
func TestRecoveryHistorySparseRTTAndRingBoundaries(t *testing.T) {
	for _, rtt := range []time.Duration{time.Nanosecond, 40 * time.Millisecond, 900 * time.Millisecond, 30 * time.Second} {
		for _, countHistory := range []bool{false, true} {
			m := pathMonitor{countHistory: countHistory}
			for count := 0; count <= 80; count++ {
				if count > 0 {
					at := time.Duration(count) * time.Hour
					m.sent(at)
					if got, ok := m.replied(at, at+rtt); !ok || got != rtt {
						t.Fatalf("RTT %s sample %d was not accepted", rtt, count)
					}
				}
				before := m
				threshold, horizon, samples := m.tail(2 * time.Second)
				if m != before {
					t.Fatal("reading history mutated path progress")
				}
				if count < 3 {
					if samples != count || threshold != time.Second || horizon != 0 {
						t.Fatalf("cold start: count=%d threshold=%s horizon=%s samples=%d", count, threshold, horizon, samples)
					}
					continue
				}
				wantSamples := 3
				if countHistory {
					wantSamples = min(count, 32)
				}
				if samples != wantSamples || threshold < rtt || threshold < 150*time.Millisecond {
					t.Fatalf("sparse RTT=%s count=%d ablation=%v threshold=%s samples=%d", rtt, count, countHistory, threshold, samples)
				}
				if !countHistory && horizon < 8*rtt {
					t.Fatalf("slow path lost proportional horizon: RTT=%s H=%s", rtt, horizon)
				}
			}
		}
	}
}

func TestRecoveryHistoryIncludesExactHorizonBoundary(t *testing.T) {
	var m pathMonitor
	const rtt = 40 * time.Millisecond
	for _, received := range []time.Duration{100 * time.Millisecond, 1100 * time.Millisecond, 1600 * time.Millisecond, 2100 * time.Millisecond} {
		m.sent(received - rtt)
		m.replied(received-rtt, received)
	}
	_, horizon, samples := m.tail(2 * time.Second)
	if horizon != 2*time.Second || samples != 4 {
		t.Fatalf("sample exactly H old was excluded: H=%s n=%d", horizon, samples)
	}
	// A new real reply advances the reference time by one nanosecond. The
	// oldest observation is then outside H; the four newer ones remain.
	received := 2100*time.Millisecond + time.Nanosecond
	m.sent(received - rtt)
	m.replied(received-rtt, received)
	_, _, samples = m.tail(2 * time.Second)
	if samples != 4 {
		t.Fatalf("sample beyond H retained or fresh history lost: n=%d", samples)
	}
}

func TestRecoveryHistorySilenceAndInvalidPONGNeverRefreshEvidence(t *testing.T) {
	var m pathMonitor
	for i := 1; i <= 12; i++ {
		at := time.Duration(i) * time.Second
		rtt := 40 * time.Millisecond
		if i < 4 {
			rtt = 900 * time.Millisecond
		}
		m.sent(at)
		m.replied(at, at+rtt)
	}
	before := m
	threshold, horizon, samples := m.tail(2 * time.Second)
	for i := 1; i <= 100; i++ {
		m.sent(time.Duration(i) * time.Hour)
	}
	if _, ok := m.replied(12*time.Second, 200*time.Hour); ok {
		t.Fatal("replayed PONG refreshed evidence")
	}
	if _, ok := m.replied(123, 200*time.Hour); ok {
		t.Fatal("unmatched PONG refreshed evidence")
	}
	if _, ok := m.replied(time.Hour, time.Hour-time.Nanosecond); ok {
		t.Fatal("future matched timestamp refreshed evidence")
	}
	afterThreshold, afterHorizon, afterSamples := m.tail(2 * time.Second)
	if afterThreshold != threshold || afterHorizon != horizon || afterSamples != samples ||
		m.proof != before.proof || m.latestReply != before.latestReply ||
		m.nsamples != before.nsamples || m.next != before.next || m.rtts != before.rtts || m.rttAt != before.rttAt {
		t.Fatal("silence or invalid PONG modified accepted history")
	}
	if m.npending != 32 || m.pending[0] != time.Hour {
		t.Fatal("silence lost the oldest still-unanswered probe")
	}
}

func TestRecoveryHistoryResetIsFencedAndNeedsNewEvidence(t *testing.T) {
	for _, countHistory := range []bool{false, true} {
		cfg := testConfig()
		cfg.Heartbeat, cfg.DeadAfter, cfg.ResumeTTL = time.Hour, 2*time.Hour, 3*time.Hour
		cfg.RecoveryMode, cfg.RecoveryCountHistory = "adaptive", countHistory
		s := New("history-fence", true, cfg)
		t.Cleanup(func() { s.Close(context.Canceled) })
		old, current := fenceLink(t), fenceLink(t)
		if err := s.AttachAttempt(old, 1); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		for i := 0; i < 6; i++ {
			at := time.Duration(i+1) * time.Second
			s.path.sent(at)
			s.path.replied(at, at+900*time.Millisecond)
		}
		s.mu.Unlock()
		if err := s.AttachAttempt(current, 2); err != nil {
			t.Fatal(err)
		}
		if err := s.receiveFrame(old, wire.Frame{Kind: wire.Pong, Offset: 0}); !errors.Is(err, errStaleCarrier) {
			t.Fatalf("old PONG was not fenced: %v", err)
		}
		if err := s.receiveFrame(current, wire.Frame{Kind: wire.Pong, Offset: 0}); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		if s.path.nsamples != 0 || s.path.proof != 0 || s.path.latestReply != 0 || s.path.npending != 0 || s.path.countHistory != countHistory {
			t.Error("attachment retained old history or unsolicited PONG manufactured samples")
		}
		at := time.Since(s.started)
		s.path.sent(at)
		s.mu.Unlock()
		if err := s.receiveFrame(current, wire.Frame{Kind: wire.Pong, Offset: uint64(at)}); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		if s.path.nsamples != 1 || s.path.proof != 1 || s.path.latestReply == 0 {
			t.Error("fresh matched PONG was not accepted on the new carrier")
		}
		before := s.path
		s.mu.Unlock()
		if err := s.AttachAttempt(fenceLink(t), 1); !errors.Is(err, ErrStaleAttempt) {
			t.Fatalf("delayed attempt bypassed history fence: %v", err)
		}
		s.mu.Lock()
		if s.path != before {
			t.Error("rejected stale attempt reset current evidence")
		}
		s.mu.Unlock()
	}
}
