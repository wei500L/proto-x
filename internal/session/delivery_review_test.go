package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"proto-x/internal/wire"
)

func deliveryReviewSession(t *testing.T, probeOnly bool) *Session {
	t.Helper()
	cfg := testConfig()
	cfg.Heartbeat, cfg.DeadAfter, cfg.ResumeTTL = time.Hour, 2*time.Hour, 3*time.Hour
	cfg.RecoveryMode, cfg.RecoveryProbeOnly, cfg.RecoveryCountHistory = "adaptive", probeOnly, true
	s := New("delivery-review", false, cfg)
	t.Cleanup(func() { s.Close(context.Canceled) })
	return s
}

func deliveryReviewFlow(t *testing.T) *Flow {
	t.Helper()
	f := newFlow(deliveryReviewSession(t, false), 1, "example.test:443")
	f.opened, f.txBuf, f.txEnd, f.txSent = true, make([]byte, 100), 100, 100
	f.delivery.sent(1, wire.Frame{Kind: wire.Data, Payload: make([]byte, 100)}, time.Millisecond)
	return f
}

func TestDeliveryReviewACKValidationPrecedesProof(t *testing.T) {
	for _, bad := range []wire.Frame{
		{Kind: wire.Ack, Offset: 101, Limit: 101},
		{Kind: wire.Ack, Offset: 100, Limit: 99},
		{Kind: wire.Ack, Offset: 100, Limit: 1 << 30},
		{Kind: wire.Ack, Offset: 100, Limit: 100, Flags: wire.FlagFIN},
		{Kind: wire.Opened, Payload: []byte("unexpected payload")},
	} {
		f := deliveryReviewFlow(t)
		if at, err := f.receiveWithProof(bad, 1); err == nil || at != 0 {
			t.Fatalf("invalid ACK/OPENED manufactured proof: frame=%+v at=%s err=%v", bad, at, err)
		}
	}
	f := deliveryReviewFlow(t)
	ack := wire.Frame{Kind: wire.Ack, Offset: 100, Limit: 100}
	if at, err := f.receiveWithProof(ack, 1); err != nil || at != time.Millisecond {
		t.Fatalf("valid covered marker not proven: at=%s err=%v", at, err)
	}
	for _, p := range []wire.Frame{ack, {Kind: wire.Ack, Offset: 99, Limit: 99}} {
		if at, err := f.receiveWithProof(p, 1); err != nil || at != 0 {
			t.Fatalf("duplicate/stale ACK refreshed proof: at=%s err=%v", at, err)
		}
	}
}

func TestDeliveryReviewReplayFloorAcrossGenerations(t *testing.T) {
	var d deliveryProof
	d.sent(1, wire.Frame{Kind: wire.Open}, time.Millisecond)
	d.sent(1, wire.Frame{Kind: wire.Data, Payload: make([]byte, 100)}, 2*time.Millisecond)
	// The old attempted bytes are excluded even if Send failed or their ACK
	// was lost. A retransmission cannot assert new uplink activity by itself.
	d.sent(2, wire.Frame{Kind: wire.Open}, 3*time.Millisecond)
	d.sent(2, wire.Frame{Kind: wire.Data, Payload: make([]byte, 100)}, 4*time.Millisecond)
	if d.floor != 100 || d.n != 0 {
		t.Fatalf("replay entered fresh marker history: floor=%d n=%d", d.floor, d.n)
	}
	if got := d.acknowledged(2, wire.Frame{Kind: wire.Opened}, 0, false); got != 0 {
		t.Fatal("resumed OPENED was treated as a fresh first OPEN")
	}
	if got := d.acknowledged(2, wire.Frame{Kind: wire.Ack, Offset: 100}, 0, true); got != 0 {
		t.Fatal("ACK of replayed bytes refreshed proof")
	}
	d.sent(2, wire.Frame{Kind: wire.Data, Offset: 100, Payload: make([]byte, 100)}, 5*time.Millisecond)
	if got := d.acknowledged(1, wire.Frame{Kind: wire.Ack, Offset: 200}, 100, true); got != 0 {
		t.Fatal("old generation ACK used new markers")
	}
	if got := d.acknowledged(2, wire.Frame{Kind: wire.Ack, Offset: 200}, 100, true); got != 5*time.Millisecond {
		t.Fatalf("fresh post-floor bytes failed to prove send: %s", got)
	}
	d.sent(2, wire.Frame{Kind: wire.Data, Offset: 100, Payload: make([]byte, 100)}, 9*time.Millisecond)
	if got := d.acknowledged(2, wire.Frame{Kind: wire.Ack, Offset: 200}, 100, true); got != 5*time.Millisecond {
		t.Fatalf("same-generation resend changed original send timestamp: %s", got)
	}
}

func TestDeliveryReviewFirstOPENOnly(t *testing.T) {
	f := newFlow(deliveryReviewSession(t, false), 1, "example.test:443")
	f.delivery.sent(1, wire.Frame{Kind: wire.Open}, 7*time.Millisecond)
	p := wire.Frame{Kind: wire.Opened, Limit: uint64(f.s.cfg.Window)}
	if at, err := f.receiveWithProof(p, 1); err != nil || at != 7*time.Millisecond {
		t.Fatalf("first valid OPENED failed to prove OPEN: %s %v", at, err)
	}
	if at, err := f.receiveWithProof(p, 1); err != nil || at != 0 {
		t.Fatalf("repeated OPENED refreshed proof: %s %v", at, err)
	}
	f.delivery.sent(2, wire.Frame{Kind: wire.Open}, 10*time.Millisecond)
	if at, err := f.receiveWithProof(p, 2); err != nil || at != 0 {
		t.Fatalf("resumed OPENED refreshed proof: %s %v", at, err)
	}
}

func TestDeliveryReviewMarkerRingIsBoundedAndConservative(t *testing.T) {
	var d deliveryProof
	for i := 1; i <= 100; i++ {
		d.sent(1, wire.Frame{Kind: wire.Data, Offset: uint64((i - 1) * 10), Payload: make([]byte, 10)}, time.Duration(i)*time.Millisecond)
		if d.n > 8 || d.next < 0 || d.next >= 8 {
			t.Fatalf("marker storage escaped its bound: n=%d next=%d", d.n, d.next)
		}
	}
	if got := d.acknowledged(1, wire.Frame{Kind: wire.Ack, Offset: 900}, 0, true); got != 0 {
		t.Fatal("overwritten old marker manufactured evidence")
	}
	if got := d.acknowledged(1, wire.Frame{Kind: wire.Ack, Offset: 995}, 900, true); got != 99*time.Millisecond {
		t.Fatalf("partial cumulative ACK used an uncovered marker: %s", got)
	}
	if got := d.acknowledged(1, wire.Frame{Kind: wire.Ack, Offset: 999}, 995, true); got != 0 {
		t.Fatal("partial progress within an already covered marker refreshed evidence")
	}
	if got := d.acknowledged(1, wire.Frame{Kind: wire.Ack, Offset: 1000}, 995, true); got != 100*time.Millisecond {
		t.Fatalf("newest fully covered marker not used: %s", got)
	}
}

// Synthetic monotonic times isolate the manager-facing decision from packet
// scheduling. A stalled control probe can coexist with causally proven useful
// uplink progress; only recent SEND evidence makes it safe to cancel a hedge.
func TestDeliveryReviewStaleFeedbackCannotCancelPreparation(t *testing.T) {
	s := deliveryReviewSession(t, false)
	l := fenceLink(t)
	if err := s.Attach(l); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path.nsamples, s.path.next = 3, 3
	s.path.rtts[0], s.path.rtts[1], s.path.rtts[2] = 40*time.Millisecond, 40*time.Millisecond, 40*time.Millisecond
	s.path.sent(time.Second)
	f := newFlow(s, 1, "example.test:443")
	f.opened, f.txEnd, f.txBuf = true, 1, []byte{1}
	s.flows[1] = f
	const now = 2 * time.Second
	state := s.pathStateLocked(l, now)
	if !state.Confirmed || state.Threshold != 150*time.Millisecond {
		t.Fatal("fixture did not create a confirmed stalled control probe")
	}
	rtts, proof := s.path.rtts, state.Proof
	if s.path.delivered(900*time.Millisecond, now, state.Threshold) {
		t.Fatal("SEND before oldest probe canceled preparation")
	}
	if s.path.delivered(1100*time.Millisecond, now, state.Threshold) {
		t.Fatal("late ACK with stale SEND canceled preparation")
	}
	state = s.pathStateLocked(l, now)
	if !state.Confirmed || state.Proof != proof || state.ProbeAge != 900*time.Millisecond {
		t.Fatalf("stale feedback incorrectly recovered the path: %+v", state)
	}
	if !s.path.delivered(1950*time.Millisecond, now, state.Threshold) {
		t.Fatal("recent causally proven SEND did not cancel preparation")
	}
	state = s.pathStateLocked(l, now)
	if state.Suspect || state.ProbeAge != 50*time.Millisecond || state.Proof != proof+1 {
		t.Fatalf("useful progress did not bound stalled-probe age: %+v", state)
	}
	if s.path.npending != 1 || s.path.rtts != rtts || s.path.nsamples != 3 {
		t.Fatal("delivery evidence consumed probes or fabricated RTT samples")
	}
	for _, at := range []time.Duration{0, -1, 1800 * time.Millisecond, now + time.Nanosecond} {
		if s.path.delivered(at, now, state.Threshold) {
			t.Fatalf("invalid/older timestamp refreshed evidence: %s", at)
		}
	}
}

func TestDeliveryReviewBusinessProgressAndProbeOnlyAblation(t *testing.T) {
	for _, probeOnly := range []bool{false, true} {
		s := deliveryReviewSession(t, probeOnly)
		// Backdate only the synthetic session clock before any carrier starts.
		// Adaptive maintenance still ticks every 25 ms; the long deadlines limit
		// session expiry during the test rather than disabling its timer.
		s.mu.Lock()
		s.started = time.Now().Add(-2 * time.Second)
		s.mu.Unlock()
		l := fenceLink(t)
		if err := s.Attach(l); err != nil {
			t.Fatal(err)
		}
		f := newFlow(s, 1, "example.test:443")
		f.opened, f.txBuf, f.txEnd, f.txSent = true, make([]byte, 100), 100, 100
		s.mu.Lock()
		s.path.nsamples, s.path.next = 3, 3
		s.path.rtts[0], s.path.rtts[1], s.path.rtts[2] = 40*time.Millisecond, 40*time.Millisecond, 40*time.Millisecond
		at := time.Since(s.started)
		s.path.sent(time.Second)
		f.delivery.sent(1, wire.Frame{Kind: wire.Data, Payload: make([]byte, 100)}, at)
		s.flows[1] = f
		if state := s.pathStateLocked(l, at); !state.Confirmed {
			t.Error("control probe was not stalled before business acknowledgement")
		}
		s.mu.Unlock()
		if err := s.receiveFrame(l, wire.Frame{Kind: wire.Ack, ID: 1, Offset: 100, Limit: 100}); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		want := uint64(1)
		if probeOnly {
			want = 0
		}
		if s.path.proof != want || s.path.nsamples != 3 || s.path.npending != 1 {
			t.Errorf("business ACK proof=%d want=%d with probe_only=%v", s.path.proof, want, probeOnly)
		}
		if state := s.pathStateLocked(l, time.Since(s.started)); state.Confirmed != probeOnly || state.Suspect != probeOnly {
			t.Errorf("business progress did not change stalled-probe decision: probe_only=%v state=%+v", probeOnly, state)
		}
		before := s.path
		s.mu.Unlock()
		if err := s.receiveFrame(l, wire.Frame{Kind: wire.Data, ID: 1, Payload: []byte("downstream")}); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		if s.path != before {
			t.Error("downstream DATA manufactured uplink evidence")
		}
		s.mu.Unlock()
	}
}

func TestDeliveryReviewOldCarrierACKCannotRefreshNewPath(t *testing.T) {
	s := deliveryReviewSession(t, false)
	old, current := fenceLink(t), fenceLink(t)
	if err := s.Attach(old); err != nil {
		t.Fatal(err)
	}
	f := newFlow(s, 1, "example.test:443")
	f.opened, f.txBuf, f.txEnd = true, make([]byte, 100), 100
	f.delivery.sent(1, wire.Frame{Kind: wire.Data, Payload: make([]byte, 100)}, time.Microsecond)
	s.mu.Lock()
	s.flows[1] = f
	s.mu.Unlock()
	if err := s.Attach(current); err != nil {
		t.Fatal(err)
	}
	if err := s.receiveFrame(old, wire.Frame{Kind: wire.Ack, ID: 1, Offset: 100, Limit: 100}); !errors.Is(err, errStaleCarrier) {
		t.Fatalf("old carrier ACK was accepted: %v", err)
	}
	s.mu.Lock()
	if s.path.proof != 0 || s.path.deliveredAt != 0 {
		t.Error("old carrier ACK refreshed new path state")
	}
	s.mu.Unlock()
	f.mu.Lock()
	if f.txBase != 0 {
		t.Error("old carrier ACK advanced new generation flow offsets")
	}
	f.mu.Unlock()
}
