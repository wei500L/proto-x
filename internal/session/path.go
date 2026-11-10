package session

import (
	"slices"
	"time"

	"proto-x/internal/carrier"
	"proto-x/internal/wire"
)

// pathMonitor estimates application-level round-trip progress. In contrast to
// lastRX, an unmatched downstream DATA record does not prove the uplink works.
// All times are monotonic offsets from Session.started. The bounded history is
// intentionally reset on attachment: different carriers need separate evidence.
type pathMonitor struct {
	pending        [32]time.Duration
	npending       int
	rtts           [32]time.Duration
	rttAt          [32]time.Duration
	nsamples, next int
	lastProbe      time.Duration
	latestReply    time.Duration
	deliveredAt    time.Duration
	proof          uint64
	countHistory   bool
}

func (m *pathMonitor) sent(at time.Duration) {
	if m.npending < len(m.pending) {
		m.pending[m.npending] = at
		m.npending++
	}
	// If full, retain the oldest probe. Discarding it would continuously
	// postpone suspicion during a prolonged blackhole.
	m.lastProbe = at
}

func (m *pathMonitor) replied(offset, now time.Duration) (time.Duration, bool) {
	index := -1
	for i := 0; i < m.npending; i++ {
		if m.pending[i] == offset {
			index = i
			break
		}
	}
	if index < 0 || offset > now {
		return 0, false
	}
	rtt := now - offset
	copy(m.pending[:], m.pending[index+1:m.npending])
	m.npending -= index + 1
	m.rtts[m.next] = rtt
	m.rttAt[m.next] = now
	m.latestReply = now
	m.next = (m.next + 1) % len(m.rtts)
	m.nsamples = min(m.nsamples+1, len(m.rtts))
	m.proof++
	return rtt, true
}

// delivered records the time of the causally proven SEND, not ACK arrival.
// Keep unanswered probes for RTT sampling; useful progress bounds their effective
// age without letting delayed feedback sent before a failure hide that failure.
func (m *pathMonitor) delivered(sent, now, patience time.Duration) bool {
	if sent <= m.deliveredAt || sent <= 0 || sent > now {
		return false
	}
	m.deliveredAt = sent
	// Old feedback may refine the age bound, but cannot cancel a prepared
	// alternate and impose the manager's cooldown while still suspect.
	if now-sent > patience || (m.npending > 0 && sent <= m.pending[0]) {
		return false
	}
	m.proof++
	return true
}

func (m *pathMonitor) threshold(fallback time.Duration) time.Duration {
	t, _, _ := m.tail(fallback)
	return t
}

func (m *pathMonitor) tail(fallback time.Duration) (time.Duration, time.Duration, int) {
	if m.nsamples < 3 {
		return fallback / 2, 0, m.nsamples
	}
	var ordered [32]time.Duration
	copy(ordered[:], m.rtts[:m.nsamples])
	slices.Sort(ordered[:m.nsamples])
	n := m.nsamples
	var horizon time.Duration
	if !m.countHistory {
		// Sampling frequency is itself controlled by the estimated tail. A
		// pure 32-sample window therefore preserves old queue spikes longest
		// precisely when they have slowed probing. Age samples relative to the
		// last matched reply, not timeouts: absence of evidence must never age
		// away the evidence being used to decide an ongoing failure.
		horizon = max(2*time.Second, 8*ordered[(n-1)/2])
		n = 0
		for age := 0; age < m.nsamples; age++ {
			i := (m.next - 1 - age + len(m.rtts)) % len(m.rtts)
			// Retain three observations on sparse/high RTT paths. Persistent
			// high RTT remains high; only stale, isolated queue spikes expire.
			if age < 3 || m.latestReply-m.rttAt[i] <= horizon {
				ordered[n] = m.rtts[i]
				n++
			}
		}
		slices.Sort(ordered[:n])
	}
	// Recent upper-tail RTT plus an inter-quantile jitter guard. There is no
	// short cap: a healthy slow path earns a proportionally longer patience.
	p50 := ordered[(n-1)/2]
	p90 := ordered[(9*n-1)/10]
	return max(150*time.Millisecond, p90+max(25*time.Millisecond, 4*(p90-p50))), horizon, n
}

// PathState is a local policy snapshot, not a QUIC loss declaration. A prepared
// alternate provides a second observation before the manager commits a switch.
type PathState struct {
	Generation uint64
	Proof      uint64
	Samples    int
	Demand     bool
	Current    bool
	ProbeAge   time.Duration
	Quiet      time.Duration
	Threshold  time.Duration
	Horizon    time.Duration
	Suspect    bool
	Confirmed  bool
}

func (s *Session) pathStateLocked(l *carrier.Link, now time.Duration) PathState {
	threshold, horizon, samples := s.path.tail(s.cfg.DeadAfter)
	p := PathState{Generation: s.gen, Proof: s.path.proof, Samples: samples,
		Current: s.link == l && l != nil, Quiet: now - time.Duration(s.lastRX.Load()),
		Threshold: threshold, Horizon: horizon}
	if s.path.npending > 0 {
		p.ProbeAge = now - max(s.path.pending[0], s.path.deliveredAt)
	}
	// Pending OPEN / bytes are demand even after a long idle period. Recent
	// received application records cover receive-only streams such as SSE.
	recent := now-time.Duration(s.lastApplication.Load()) < max(4*s.cfg.Heartbeat, 4*p.Threshold)
	for _, f := range s.flows {
		f.mu.Lock()
		active := f.err == nil && !(f.txEOF && f.rxEOF)
		pending := !f.opened || f.txBase < f.txEnd
		f.mu.Unlock()
		if active && (pending || recent) {
			p.Demand = true
			break
		}
	}
	p.Suspect = p.Current && p.Demand && p.Samples >= 3 && p.ProbeAge > p.Threshold
	p.Confirmed = p.Suspect && p.ProbeAge > 2*p.Threshold
	return p
}

func (s *Session) PathState(l *carrier.Link) PathState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pathStateLocked(l, time.Since(s.started))
}

func (s *Session) RecoveryEvent(event string, args ...any) {
	if !s.cfg.RecoveryTrace {
		return
	}
	values := []any{"event", event, "mono_ns", int64(time.Since(s.started)), "server", s.Server}
	s.cfg.Logger.Info("path recovery", append(values, args...)...)
}

func (s *Session) maintainPath(l *carrier.Link) {
	s.mu.Lock()
	now := time.Since(s.started)
	state := s.pathStateLocked(l, now)
	if !state.Current {
		s.mu.Unlock()
		return
	}
	deadline, interval := s.cfg.DeadAfter, s.cfg.Heartbeat
	adaptive := s.cfg.RecoveryMode == "adaptive" && !s.Server
	if adaptive && state.Samples >= 3 {
		deadline = max(deadline, 3*state.Threshold)
		if state.Demand {
			interval = min(interval, max(100*time.Millisecond, state.Threshold/2))
		}
	}
	dead := state.Quiet > deadline || (adaptive && state.Demand && state.ProbeAge > deadline)
	probe := !dead && (!adaptive || now-s.path.lastProbe >= interval) && (!s.Server || s.cfg.Adaptive || state.Quiet >= s.cfg.DeadAfter/2)
	if probe {
		s.path.sent(now)
	}
	s.mu.Unlock()
	if dead {
		s.RecoveryEvent("dead_timeout", "carrier", l.Kind, "generation", state.Generation, "quiet_ns", int64(state.Quiet), "probe_age_ns", int64(state.ProbeAge), "deadline_ns", int64(deadline))
		s.Drop(l)
	} else if probe {
		s.RecoveryEvent("probe_sent", "carrier", l.Kind, "generation", state.Generation, "probe_ns", uint64(now))
		if !l.QueueControl(wire.Frame{Kind: wire.Ping, Offset: uint64(now)}) {
			s.Drop(l)
		}
	}
}
