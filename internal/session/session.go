// Package session keeps TCP sockets and byte offsets independent of carriers.
// State survives a link loss only while this process and Session remain alive.
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"proto-x/internal/carrier"
	"proto-x/internal/scheduler"
	"proto-x/internal/wire"
)

var ErrSessionLost = errors.New("session state unavailable; existing sockets cannot resume")
var ErrFlowLimit = errors.New("concurrent flow limit reached")
var ErrProtocol = errors.New("invalid flow state")
var ErrStaleAttempt = errors.New("stale carrier attempt")

type Config struct {
	Window               int
	MaxFlows             int
	Rate                 float64 // shared bytes/s, including record headers and an overhead estimate
	Priority             bool
	Adaptive             bool
	Heartbeat            time.Duration
	DeadAfter            time.Duration
	ResumeTTL            time.Duration
	RecoveryMode         string // legacy or adaptive; adaptive hedging is driven by the client manager
	RecoveryTrace        bool
	RecoveryCountHistory bool // retain last 32 RTTs; false enables experimental age filtering
	RecoveryProbeOnly    bool // ablation: ignore causally matched application progress
	ACKCoalesce          bool // coalesce cumulative ACKs while preserving credit and FIN progress
	Dial                 func(context.Context, string) (net.Conn, error)
	Logger               *slog.Logger
}

func (c *Config) defaults() {
	if c.Window == 0 {
		c.Window = 64 << 10
	}
	if c.MaxFlows == 0 {
		c.MaxFlows = 32
	}
	if c.Heartbeat == 0 {
		c.Heartbeat = 500 * time.Millisecond
	}
	if c.DeadAfter == 0 {
		c.DeadAfter = 2 * time.Second
	}
	if c.ResumeTTL == 0 {
		c.ResumeTTL = 90 * time.Second
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}
func (c Config) Validate() error {
	c.defaults()
	if c.Window < 4096 || c.Window > 1<<20 || c.MaxFlows < 1 || c.MaxFlows > 64 || c.Rate < 0 || c.Heartbeat < 100*time.Millisecond || c.DeadAfter < c.Heartbeat*2 || c.ResumeTTL < c.DeadAfter || (c.RecoveryMode != "" && c.RecoveryMode != "legacy" && c.RecoveryMode != "adaptive") {
		return errors.New("invalid session limits")
	}
	return nil
}

type Session struct {
	ID              string
	Server          bool
	cfg             Config
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	link            *carrier.Link
	gen             uint64
	flows           map[uint64]*Flow
	tombs           map[uint64]tombstone
	maxID           uint64
	nextID          uint64
	detached        time.Time
	changed         chan struct{}
	budget          *scheduler.Budget
	lastRX          atomic.Int64
	started         time.Time
	path            pathMonitor // protected by mu, including samples and queued probes
	lastApplication atomic.Int64
	progressGen     uint64
	nextAttempt     uint64 // client HELLO sequence, independent of attached generations
	attachedAttempt uint64 // server's committed sequence; zero denotes legacy mode
	Reattachments   atomic.Uint64
	RecordSent      atomic.Uint64
	RecordReceived  atomic.Uint64
	DuplicateBytes  atomic.Uint64
	RTTNanos        atomic.Int64
}

type tombstone struct {
	reset          bool
	received, sent uint64
}

func New(id string, server bool, cfg Config) *Session {
	cfg.defaults()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{ID: id, Server: server, cfg: cfg, ctx: ctx, cancel: cancel, flows: make(map[uint64]*Flow), tombs: make(map[uint64]tombstone), nextID: 1, detached: time.Now(), started: time.Now(), changed: make(chan struct{})}
	s.budget = scheduler.New(ctx, cfg.Rate, cfg.Priority, cfg.Adaptive)
	go s.maintenance()
	return s
}
func (s *Session) Done() <-chan struct{} { return s.ctx.Done() }
func (s *Session) notifyLocked()         { close(s.changed); s.changed = make(chan struct{}) }
func (s *Session) Current() (*carrier.Link, uint64, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.link, s.gen, s.changed
}
func (s *Session) Attach(l *carrier.Link) error {
	return s.AttachAttempt(l, 0)
}

// NextAttempt consumes a sequence number for every activation, including failed
// attempts. TLS-only preparation does not change it. Never wrap the sequence.
func (s *Session) NextAttempt() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil || s.nextAttempt == ^uint64(0) {
		return 0, ErrSessionLost
	}
	s.nextAttempt++
	return s.nextAttempt, nil
}

// AttachAttempt fences delayed authenticated activations. The check and path
// publication are atomic. Once fenced, legacy Attach cannot replace this session.
// WELCOME delivery is not an atomic distributed commit: its loss can still
// leave the client uncertain, but a newer retry cannot be rolled back by it.
func (s *Session) AttachAttempt(l *carrier.Link, attempt uint64) error {
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return ErrSessionLost
	}
	if (attempt == 0 && s.attachedAttempt != 0) || (attempt != 0 && attempt <= s.attachedAttempt) {
		s.mu.Unlock()
		return ErrStaleAttempt
	}
	select {
	case <-l.Done():
		s.mu.Unlock()
		return io.ErrClosedPipe
	default:
	}
	old := s.link
	s.attachedAttempt = attempt
	s.link = l
	s.gen++
	gen := s.gen
	s.path = pathMonitor{countHistory: s.cfg.RecoveryCountHistory}
	s.progressGen = 0
	s.detached = time.Time{}
	s.lastRX.Store(int64(time.Since(s.started)))
	s.notifyLocked()
	flows := s.flowListLocked()
	s.mu.Unlock()
	if old != nil {
		s.retireLink(old)
	}
	s.budget.ResetRTT()
	s.Reattachments.Add(1)
	l.Start()
	for _, f := range flows {
		f.signal()
	}
	go s.receive(l)
	s.cfg.Logger.Info("carrier attached", "carrier", l.Kind, "generation", gen, "resumed_flows", len(flows))
	s.RecoveryEvent("attached", "carrier", l.Kind, "generation", gen, "attempt", attempt, "resumed_flows", len(flows))
	return nil
}
func (s *Session) Drop(l *carrier.Link) {
	s.mu.Lock()
	if s.link != l {
		s.mu.Unlock()
		return
	}
	s.link = nil
	s.detached = time.Now()
	s.notifyLocked()
	fs := s.flowListLocked()
	s.mu.Unlock()
	s.retireLink(l)
	for _, f := range fs {
		f.signal()
	}
	s.cfg.Logger.Info("carrier detached", "carrier", l.Kind)
	s.RecoveryEvent("detached", "carrier", l.Kind)
}

// Diagnostic snapshots of retired application records, not wire-byte meters.
// Include direct replacement as well as detached paths. Outer ACKs, probes,
// padding, handshake traffic and in-flight completion require link capture.
func (s *Session) retireLink(l *carrier.Link) {
	_ = l.Close()
	s.RecordSent.Add(l.Sent.Load())
	s.RecordReceived.Add(l.Received.Load())
}
func (s *Session) Close(err error) {
	s.cancel()
	s.mu.Lock()
	l := s.link
	s.link = nil
	fs := s.flowListLocked()
	s.notifyLocked()
	s.mu.Unlock()
	if l != nil {
		_ = l.Close()
	}
	for _, f := range fs {
		f.fail(err, false)
	}
}
func (s *Session) flowListLocked() []*Flow {
	fs := make([]*Flow, 0, len(s.flows))
	for _, f := range s.flows {
		fs = append(fs, f)
	}
	return fs
}
func (s *Session) FlowCount() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.flows) }
func (s *Session) Rate() float64  { return s.budget.Rate() }

func (s *Session) Open(ctx context.Context, target string) (*Flow, error) {
	if s.Server {
		return nil, errors.New("server cannot initiate proxy flows")
	}
	if len(target) > 1024 {
		return nil, errors.New("target too long")
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, ErrSessionLost
	}
	if len(s.flows) >= s.cfg.MaxFlows {
		s.mu.Unlock()
		return nil, ErrFlowLimit
	}
	id := s.nextID
	s.nextID += 2
	s.maxID = id
	f := newFlow(s, id, target)
	s.flows[id] = f
	s.lastApplication.Store(int64(time.Since(s.started)))
	s.mu.Unlock()
	go f.sendLoop()
	f.signal()
	select {
	case <-f.openDone:
		f.mu.Lock()
		err := f.err
		f.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return f, nil
	case <-ctx.Done():
		f.fail(ctx.Err(), true)
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, ErrSessionLost
	}
}

// receiveFrame holds the generation lock through state mutation. A frame
// already dequeued from an old carrier cannot reset or half-close a resumed
// flow after Attach publishes a new generation.
var errStaleCarrier = errors.New("stale carrier generation")

func (s *Session) receive(l *carrier.Link) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-l.Done():
			s.Drop(l)
			return
		case p := <-l.Frames():
			if err := s.receiveFrame(l, p); err != nil {
				if !errors.Is(err, errStaleCarrier) {
					s.Drop(l)
				}
				return
			}
		}
	}
}

func (s *Session) receiveFrame(l *carrier.Link, p wire.Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.link != l {
		return errStaleCarrier
	}
	now := time.Since(s.started)
	s.lastRX.Store(int64(now))
	if p.ID == 0 {
		switch p.Kind {
		case wire.Ping:
			if !l.QueueControl(wire.Frame{Kind: wire.Pong, Offset: p.Offset}) {
				return ErrProtocol
			}
		case wire.Pong:
			if p.Offset > uint64(now) {
				return ErrProtocol
			}
			rtt, matched := s.path.replied(time.Duration(p.Offset), now)
			if !matched && s.cfg.RecoveryMode != "adaptive" {
				rtt = now - time.Duration(p.Offset)
			}
			if matched || s.cfg.RecoveryMode != "adaptive" {
				s.RTTNanos.Store(int64(rtt))
				s.budget.ObserveRTT(rtt)
				s.RecoveryEvent("probe_reply", "generation", s.gen, "carrier", l.Kind, "probe_ns", p.Offset, "rtt_ns", int64(rtt))
			}
		default:
			return ErrProtocol
		}
		return nil
	}
	if p.ID%2 != 1 {
		return ErrProtocol
	}
	f := s.flows[p.ID]
	tomb, closed := s.tombs[p.ID]
	stale := s.maxID > 8192 && p.ID < s.maxID-8192
	if f == nil && p.Kind == wire.Open && s.Server && !closed && !stale && len(s.flows) < s.cfg.MaxFlows {
		target := string(p.Payload)
		if len(target) == 0 || len(target) > 1024 {
			return ErrProtocol
		}
		f = newFlow(s, p.ID, target)
		s.flows[p.ID] = f
		if p.ID > s.maxID {
			s.maxID = p.ID
		}
		go f.sendLoop()
		go s.connectTarget(f)
	}
	if f == nil {
		if p.Kind == wire.Reset || p.Kind == wire.Ack {
			return nil
		}
		if closed && !tomb.reset {
			kind := uint8(wire.Ack)
			if p.Kind == wire.Open {
				kind = wire.Opened
			}
			if !l.QueueControl(wire.Frame{Kind: kind, Flags: wire.FlagFIN, ID: p.ID, Offset: tomb.received, Limit: tomb.received + uint64(s.cfg.Window)}) {
				return ErrProtocol
			}
			if p.Kind == wire.Open && !l.QueueControl(wire.Frame{Kind: wire.Fin, ID: p.ID, Offset: tomb.sent}) {
				return ErrProtocol
			}
		} else if !l.QueueControl(wire.Frame{Kind: wire.Reset, ID: p.ID, Payload: []byte("flow unavailable")}) {
			return ErrProtocol
		}
		return nil
	}
	proofAt, err := f.receiveWithProof(p, s.gen)
	if err != nil {
		f.fail(err, true)
		return nil
	}
	if proofAt > 0 && s.cfg.RecoveryMode == "adaptive" && !s.Server && !s.cfg.RecoveryProbeOnly && s.path.delivered(proofAt, now, s.path.threshold(s.cfg.DeadAfter)) {
		s.RecoveryEvent("delivery_proof", "generation", s.gen, "carrier", l.Kind, "kind", p.Kind, "sent_ns", int64(proofAt), "age_ns", int64(now-proofAt))
	}
	if p.Kind == wire.Data || p.Kind == wire.Open || p.Kind == wire.Opened {
		s.lastApplication.Store(int64(now))
		if s.progressGen != s.gen {
			s.progressGen = s.gen
			s.RecoveryEvent("first_progress", "generation", s.gen, "carrier", l.Kind, "kind", p.Kind)
		}
	}
	return nil
}

func (s *Session) connectTarget(f *Flow) {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	if s.cfg.Dial == nil {
		f.fail(errors.New("no target dialer"), true)
		return
	}
	c, err := s.cfg.Dial(ctx, f.target)
	if err != nil {
		f.fail(errors.New("target connection failed"), true)
		return
	}
	f.mu.Lock()
	if f.err != nil {
		f.mu.Unlock()
		_ = c.Close()
		return
	}
	f.socket = c
	f.opened = true
	f.openReply = true
	f.openOnce.Do(func() { close(f.openDone) })
	f.mu.Unlock()
	f.signal()
	go Bridge(c, f)
}

// Bridge preserves TCP half-close. An interrupted carrier is not exposed as EOF;
// only flow EOF, explicit reset, expiry or application closure finishes it.
func Bridge(c net.Conn, f *Flow) {
	defer c.Close()
	defer f.Close()
	done := make(chan struct{})
	go func() {
		_, err := io.Copy(f, c)
		if err != nil {
			f.fail(err, true)
		} else {
			_ = f.CloseWrite()
		}
		close(done)
	}()
	_, err := io.Copy(c, f)
	if err != nil {
		f.fail(err, true)
		_ = c.Close()
	} else if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = c.Close()
	}
	<-done
}

func (s *Session) maintenance() {
	interval := s.cfg.Heartbeat
	if s.cfg.RecoveryMode == "adaptive" && !s.Server {
		interval = min(interval, 25*time.Millisecond)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-t.C:
			l, _, _ := s.Current()
			if l != nil {
				s.maintainPath(l)
			}
			s.mu.Lock()
			expired := s.link == nil && !s.detached.IsZero() && now.Sub(s.detached) > s.cfg.ResumeTTL
			var removed []*Flow
			for id, f := range s.flows {
				f.mu.Lock()
				done := !f.inFlight && (f.resetSent || (f.txFinAck && f.rxReadEOF && f.rxFinAckSent && !f.ackPending))
				if done {
					f.retireOnce.Do(func() { close(f.done) })
					delete(s.flows, id)
					s.tombs[id] = tombstone{reset: f.resetSent, received: f.rxNext, sent: f.txEnd}
					removed = append(removed, f)
				}
				f.mu.Unlock()
			}
			if s.maxID > 8192 {
				for id := range s.tombs {
					if id < s.maxID-8192 {
						delete(s.tombs, id)
					}
				}
			}
			s.mu.Unlock()
			for _, f := range removed {
				if l != nil {
					l.Forget(f.id)
				}
			}
			if expired {
				s.Close(ErrSessionLost)
				return
			}
		}
	}
}

type Flow struct {
	s            *Session
	id           uint64
	target       string
	mu           sync.Mutex
	cond         *sync.Cond
	kick         chan struct{}
	done         chan struct{}
	retireOnce   sync.Once
	openDone     chan struct{}
	openOnce     sync.Once
	opened       bool
	openReply    bool
	err          error
	socket       net.Conn
	txBuf        []byte
	txBase       uint64
	txEnd        uint64
	txSent       uint64
	remoteLimit  uint64
	txEOF        bool
	txFinAck     bool
	rxBuf        []byte
	rxNext       uint64
	rxConsumed   uint64
	rxEOF        bool
	rxReadEOF    bool
	rxFinAckSent bool
	inFlight     bool
	ackPending   bool
	ackDue       time.Time
	lastAcked    uint64
	lastLimit    uint64
	resetPending bool
	resetSent    bool
	credit       float64
	creditAt     time.Time
	delivery     deliveryProof
}

func newFlow(s *Session, id uint64, target string) *Flow {
	f := &Flow{s: s, id: id, target: target, kick: make(chan struct{}, 1), done: make(chan struct{}), openDone: make(chan struct{}), remoteLimit: uint64(s.cfg.Window), credit: 8192, creditAt: time.Now()}
	f.cond = sync.NewCond(&f.mu)
	return f
}
func (f *Flow) signal() {
	select {
	case f.kick <- struct{}{}:
	default:
	}
}
func (f *Flow) fail(err error, reset bool) {
	if err == nil {
		err = io.ErrClosedPipe
	}
	f.mu.Lock()
	if f.err == nil {
		f.err = err
		f.resetPending = reset
		f.openOnce.Do(func() { close(f.openDone) })
	}
	c := f.socket
	f.cond.Broadcast()
	f.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
	f.signal()
}

func (f *Flow) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for len(f.rxBuf) == 0 && !f.rxEOF && f.err == nil {
		f.cond.Wait()
	}
	if len(f.rxBuf) > 0 {
		n := copy(b, f.rxBuf)
		f.rxBuf = f.rxBuf[n:]
		f.rxConsumed += uint64(n)
		if f.rxConsumed+uint64(f.s.cfg.Window)-f.lastLimit >= uint64(f.s.cfg.Window/4) {
			f.queueAckLocked(false)
		}
		return n, nil
	}
	if f.err != nil {
		return 0, f.err
	}
	f.rxReadEOF = true
	return 0, io.EOF
}
func (f *Flow) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	written := 0
	for len(b) > 0 {
		for len(f.txBuf) >= f.s.cfg.Window && f.err == nil && !f.txEOF {
			f.cond.Wait()
		}
		if f.err != nil {
			return written, f.err
		}
		if f.txEOF {
			return written, io.ErrClosedPipe
		}
		n := min(len(b), f.s.cfg.Window-len(f.txBuf))
		f.txBuf = append(f.txBuf, b[:n]...)
		f.txEnd += uint64(n)
		f.s.lastApplication.Store(int64(time.Since(f.s.started)))
		written += n
		b = b[n:]
		f.signal()
	}
	return written, nil
}
func (f *Flow) CloseWrite() error {
	f.mu.Lock()
	f.txEOF = true
	f.cond.Broadcast()
	f.mu.Unlock()
	f.signal()
	return nil
}
func (f *Flow) Close() error {
	f.mu.Lock()
	clean := f.txEOF && f.rxEOF && len(f.rxBuf) == 0
	f.mu.Unlock()
	if !clean {
		f.fail(io.ErrClosedPipe, true)
	}
	return nil
}

func (f *Flow) receive(p wire.Frame) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.receiveLocked(p)
}

func (f *Flow) receiveLocked(p wire.Frame) error {
	if f.err != nil {
		if p.Kind != wire.Reset {
			f.resetPending = true
			f.signal()
		}
		return nil
	}
	switch p.Kind {
	case wire.Open:
		if !f.s.Server || string(p.Payload) != f.target {
			return ErrProtocol
		}
		if f.opened {
			f.openReply = true
			f.signal()
		}
	case wire.Opened:
		if f.s.Server || len(p.Payload) != 0 {
			return ErrProtocol
		}
		f.opened = true
		f.openOnce.Do(func() { close(f.openDone) })
		fallthrough
	case wire.Ack:
		if p.Offset < f.txBase {
			return nil
		}
		if p.Offset > f.txEnd || p.Limit < p.Offset || p.Limit-p.Offset > uint64(f.s.cfg.Window) {
			return ErrProtocol
		}
		d := p.Offset - f.txBase
		f.txBuf = f.txBuf[d:]
		f.txBase = p.Offset
		if f.txSent < f.txBase {
			f.txSent = f.txBase
		}
		if p.Limit > f.remoteLimit {
			f.remoteLimit = p.Limit
		}
		if p.Flags&wire.FlagFIN != 0 {
			if !f.txEOF || p.Offset != f.txEnd {
				return ErrProtocol
			}
			f.txFinAck = true
		}
		f.cond.Broadcast()
		f.signal()
	case wire.Data:
		if !f.opened || len(p.Payload) == 0 || p.Offset > ^uint64(0)-uint64(len(p.Payload)) {
			return ErrProtocol
		}
		end := p.Offset + uint64(len(p.Payload))
		if f.rxEOF && end > f.rxNext {
			return ErrProtocol
		}
		if p.Offset > f.rxNext {
			f.queueAckLocked(false)
			return nil
		}
		if end <= f.rxNext {
			f.s.DuplicateBytes.Add(uint64(len(p.Payload)))
			f.queueAckLocked(false)
			return nil
		}
		skip := f.rxNext - p.Offset
		if end > f.rxConsumed+uint64(f.s.cfg.Window) {
			return ErrProtocol
		}
		f.s.DuplicateBytes.Add(skip)
		f.rxBuf = append(f.rxBuf, p.Payload[skip:]...)
		f.rxNext = end
		f.queueAckLocked(true)
		f.cond.Broadcast()
	case wire.Fin:
		if !f.opened || p.Offset != f.rxNext {
			return ErrProtocol
		}
		f.rxEOF = true
		f.queueAckLocked(false)
		f.cond.Broadcast()
	case wire.Reset:
		f.err = errors.New("peer reset flow")
		f.resetSent = true
		f.openOnce.Do(func() { close(f.openDone) })
		f.cond.Broadcast()
		if f.socket != nil {
			_ = f.socket.Close()
		}
		f.signal()
	default:
		return ErrProtocol
	}
	return nil
}

func (f *Flow) sendLoop() {
	var generation uint64
	var openSent, finSent bool
	lastAck := false
	for {
		select {
		case <-f.done:
			return
		default:
		}
		l, gen, changed := f.s.Current()
		if l == nil {
			select {
			case <-f.s.Done():
				return
			case <-f.done:
				return
			case <-changed:
				continue
			case <-f.kick:
				continue
			}
		}
		f.mu.Lock()
		if gen != generation {
			generation = gen
			openSent = false
			finSent = false
			f.txSent = f.txBase
			f.ackPending = true
			f.ackDue = time.Time{} // state reconciliation cannot wait for coalescing
			f.rxFinAckSent = false
			if f.s.Server && f.opened {
				f.openReply = true
			}
		}
		var p wire.Frame
		high := true
		ackReady := f.ackPending && (f.ackDue.IsZero() || !time.Now().Before(f.ackDue))
		switch {
		case f.resetPending:
			p = wire.Frame{Kind: wire.Reset, ID: f.id, Payload: []byte("flow closed")}
		case f.err != nil:
			f.mu.Unlock()
			return
		case !f.s.Server && !openSent:
			p = wire.Frame{Kind: wire.Open, ID: f.id, Payload: []byte(f.target)}
			openSent = true
		case f.s.Server && f.openReply:
			p = wire.Frame{Kind: wire.Opened, ID: f.id, Offset: f.rxNext, Limit: f.rxConsumed + uint64(f.s.cfg.Window)}
			f.openReply = false
			f.lastLimit = p.Limit
			f.lastAcked = p.Offset
		case f.opened && ackReady && (!lastAck || f.txSent == f.txEnd || f.txSent >= f.remoteLimit):
			p = f.ackFrameLocked()
			lastAck = true
		case f.opened && f.txSent < f.txEnd && f.txSent < f.remoteLimit:
			n := min(uint64(wire.DataPayload), f.txEnd-f.txSent, f.remoteLimit-f.txSent)
			p = wire.Frame{Kind: wire.Data, ID: f.id, Offset: f.txSent, Payload: append([]byte(nil), f.txBuf[f.txSent-f.txBase:f.txSent-f.txBase+n]...)}
			f.txSent += n
			lastAck = false
			now := time.Now()
			f.credit = min(8192, f.credit+now.Sub(f.creditAt).Seconds()*4096)
			f.creditAt = now
			high = f.credit >= float64(n)
			if high {
				f.credit -= float64(n)
			}
		case f.opened && f.txEOF && f.txSent == f.txEnd && !finSent:
			p = wire.Frame{Kind: wire.Fin, ID: f.id, Offset: f.txEnd}
			finSent = true
		case f.opened && ackReady:
			p = f.ackFrameLocked()
			lastAck = true
		}
		f.inFlight = p.Kind != 0
		var ackWait time.Duration
		if p.Kind == 0 && f.opened && f.ackPending && !f.ackDue.IsZero() {
			ackWait = max(time.Nanosecond, time.Until(f.ackDue))
		}
		f.mu.Unlock()
		if p.Kind == 0 {
			var timer *time.Timer
			var tick <-chan time.Time
			if ackWait > 0 {
				timer = time.NewTimer(ackWait)
				tick = timer.C
			}
			select {
			case <-f.s.Done():
			case <-f.done:
			case <-changed:
			case <-f.kick:
			case <-tick:
			}
			if timer != nil {
				timer.Stop()
			}
			if f.s.ctx.Err() != nil {
				return
			}
			continue
		}
		if err := f.s.budget.Acquire(f.s.ctx, l.RecordCost(p)+64, high); err != nil {
			return
		}
		f.s.mu.Lock()
		if f.s.link != l || f.s.gen != generation {
			f.s.mu.Unlock()
			f.mu.Lock()
			f.inFlight = false
			f.mu.Unlock()
			continue
		}
		if f.s.cfg.RecoveryMode == "adaptive" && !f.s.Server && !f.s.cfg.RecoveryProbeOnly {
			f.mu.Lock()
			f.delivery.sent(generation, p, time.Since(f.s.started))
			f.mu.Unlock()
		}
		f.s.mu.Unlock()
		err := l.Send(p)
		f.mu.Lock()
		f.inFlight = false
		if err == nil {
			if p.Kind == wire.Reset {
				f.resetSent = true
				f.resetPending = false
			}
			if p.Kind == wire.Ack && p.Flags&wire.FlagFIN != 0 {
				f.rxFinAckSent = true
			}
		}
		f.mu.Unlock()
		if err != nil {
			f.s.Drop(l)
		}
		if p.Kind == wire.Reset && err == nil {
			return
		}
	}
}
func (f *Flow) ackFrameLocked() wire.Frame {
	p := wire.Frame{Kind: wire.Ack, ID: f.id, Offset: f.rxNext, Limit: f.rxConsumed + uint64(f.s.cfg.Window)}
	if f.rxEOF {
		p.Flags = wire.FlagFIN
	}
	f.ackPending = false
	f.ackDue = time.Time{}
	f.lastAcked = f.rxNext
	f.lastLimit = p.Limit
	return p
}

// Only cumulative receipt acknowledgements may wait. A quarter-window of
// outstanding bytes, newly released credit, FIN and replay reconciliation are
// urgent. DATA, OPEN and application delivery never wait for this timer.
func (f *Flow) queueAckLocked(coalesce bool) {
	if !f.s.cfg.ACKCoalesce || !coalesce || f.rxNext-f.lastAcked >= uint64(f.s.cfg.Window/4) {
		f.ackDue = time.Time{}
	} else if !f.ackPending {
		delay := 5 * time.Millisecond
		if rtt := time.Duration(f.s.RTTNanos.Load()); rtt > 0 {
			delay = min(10*time.Millisecond, max(time.Millisecond, rtt/4))
		}
		f.ackDue = time.Now().Add(delay)
	}
	f.ackPending = true
	f.signal()
}

func (s *Session) String() string {
	return fmt.Sprintf("session(server=%v, flows=%d)", s.Server, s.FlowCount())
}
