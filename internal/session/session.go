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

type Config struct {
	Window    int
	MaxFlows  int
	Rate      float64 // shared bytes/s, including record headers and an overhead estimate
	Priority  bool
	Adaptive  bool
	Heartbeat time.Duration
	DeadAfter time.Duration
	ResumeTTL time.Duration
	Dial      func(context.Context, string) (net.Conn, error)
	Logger    *slog.Logger
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
	if c.Window < 4096 || c.Window > 1<<20 || c.MaxFlows < 1 || c.MaxFlows > 64 || c.Rate < 0 || c.Heartbeat < 100*time.Millisecond || c.DeadAfter < c.Heartbeat*2 || c.ResumeTTL < c.DeadAfter {
		return errors.New("invalid session limits")
	}
	return nil
}

type Session struct {
	ID             string
	Server         bool
	cfg            Config
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	link           *carrier.Link
	gen            uint64
	flows          map[uint64]*Flow
	tombs          map[uint64]tombstone
	maxID          uint64
	nextID         uint64
	detached       time.Time
	changed        chan struct{}
	budget         *scheduler.Budget
	lastRX         atomic.Int64
	started        time.Time
	Reattachments  atomic.Uint64
	RecordSent     atomic.Uint64
	RecordReceived atomic.Uint64
	DuplicateBytes atomic.Uint64
	RTTNanos       atomic.Int64
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
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return ErrSessionLost
	}
	old := s.link
	s.link = l
	s.gen++
	gen := s.gen
	s.detached = time.Time{}
	s.lastRX.Store(int64(time.Since(s.started)))
	s.notifyLocked()
	flows := s.flowListLocked()
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	s.budget.ResetRTT()
	s.Reattachments.Add(1)
	l.Start()
	for _, f := range flows {
		f.signal()
	}
	go s.receive(l)
	s.cfg.Logger.Info("carrier attached", "carrier", l.Kind, "generation", gen, "resumed_flows", len(flows))
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
	s.RecordSent.Add(l.Sent.Load())
	s.RecordReceived.Add(l.Received.Load())
	s.notifyLocked()
	fs := s.flowListLocked()
	s.mu.Unlock()
	_ = l.Close()
	for _, f := range fs {
		f.signal()
	}
	s.cfg.Logger.Info("carrier detached", "carrier", l.Kind)
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

func (s *Session) receive(l *carrier.Link) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-l.Done():
			s.Drop(l)
			return
		case p := <-l.Frames():
			current, _, _ := s.Current()
			if current != l {
				return
			}
			s.lastRX.Store(int64(time.Since(s.started)))
			if p.ID == 0 {
				switch p.Kind {
				case wire.Ping:
					if !l.QueueControl(wire.Frame{Kind: wire.Pong, Offset: p.Offset}) {
						s.Drop(l)
						return
					}
				case wire.Pong:
					elapsed := time.Since(s.started)
					if p.Offset > uint64(elapsed) {
						s.Drop(l)
						return
					}
					rtt := elapsed - time.Duration(p.Offset)
					s.RTTNanos.Store(int64(rtt))
					s.budget.ObserveRTT(rtt)
				default:
					s.Drop(l)
					return
				}
				continue
			}
			if p.ID%2 != 1 {
				s.Drop(l)
				return
			}
			s.mu.Lock()
			f := s.flows[p.ID]
			tomb, closed := s.tombs[p.ID]
			stale := s.maxID > 8192 && p.ID < s.maxID-8192
			if f == nil && p.Kind == wire.Open && s.Server && !closed && !stale && len(s.flows) < s.cfg.MaxFlows {
				target := string(p.Payload)
				if len(target) == 0 || len(target) > 1024 {
					s.mu.Unlock()
					s.Drop(l)
					return
				}
				f = newFlow(s, p.ID, target)
				s.flows[p.ID] = f
				if p.ID > s.maxID {
					s.maxID = p.ID
				}
				go f.sendLoop()
				go s.connectTarget(f)
			}
			s.mu.Unlock()
			if f == nil {
				if p.Kind == wire.Reset || p.Kind == wire.Ack {
					continue
				}
				// A completed flow's compact tombstone preserves graceful FIN
				// semantics if its last ACK was lost with the previous carrier.
				if closed && !tomb.reset {
					kind := uint8(wire.Ack)
					if p.Kind == wire.Open {
						kind = wire.Opened
					}
					if !l.QueueControl(wire.Frame{Kind: kind, Flags: wire.FlagFIN, ID: p.ID, Offset: tomb.received, Limit: tomb.received + uint64(s.cfg.Window)}) {
						s.Drop(l)
						return
					}
					if p.Kind == wire.Open {
						if !l.QueueControl(wire.Frame{Kind: wire.Fin, ID: p.ID, Offset: tomb.sent}) {
							s.Drop(l)
							return
						}
					}
				} else {
					if !l.QueueControl(wire.Frame{Kind: wire.Reset, ID: p.ID, Payload: []byte("flow unavailable")}) {
						s.Drop(l)
						return
					}
				}
				continue
			}
			if err := f.receive(p); err != nil {
				f.fail(err, true)
			}
		}
	}
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
	t := time.NewTicker(s.cfg.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-t.C:
			l, _, _ := s.Current()
			if l != nil {
				quiet := time.Since(s.started) - time.Duration(s.lastRX.Load())
				if quiet > s.cfg.DeadAfter {
					s.Drop(l)
				} else if !s.Server || s.cfg.Adaptive || quiet >= s.cfg.DeadAfter/2 {
					// Client probes and server replies keep both directions live.
					// The adaptive sender needs its own RTT samples. Otherwise a
					// server probes only after prolonged silence, also allowing a
					// peer whose configured heartbeat is slower than our timeout.
					if !l.QueueControl(wire.Frame{Kind: wire.Ping, Offset: uint64(time.Since(s.started))}) {
						s.Drop(l)
					}
				}
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
	lastLimit    uint64
	resetPending bool
	resetSent    bool
	credit       float64
	creditAt     time.Time
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
			f.ackPending = true
			f.signal()
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
			f.ackPending = true
			f.signal()
			return nil
		}
		if end <= f.rxNext {
			f.s.DuplicateBytes.Add(uint64(len(p.Payload)))
			f.ackPending = true
			f.signal()
			return nil
		}
		skip := f.rxNext - p.Offset
		if end > f.rxConsumed+uint64(f.s.cfg.Window) {
			return ErrProtocol
		}
		f.s.DuplicateBytes.Add(skip)
		f.rxBuf = append(f.rxBuf, p.Payload[skip:]...)
		f.rxNext = end
		f.ackPending = true
		f.cond.Broadcast()
		f.signal()
	case wire.Fin:
		if !f.opened || p.Offset != f.rxNext {
			return ErrProtocol
		}
		f.rxEOF = true
		f.ackPending = true
		f.cond.Broadcast()
		f.signal()
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
			f.rxFinAckSent = false
			if f.s.Server && f.opened {
				f.openReply = true
			}
		}
		var p wire.Frame
		high := true
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
		case f.opened && f.ackPending && (!lastAck || f.txSent == f.txEnd || f.txSent >= f.remoteLimit):
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
		case f.opened && f.ackPending:
			p = f.ackFrameLocked()
			lastAck = true
		}
		f.inFlight = p.Kind != 0
		f.mu.Unlock()
		if p.Kind == 0 {
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
		if err := f.s.budget.Acquire(f.s.ctx, l.RecordCost(p)+64, high); err != nil {
			return
		}
		current, nowGen, _ := f.s.Current()
		if current != l || nowGen != generation {
			f.mu.Lock()
			f.inFlight = false
			f.mu.Unlock()
			continue
		}
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
	f.lastLimit = p.Limit
	return p
}

func (s *Session) String() string {
	return fmt.Sprintf("session(server=%v, flows=%d)", s.Server, s.FlowCount())
}
