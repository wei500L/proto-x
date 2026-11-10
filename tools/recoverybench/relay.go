package main

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type counters struct {
	rxPackets, rxBytes, txPackets, txBytes, drops, dropBytes, queueDrops, errors atomic.Int64
}

func (c *counters) snapshot() map[string]int64 {
	return map[string]int64{"received_packets": c.rxPackets.Load(), "received_bytes": c.rxBytes.Load(), "forwarded_packets": c.txPackets.Load(), "forwarded_bytes": c.txBytes.Load(), "dropped_packets": c.drops.Load(), "dropped_bytes": c.dropBytes.Load(), "queue_drops": c.queueDrops.Load(), "io_errors": c.errors.Load()}
}

type packet struct {
	data []byte
	due  time.Time
}
type udpRelay struct {
	ctx                        context.Context
	cancel                     context.CancelFunc
	local, remote              *net.UDPConn
	mu                         sync.Mutex
	client                     *net.UDPAddr
	delay                      time.Duration
	extraDelay                 atomic.Int64
	blackholeUp, blackholeDown atomic.Bool
	up, down                   counters
	wg                         sync.WaitGroup
	once                       sync.Once
	logs                       *eventLog
}

func newUDPRelay(parent context.Context, target string, delay time.Duration, logs *eventLog) (*udpRelay, error) {
	a, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return nil, err
	}
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	r, err := net.DialUDP("udp4", nil, a)
	if err != nil {
		l.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	u := &udpRelay{ctx: ctx, cancel: cancel, local: l, remote: r, delay: delay, logs: logs}
	for _, direction := range []string{"up", "down"} {
		u.wg.Add(1)
		go u.direction(direction)
	}
	return u, nil
}
func (u *udpRelay) address() string { return u.local.LocalAddr().String() }
func (u *udpRelay) setBlackhole(direction string, on bool) {
	if direction == "both" || direction == "up" {
		u.blackholeUp.Store(on)
	}
	if direction == "both" || direction == "down" {
		u.blackholeDown.Store(on)
	}
}
func (u *udpRelay) direction(dir string) {
	defer u.wg.Done()
	source := u.local
	c := &u.up
	blocked := &u.blackholeUp
	if dir == "down" {
		source = u.remote
		c = &u.down
		blocked = &u.blackholeDown
	}
	queue := make(chan packet, 4096)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-u.ctx.Done():
				return
			case p, ok := <-queue:
				if !ok {
					return
				}
				if !waitFor(u.ctx, time.Until(p.due)) {
					return
				}
				if blocked.Load() {
					c.drops.Add(1)
					c.dropBytes.Add(int64(len(p.data)))
					continue
				}
				var n int
				var err error
				if dir == "up" {
					n, err = u.remote.Write(p.data)
				} else {
					u.mu.Lock()
					peer := u.client
					u.mu.Unlock()
					if peer == nil {
						c.drops.Add(1)
						c.dropBytes.Add(int64(len(p.data)))
						continue
					}
					n, err = u.local.WriteToUDP(p.data, peer)
				}
				if err != nil {
					if u.ctx.Err() == nil {
						c.errors.Add(1)
					}
				} else {
					c.txPackets.Add(1)
					c.txBytes.Add(int64(n))
				}
			}
		}
	}()
	defer func() { close(queue); <-done }()
	b := make([]byte, 65535)
	for {
		n, from, err := source.ReadFromUDP(b)
		if err != nil {
			if u.ctx.Err() == nil {
				c.errors.Add(1)
			}
			return
		}
		c.rxPackets.Add(1)
		c.rxBytes.Add(int64(n))
		if dir == "up" {
			u.mu.Lock()
			u.client = from
			u.mu.Unlock()
		}
		if blocked.Load() {
			c.drops.Add(1)
			c.dropBytes.Add(int64(n))
			continue
		}
		p := packet{data: append([]byte(nil), b[:n]...), due: time.Now().Add(u.delay + time.Duration(u.extraDelay.Load()))}
		select {
		case queue <- p:
		case <-u.ctx.Done():
			return
		default:
			c.drops.Add(1)
			c.dropBytes.Add(int64(n))
			c.queueDrops.Add(1)
		}
	}
}
func (u *udpRelay) close() {
	u.once.Do(func() {
		u.cancel()
		u.local.Close()
		u.remote.Close()
		u.wg.Wait()
		u.logs.record("udp_relay_end", u.counts())
	})
}
func (u *udpRelay) counts() map[string]any {
	return map[string]any{"up": u.up.snapshot(), "down": u.down.snapshot()}
}

type tcpRelay struct {
	ctx      context.Context
	cancel   context.CancelFunc
	l        net.Listener
	target   string
	delay    time.Duration
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	once     sync.Once
	logs     *eventLog
	up, down counters
	accepted atomic.Int64
}

func newTCPRelay(parent context.Context, target string, delay time.Duration, logs *eventLog) (*tcpRelay, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	r := &tcpRelay{ctx: ctx, cancel: cancel, l: l, target: target, delay: delay, conns: make(map[net.Conn]struct{}), logs: logs}
	r.wg.Add(1)
	go r.accept()
	return r, nil
}
func (r *tcpRelay) address() string { return r.l.Addr().String() }
func (r *tcpRelay) accept() {
	defer r.wg.Done()
	for {
		c, err := r.l.Accept()
		if err != nil {
			return
		}
		id := r.accepted.Add(1)
		r.logs.record("tcp_path_connect", map[string]any{"connection": id})
		d, err := (&net.Dialer{Timeout: time.Second}).DialContext(r.ctx, "tcp4", r.target)
		if err != nil {
			c.Close()
			r.up.errors.Add(1)
			continue
		}
		r.mu.Lock()
		r.conns[c] = struct{}{}
		r.conns[d] = struct{}{}
		r.mu.Unlock()
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer c.Close()
			defer d.Close()
			defer func() { r.mu.Lock(); delete(r.conns, c); delete(r.conns, d); r.mu.Unlock() }()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); r.copy(d, c, &r.up) }()
			go func() { defer wg.Done(); r.copy(c, d, &r.down) }()
			wg.Wait()
			r.logs.record("tcp_path_close", map[string]any{"connection": id})
		}()
	}
}

// The relay delays byte chunks after reads. It neither changes TCP ACKs nor
// reproduces kernel congestion-control or packet retransmission behavior.
func (r *tcpRelay) copy(dst, src net.Conn, c *counters) {
	defer func() {
		if t, ok := dst.(*net.TCPConn); ok {
			t.CloseWrite()
		}
	}()
	b := make([]byte, 64<<10)
	for {
		n, err := src.Read(b)
		if n > 0 {
			c.rxPackets.Add(1)
			c.rxBytes.Add(int64(n))
			if !waitFor(r.ctx, r.delay) {
				return
			}
			written, e := dst.Write(b[:n])
			if e != nil {
				if r.ctx.Err() == nil {
					c.errors.Add(1)
				}
				return
			}
			c.txPackets.Add(1)
			c.txBytes.Add(int64(written))
		}
		if err != nil {
			if err != io.EOF && r.ctx.Err() == nil {
				c.errors.Add(1)
			}
			return
		}
	}
}
func (r *tcpRelay) counts() map[string]any {
	return map[string]any{"connections": r.accepted.Load(), "up": r.up.snapshot(), "down": r.down.snapshot(), "units": "TLS bytes and read/write chunks; no TCP packet or retransmission counters"}
}
func (r *tcpRelay) close() {
	r.once.Do(func() {
		r.cancel()
		r.l.Close()
		r.mu.Lock()
		for c := range r.conns {
			c.Close()
		}
		r.mu.Unlock()
		r.wg.Wait()
		r.logs.record("tcp_relay_end", r.counts())
	})
}
