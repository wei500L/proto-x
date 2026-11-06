// Package scheduler implements a shared paced budget with bounded sparse-flow
// preference. The transport's congestion controller remains authoritative.
package scheduler

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

type request struct {
	ctx   context.Context
	bytes int
	high  bool
	ready chan struct{}
}
type Budget struct {
	requests   chan request
	capRate    float64
	rate       atomic.Uint64
	priority   bool
	adaptive   bool
	mu         sync.Mutex
	minRTT     time.Duration
	lastAdjust time.Time
	lastSend   atomic.Int64
	started    time.Time
	High       atomic.Uint64
	Low        atomic.Uint64
}

// rate is bytes per second; rate<=0 disables shaping but retains arbitration.
func New(ctx context.Context, rate float64, priority, adaptive bool) *Budget {
	b := &Budget{requests: make(chan request, 128), capRate: rate, priority: priority, adaptive: adaptive, started: time.Now()}
	b.setRate(rate)
	go b.run(ctx)
	return b
}
func (b *Budget) setRate(rate float64) { b.rate.Store(math.Float64bits(rate)) }
func (b *Budget) Rate() float64        { return math.Float64frombits(b.rate.Load()) }
func (b *Budget) Acquire(ctx context.Context, n int, high bool) error {
	r := request{ctx: ctx, bytes: n, high: high && b.priority, ready: make(chan struct{})}
	select {
	case b.requests <- r:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-r.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (b *Budget) ResetRTT() {
	b.mu.Lock()
	b.minRTT = 0
	b.lastAdjust = time.Time{}
	b.mu.Unlock()
	b.setRate(b.capRate)
}
func (b *Budget) ObserveRTT(rtt time.Duration) {
	if !b.adaptive || b.capRate <= 0 || rtt <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.minRTT == 0 || rtt < b.minRTT {
		b.minRTT = rtt
	}
	now := time.Now()
	if now.Sub(b.lastAdjust) < 500*time.Millisecond || time.Since(b.started)-time.Duration(b.lastSend.Load()) > time.Second {
		return
	}
	rate := b.Rate()
	queue := rtt - b.minRTT
	if queue > 25*time.Millisecond {
		rate = math.Max(math.Min(b.capRate, math.Max(b.capRate/16, 4096)), rate*0.85)
	} else if queue < 10*time.Millisecond {
		rate = math.Min(b.capRate, rate+math.Max(b.capRate*0.02, 1024))
	}
	b.setRate(rate)
	b.lastAdjust = now
}

func (b *Budget) run(ctx context.Context) {
	var high, low []request
	var next time.Time
	streak := 0
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		// Drain waiting contenders before making a decision, so high priority is
		// evaluated at dispatch time rather than when a bulk writer arrived.
		for len(b.requests) > 0 {
			r := <-b.requests
			if r.high {
				high = append(high, r)
			} else {
				low = append(low, r)
			}
		}
		for len(high) > 0 && high[0].ctx.Err() != nil {
			high = high[1:]
		}
		for len(low) > 0 && low[0].ctx.Err() != nil {
			low = low[1:]
		}
		var tick <-chan time.Time
		if len(high)+len(low) > 0 {
			wait := time.Until(next)
			if wait <= 0 {
				var r request
				if len(high) > 0 && (streak < 3 || len(low) == 0) {
					r = high[0]
					high = high[1:]
					streak++
					b.High.Add(uint64(r.bytes))
				} else {
					r = low[0]
					low = low[1:]
					streak = 0
					b.Low.Add(uint64(r.bytes))
				}
				if r.ctx.Err() == nil {
					close(r.ready)
					now := time.Now()
					b.lastSend.Store(int64(time.Since(b.started)))
					rate := b.Rate()
					if rate > 0 {
						next = now.Add(time.Duration(float64(r.bytes) / rate * float64(time.Second)))
					} else {
						next = now
					}
				}
				continue
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(wait)
			tick = timer.C
		}
		select {
		case <-ctx.Done():
			return
		case <-tick:
		case r := <-b.requests:
			if r.high {
				high = append(high, r)
			} else {
				low = append(low, r)
			}
		}
	}
}
