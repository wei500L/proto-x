package session

import (
	"time"

	"proto-x/internal/wire"
)

// deliveryProof correlates cumulative ACKs with fresh sends. Arrival of DATA
// or an old ACK cannot prove that the uplink worked after an unanswered probe.
// Protected by Flow.mu. All times are monotonic offsets from Session.started.
type deliveryProof struct {
	generation          uint64
	highest, floor      uint64 // highest attempted DATA end; replay exclusion boundary
	markers             [8]deliveryMarker
	n, next             int
	openSeen, freshOpen bool
	openAt              time.Duration
}

type deliveryMarker struct {
	end uint64
	at  time.Duration
}

// sent runs after pacing and the generation check, immediately before Send.
// The timestamp is a lower bound on actual transmission, including blocked or
// failed attempts. An ACK may therefore understate freshness, never overstate it.
func (d *deliveryProof) sent(gen uint64, p wire.Frame, at time.Duration) {
	if d.generation != gen {
		d.generation, d.floor = gen, d.highest
		d.n, d.next, d.freshOpen, d.openAt = 0, 0, false, 0
	}
	switch p.Kind {
	case wire.Open:
		if !d.openSeen {
			d.freshOpen, d.openAt = true, at
		}
		d.openSeen = true
	case wire.Data:
		end := p.Offset + uint64(len(p.Payload))
		if end <= d.highest { // retransmission is not fresh evidence
			return
		}
		d.highest = end
		d.markers[d.next] = deliveryMarker{end: end, at: at}
		d.next = (d.next + 1) % len(d.markers)
		d.n = min(d.n+1, len(d.markers))
	}
}

// acknowledged is called only after full frame validation, on this generation.
// A cumulative ACK proves receipt of the newest covered fresh marker. A replay
// ACK, duplicate ACK or repeated OPENED does not manufacture a new timestamp.
func (d *deliveryProof) acknowledged(gen uint64, p wire.Frame, oldBase uint64, wasOpened bool) time.Duration {
	if d.generation != gen || (p.Kind != wire.Ack && p.Kind != wire.Opened) {
		return 0
	}
	var at time.Duration
	if p.Kind == wire.Opened && !wasOpened && d.freshOpen {
		at = d.openAt
		d.freshOpen = false
	}
	if p.Offset > oldBase {
		for _, m := range d.markers[:d.n] {
			if m.end > oldBase && m.end > d.floor && m.end <= p.Offset {
				at = max(at, m.at)
			}
		}
	}
	return at
}

func (f *Flow) receiveWithProof(p wire.Frame, gen uint64) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	base, opened := f.txBase, f.opened
	if err := f.receiveLocked(p); err != nil {
		return 0, err
	}
	if f.err != nil {
		return 0, nil
	}
	return f.delivery.acknowledged(gen, p, base, opened), nil
}
