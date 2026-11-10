package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"proto-x/internal/carrier"
	"proto-x/internal/session"
	"proto-x/internal/wire"
)

func (c *Client) webOptions(ep Endpoint) (carrier.WebOptions, error) {
	tc, err := c.cfg.webTLS(ep)
	return carrier.WebOptions{Network: ep.Network, Address: ep.Address, Authority: ep.ServerName,
		Path: c.cfg.WebPath, TLSConfig: tc, Gate: c.gate, Padding: c.cfg.WebPadding}, err
}

// connectCarrier includes both the transport and HELLO/WELCOME deadlines. A
// preparation can be consumed only here, after the policy has committed to it.
func (c *Client) connectCarrier(ctx context.Context, s *session.Session, ep Endpoint, resuming bool, prepared *carrier.PreparedWeb) (*carrier.Link, error) {
	dctx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.DialTimeoutMS)*time.Millisecond)
	defer cancel()
	var attempt uint64
	if c.cfg.RecoveryMode == "adaptive" {
		var err error
		attempt, err = s.NextAttempt()
		if err != nil {
			if prepared != nil {
				_ = prepared.Close()
			}
			return nil, err
		}
	}
	s.RecoveryEvent("dial_start", "carrier", ep.Network, "resuming", resuming, "prepared", prepared != nil, "attempt", attempt)
	helloBody, _ := json.Marshal(hello{Version: wire.Version, Session: s.ID, Token: c.token, Resume: resuming, Window: c.cfg.Window, Attempt: attempt})
	helloFrame := wire.Frame{Kind: wire.Hello, Payload: helloBody}
	var l *carrier.Link
	var err error
	httpCarrier := ep.Network == "h2" || ep.Network == "h3"
	if httpCarrier {
		if prepared == nil {
			var o carrier.WebOptions
			o, err = c.webOptions(ep)
			if err == nil {
				prepared, err = carrier.PrepareWeb(dctx, o)
			}
		}
		if err == nil {
			state := prepared.ConnectionState()
			s.RecoveryEvent("tls_ready", "carrier", ep.Network, "ech_required", c.cfg.ECHConfigFile != "", "ech_accepted", state.ECHAccepted, "tls_version", state.Version, "alpn", state.NegotiatedProtocol)
			l, err = prepared.Activate(dctx, &helloFrame)
		}
	} else {
		tc, e := carrier.ClientTLS(c.cfg.Pin, ep.ServerName)
		err = e
		if err == nil {
			l, err = carrier.Dial(dctx, ep.Network, ep.Address, tc)
		}
	}
	if err == nil {
		stop := context.AfterFunc(dctx, func() { _ = l.Close() })
		deadline, _ := dctx.Deadline()
		l.SetHandshakeDeadline(deadline)
		if !httpCarrier {
			err = l.HandshakeWrite(helloFrame)
		}
		if err == nil {
			var p wire.Frame
			p, err = l.HandshakeRead()
			if err == nil {
				var w welcome
				if p.Kind != wire.Welcome || json.Unmarshal(p.Payload, &w) != nil {
					err = wire.ErrFrame
				} else if !w.OK {
					if w.Error == "session_lost" {
						err = session.ErrSessionLost
					} else {
						err = fmt.Errorf("server: %s", w.Error)
					}
				} else if resuming && !w.Resumed {
					err = session.ErrSessionLost
				} else if attempt != 0 && w.Attempt != attempt {
					err = errors.New("server did not negotiate fenced recovery")
				}
			}
		}
		if !stop() && err == nil {
			err = dctx.Err()
		}
	}
	if err != nil {
		if l != nil {
			_ = l.Close()
		} else if prepared != nil {
			_ = prepared.Close()
		}
		return nil, err
	}
	l.SetHandshakeDeadline(time.Time{})
	s.RecoveryEvent("activation_ready", "carrier", ep.Network, "resuming", resuming)
	return l, nil
}

type pathPreparation struct {
	index             int
	generation, proof uint64
	cancel            context.CancelFunc
	done              chan struct{}
	prepared          *carrier.PreparedWeb // published by closing done
	err               error
	ready             bool
}

func (a *pathPreparation) close() {
	a.cancel()
	<-a.done
	if a.prepared != nil {
		_ = a.prepared.Close()
	}
}

func (c *Client) preparePath(ctx context.Context, s *session.Session, index int, state session.PathState) *pathPreparation {
	pctx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.DialTimeoutMS)*time.Millisecond)
	a := &pathPreparation{index: index, generation: state.Generation, proof: state.Proof, cancel: cancel, done: make(chan struct{})}
	ep := c.cfg.Endpoints[index]
	s.RecoveryEvent("prepare_start", "carrier", ep.Network, "generation", state.Generation, "probe_age_ns", int64(state.ProbeAge), "threshold_ns", int64(state.Threshold))
	go func() {
		defer close(a.done)
		o, err := c.webOptions(ep)
		if err == nil {
			a.prepared, err = carrier.PrepareWeb(pctx, o)
		}
		a.err = err
	}()
	return a
}

// waitCarrier never sends a speculative HELLO. A TLS/ECH-validated alternate
// is only evidence that a different path is working. We first recheck the
// generation and matched round-trip proof, then require twice the estimated tail
// RTT before resuming. A recovered original path cancels the preparation.
func (c *Client) waitCarrier(ctx context.Context, s *session.Session, l *carrier.Link, index int) (*carrier.Link, int) {
	var rotate <-chan time.Time
	if c.cfg.RotateSeconds > 0 {
		t := time.NewTimer(time.Duration(c.cfg.RotateSeconds) * time.Second)
		defer t.Stop()
		rotate = t.C
	}
	if c.cfg.RecoveryMode != "adaptive" || len(c.cfg.Endpoints) < 2 {
		select {
		case <-ctx.Done():
		case <-s.Done():
		case <-l.Done():
		case <-rotate:
			s.Drop(l)
		}
		return nil, index
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	var a *pathPreparation
	defer func() {
		if a != nil {
			a.close()
		}
	}()
	var nextTry time.Time
	suspected := false
	commit := func() (*carrier.Link, int) {
		ep := c.cfg.Endpoints[a.index]
		candidate, err := c.connectCarrier(ctx, s, ep, true, a.prepared)
		// Activation now owns the preparation. Never close a successful live
		// link from the preparation cleanup or its old timeout context.
		a.prepared = nil
		a.cancel()
		nextIndex := a.index
		a = nil
		if err != nil {
			s.RecoveryEvent("activation_failed", "carrier", ep.Network, "session_lost", errors.Is(err, session.ErrSessionLost))
			return nil, index
		}
		if err = s.Attach(candidate); err != nil {
			_ = candidate.Close()
			return nil, index
		}
		return candidate, nextIndex
	}
	for {
		var ready <-chan struct{}
		if a != nil && !a.ready {
			ready = a.done
		}
		select {
		case <-ctx.Done():
			return nil, index
		case <-s.Done():
			return nil, index
		case <-rotate:
			s.Drop(l)
			return nil, index
		case <-l.Done():
			if a != nil {
				select {
				case <-a.done:
				case <-ctx.Done():
					return nil, index
				}
				if a.err == nil {
					s.RecoveryEvent("commit", "generation", a.generation, "reason", "carrier_closed", "prepared", true)
					return commit()
				}
			}
			return nil, index
		case <-ready:
			a.ready = true
			if a.err != nil {
				s.RecoveryEvent("prepare_failed", "carrier", c.cfg.Endpoints[a.index].Network, "generation", a.generation)
				a.close()
				a = nil
				nextTry = time.Now().Add(time.Second)
				continue
			}
			state := a.prepared.ConnectionState()
			s.RecoveryEvent("prepare_ready", "carrier", c.cfg.Endpoints[a.index].Network, "generation", a.generation, "ech_accepted", state.ECHAccepted, "tls_version", state.Version, "alpn", state.NegotiatedProtocol)
		case <-ticker.C:
		}
		state := s.PathState(l)
		if a != nil && (!state.Current || a.generation != state.Generation || a.proof != state.Proof) {
			s.RecoveryEvent("prepare_cancel", "generation", a.generation, "reason", "original_progress")
			a.close()
			a = nil
			nextTry = time.Now().Add(max(time.Second, 4*state.Threshold))
		}
		if !state.Suspect {
			suspected = false
			continue
		}
		if !suspected {
			s.RecoveryEvent("suspected", "generation", state.Generation, "carrier", l.Kind, "probe_age_ns", int64(state.ProbeAge), "threshold_ns", int64(state.Threshold), "samples", state.Samples, "history_horizon_ns", int64(state.Horizon), "demand", state.Demand)
			suspected = true
		}
		if c.cfg.RecoveryNoPrepare {
			if state.Confirmed {
				s.RecoveryEvent("commit", "generation", state.Generation, "reason", "confirmed_probe_stall", "prepared", false)
				s.Drop(l)
				return nil, index
			}
			continue
		}
		if a == nil && !time.Now().Before(nextTry) {
			// Pick a distinct HTTP path. Legacy carriers remain available for
			// ordinary recovery but are not silently substituted for ECH.
			for i := 1; i < len(c.cfg.Endpoints); i++ {
				next := (index + i) % len(c.cfg.Endpoints)
				ep := c.cfg.Endpoints[next]
				if ep.Network == "h2" || ep.Network == "h3" {
					a = c.preparePath(ctx, s, next, state)
					break
				}
			}
		}
		if a != nil && a.ready && state.Confirmed && a.generation == state.Generation && a.proof == state.Proof {
			s.RecoveryEvent("commit", "generation", state.Generation, "reason", "confirmed_probe_stall", "prepared", true, "probe_age_ns", int64(state.ProbeAge), "threshold_ns", int64(state.Threshold))
			next, nextIndex := commit()
			if next != nil {
				return next, nextIndex
			}
			// After HELLO the server may already have replaced the original,
			// even if WELCOME was lost. Observe closure or retry with a higher
			// attempt; only TLS preparation guarantees the old path is intact.
			nextTry = time.Now().Add(max(time.Second, 4*state.Threshold))
		}
	}
}
