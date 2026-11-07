package session

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"proto-x/internal/carrier"
)

// An idle application must remain attached for multiple failure intervals.
// The server needs its own RTT samples only for the optional adaptive sender.
func TestIdleHeartbeatKeepsBothPeersAlive(t *testing.T) {
	for _, adaptive := range []bool{false, true} {
		name := "default"
		if adaptive {
			name = "adaptive"
		}
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			cfg.DeadAfter = 500 * time.Millisecond
			cfg.Adaptive = adaptive
			p := newMemorySessions(t, cfg)
			select {
			case <-p.cl.Done():
				t.Fatal("idle client carrier closed")
			case <-p.sl.Done():
				t.Fatal("idle server carrier closed")
			case <-time.After(3 * cfg.DeadAfter):
			}
			if p.client.RTTNanos.Load() <= 0 {
				t.Fatal("client received no heartbeat response")
			}
			if sampled := p.server.RTTNanos.Load() > 0; sampled != adaptive {
				t.Fatalf("server sampled RTT=%v with adaptive=%v", sampled, adaptive)
			}
			if p.client.Reattachments.Load() != 1 || p.server.Reattachments.Load() != 1 {
				t.Fatal("idle session replaced its carrier")
			}
		})
	}
}

func TestSlowClientHeartbeatDoesNotExpireHealthyServer(t *testing.T) {
	serverCfg := testConfig()
	serverCfg.DeadAfter = 500 * time.Millisecond
	clientCfg := serverCfg
	clientCfg.Heartbeat = 5 * time.Second
	clientCfg.DeadAfter = 10 * time.Second
	clientCfg.ResumeTTL = 20 * time.Second
	for _, cfg := range []Config{serverCfg, clientCfg} {
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	client := New("unequal-heartbeat", false, clientCfg)
	server := New("unequal-heartbeat", true, serverCfg)
	t.Cleanup(func() { client.Close(context.Canceled); server.Close(context.Canceled) })
	c, s := net.Pipe()
	cl, sl := carrier.AcceptTLS(c), carrier.AcceptTLS(s)
	if err := server.Attach(sl); err != nil {
		t.Fatal(err)
	}
	if err := client.Attach(cl); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cl.Done():
		t.Fatal("healthy client carrier closed with unequal heartbeat intervals")
	case <-sl.Done():
		t.Fatal("server mistook a slow peer heartbeat for path failure")
	case <-time.After(3 * serverCfg.DeadAfter):
	}
	if server.RTTNanos.Load() <= 0 {
		t.Fatal("server did not probe the peer during a long quiet interval")
	}
}

type silentWriter struct {
	net.Conn
	silent atomic.Bool
}

func (c *silentWriter) Write(p []byte) (int, error) {
	if c.silent.Load() {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

// This is record-level fault injection, not packet loss emulation. Dropping
// either direction must still detach the default one-probe/two-way exchange.
func TestHeartbeatDetectsEitherSilentDirection(t *testing.T) {
	for _, upstream := range []bool{true, false} {
		name := "downstream"
		if upstream {
			name = "upstream"
		}
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			cfg.DeadAfter = 500 * time.Millisecond
			client := New("idle-fault", false, cfg)
			server := New("idle-fault", true, cfg)
			t.Cleanup(func() { client.Close(context.Canceled); server.Close(context.Canceled) })
			cc, sc := net.Pipe()
			c, s := &silentWriter{Conn: cc}, &silentWriter{Conn: sc}
			cl, sl := carrier.AcceptTLS(c), carrier.AcceptTLS(s)
			if err := server.Attach(sl); err != nil {
				t.Fatal(err)
			}
			if err := client.Attach(cl); err != nil {
				t.Fatal(err)
			}
			waitCondition(t, time.Second, "initial heartbeat", func() bool { return client.RTTNanos.Load() > 0 })
			if upstream {
				c.silent.Store(true)
			} else {
				s.silent.Store(true)
			}
			waitCondition(t, time.Second, "silent path to detach at both peers", func() bool {
				c, _, _ := client.Current()
				s, _, _ := server.Current()
				return c == nil && s == nil
			})
		})
	}
}
