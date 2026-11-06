package app

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"proto-x/internal/carrier"
	"proto-x/internal/session"
	"proto-x/internal/wire"
)

type Client struct {
	cfg     Config
	token   string
	mu      sync.Mutex
	current *session.Session
	changed chan struct{}
}

func RunClient(ctx context.Context, cfg Config) error {
	if len(cfg.Endpoints) == 0 {
		return errors.New("at least one endpoint required")
	}
	host, _, e := net.SplitHostPort(cfg.SOCKSListen)
	if e != nil {
		return e
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("SOCKS listener must bind a numeric loopback address")
	}
	token, e := Token(cfg.TokenFile)
	if e != nil {
		return e
	}
	for _, ep := range cfg.Endpoints {
		if ep.Network != "tls" && ep.Network != "quic" {
			return errors.New("invalid endpoint transport")
		}
		if _, e = carrier.ClientTLS(cfg.Pin, ep.ServerName); e != nil {
			return e
		}
	}
	ln, e := net.Listen("tcp", cfg.SOCKSListen)
	if e != nil {
		return e
	}
	defer ln.Close()
	c := &Client{cfg: cfg, token: token, changed: make(chan struct{})}
	go c.manage(ctx)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		c.mu.Lock()
		s := c.current
		c.mu.Unlock()
		if s != nil {
			s.Close(context.Canceled)
		}
	}()
	slog.Info("SOCKS5 listener ready", "listen", cfg.SOCKSListen)
	connections := make(chan struct{}, cfg.MaxFlows+8)
	for {
		conn, e := ln.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case connections <- struct{}{}:
			go func() { defer func() { <-connections }(); c.socks(ctx, conn) }()
		default:
			_ = conn.Close()
		}
	}
}
func (c *Client) publish(s *session.Session) {
	c.mu.Lock()
	c.current = s
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
}
func (c *Client) manage(ctx context.Context) {
	var s *session.Session
	resuming := false
	startIndex := 0
	for ctx.Err() == nil {
		if s == nil {
			id, e := RandomID()
			if e != nil {
				slog.Error("session ID generation failed")
				return
			}
			s = session.New(id, false, c.cfg.Session())
			c.publish(s)
			resuming = false
		}
		select {
		case <-s.Done():
			s = nil
			continue
		default:
		}
		var connected *carrier.Link
		connectedIndex := 0
		missingState := false
		for attempt := range c.cfg.Endpoints {
			index := (startIndex + attempt) % len(c.cfg.Endpoints)
			ep := c.cfg.Endpoints[index]
			dctx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.DialTimeoutMS)*time.Millisecond)
			cfg, _ := carrier.ClientTLS(c.cfg.Pin, ep.ServerName)
			l, e := carrier.Dial(dctx, ep.Network, ep.Address, cfg)
			if e == nil {
				deadline, _ := dctx.Deadline()
				l.SetHandshakeDeadline(deadline)
				b, _ := json.Marshal(hello{Version: wire.Version, Session: s.ID, Token: c.token, Resume: resuming, Window: c.cfg.Window})
				e = l.HandshakeWrite(wire.Frame{Kind: wire.Hello, Payload: b})
				if e == nil {
					var p wire.Frame
					p, e = l.HandshakeRead()
					if e == nil {
						var w welcome
						if p.Kind != wire.Welcome || json.Unmarshal(p.Payload, &w) != nil {
							e = wire.ErrFrame
						} else if !w.OK {
							if w.Error == "session_lost" {
								e = session.ErrSessionLost
							} else {
								e = fmt.Errorf("server: %s", w.Error)
							}
						} else if resuming && !w.Resumed {
							e = session.ErrSessionLost
						}
					}
				}
			}
			cancel()
			if e != nil {
				if l != nil {
					_ = l.Close()
				}
				slog.Info("carrier attempt failed", "carrier", ep.Network, "error", e)
				if errors.Is(e, session.ErrSessionLost) {
					missingState = true
				}
				continue
			}
			l.SetHandshakeDeadline(time.Time{})
			if e = s.Attach(l); e != nil {
				_ = l.Close()
				s = nil
				break
			}
			connected = l
			connectedIndex = index
			resuming = true
			break
		}
		if connected == nil {
			// Try every authorized path before deciding the retained state is
			// unavailable. A reachable alternate server may lack that state.
			if missingState && s != nil {
				s.Close(session.ErrSessionLost)
				s = nil
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		var rotate <-chan time.Time
		var timer *time.Timer
		if c.cfg.RotateSeconds > 0 {
			timer = time.NewTimer(time.Duration(c.cfg.RotateSeconds) * time.Second)
			rotate = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-connected.Done():
		case <-s.Done():
		case <-rotate:
			s.Drop(connected)
		}
		if timer != nil {
			timer.Stop()
		}
		// A carrier that just failed does not get another full dial timeout
		// ahead of an available alternate path.
		startIndex = (connectedIndex + 1) % len(c.cfg.Endpoints)
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (c *Client) open(ctx context.Context, target string) (*session.Flow, error) {
	for {
		c.mu.Lock()
		s, changed := c.current, c.changed
		c.mu.Unlock()
		if s != nil {
			return s.Open(ctx, target)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func (c *Client) socks(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if t, ok := conn.(*net.TCPConn); ok {
		_ = t.SetNoDelay(true)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var b [4]byte
	if _, e := io.ReadFull(conn, b[:2]); e != nil || b[0] != 5 || b[1] == 0 {
		return
	}
	methods := make([]byte, int(b[1]))
	if _, e := io.ReadFull(conn, methods); e != nil {
		return
	}
	noauth := false
	for _, m := range methods {
		noauth = noauth || m == 0
	}
	if !noauth {
		_, _ = conn.Write([]byte{5, 255})
		return
	}
	if _, e := conn.Write([]byte{5, 0}); e != nil {
		return
	}
	if _, e := io.ReadFull(conn, b[:]); e != nil || b[0] != 5 || b[1] != 1 || b[2] != 0 {
		_, _ = conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch b[3] {
	case 1:
		v := make([]byte, 4)
		if _, e := io.ReadFull(conn, v); e != nil {
			return
		}
		host = net.IP(v).String()
	case 4:
		v := make([]byte, 16)
		if _, e := io.ReadFull(conn, v); e != nil {
			return
		}
		host = net.IP(v).String()
	case 3:
		if _, e := io.ReadFull(conn, b[:1]); e != nil || b[0] == 0 {
			return
		}
		v := make([]byte, int(b[0]))
		if _, e := io.ReadFull(conn, v); e != nil {
			return
		}
		host = string(v)
	default:
		return
	}
	if _, e := io.ReadFull(conn, b[:2]); e != nil {
		return
	}
	port := binary.BigEndian.Uint16(b[:2])
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	octx, cancel := context.WithTimeout(ctx, 12*time.Second)
	f, e := c.open(octx, target)
	cancel()
	if e != nil {
		_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, e = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
		_ = f.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	session.Bridge(conn, f)
}
