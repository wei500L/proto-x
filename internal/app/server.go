package app

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"proto-x/internal/carrier"
	"proto-x/internal/session"
	"proto-x/internal/wire"
)

type hello struct {
	Version int    `json:"version"`
	Session string `json:"session"`
	Token   string `json:"token"`
	Resume  bool   `json:"resume"`
	Window  int    `json:"window"`
	Attempt uint64 `json:"attempt,omitempty"`
}
type welcome struct {
	OK      bool   `json:"ok"`
	Resumed bool   `json:"resumed"`
	Error   string `json:"error,omitempty"`
	Attempt uint64 `json:"attempt,omitempty"`
}
type Server struct {
	cfg      Config
	token    string
	mu       sync.Mutex
	sessions map[string]*session.Session
	slots    chan struct{}
}

func RunServer(ctx context.Context, cfg Config) error {
	if err := cfg.validateWeb(true); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cert, e := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if e != nil {
		return e
	}
	token, e := Token(cfg.TokenFile)
	if e != nil {
		return e
	}
	if cfg.TLSListen == "" && cfg.QUICListen == "" && cfg.WebListen == "" && cfg.HTTP3Listen == "" {
		return errors.New("at least one listener required")
	}
	s := &Server{cfg: cfg, token: token, sessions: make(map[string]*session.Session), slots: make(chan struct{}, 8)}
	var closers []func()
	defer func() {
		for _, f := range closers {
			f()
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, ss := range s.sessions {
			ss.Close(context.Canceled)
		}
	}()
	errs := make(chan error, 4)
	webClosers, e := s.serveWeb(ctx, cert, errs)
	if e != nil {
		return e
	}
	closers = append(closers, webClosers...)
	if cfg.TLSListen != "" {
		ln, e := tls.Listen("tcp", cfg.TLSListen, carrier.TLSConfig(cert))
		if e != nil {
			return e
		}
		closers = append(closers, func() { _ = ln.Close() })
		go func() {
			for {
				c, e := ln.Accept()
				if e != nil {
					errs <- e
					return
				}
				if tc, ok := c.(*tls.Conn); ok {
					if t, ok := tc.NetConn().(*net.TCPConn); ok {
						_ = t.SetNoDelay(true)
						_ = t.SetWriteBuffer(16 << 10)
					}
				}
				l := carrier.AcceptTLS(c)
				s.admit(ctx, l)
			}
		}()
		slog.Info("TLS listener ready", "listen", cfg.TLSListen)
	}
	if cfg.QUICListen != "" {
		ln, e := quic.ListenAddr(cfg.QUICListen, carrier.TLSConfig(cert), carrier.QUICConfig())
		if e != nil {
			return e
		}
		closers = append(closers, func() { _ = ln.Close() })
		go func() {
			for {
				c, e := ln.Accept(ctx)
				if e != nil {
					errs <- e
					return
				}
				select {
				case s.slots <- struct{}{}:
				default:
					_ = c.CloseWithError(0, "busy")
					continue
				}
				go func() {
					defer func() { <-s.slots }()
					hctx, cancel := context.WithTimeout(ctx, 3*time.Second)
					defer cancel()
					l, e := carrier.AcceptQUIC(hctx, c)
					if e != nil {
						_ = c.CloseWithError(0, "handshake timeout")
						return
					}
					s.handshake(ctx, l)
				}()
			}
		}()
		slog.Info("QUIC listener ready", "listen", cfg.QUICListen)
	}
	select {
	case <-ctx.Done():
		return nil
	case e := <-errs:
		return e
	}
}

func (s *Server) admit(ctx context.Context, l *carrier.Link) {
	select {
	case s.slots <- struct{}{}:
		go func() { defer func() { <-s.slots }(); s.handshake(ctx, l) }()
	default:
		_ = l.Close()
	}
}
func (s *Server) handshake(ctx context.Context, l *carrier.Link) {
	accepted := false
	defer func() {
		if !accepted {
			_ = l.Close()
		}
	}()
	l.SetHandshakeDeadline(time.Now().Add(3 * time.Second))
	p, e := l.HandshakeRead()
	if e != nil || p.Kind != wire.Hello || p.ID != 0 {
		return
	}
	var h hello
	if json.Unmarshal(p.Payload, &h) != nil || h.Version != wire.Version || h.Window != s.cfg.Window || len(h.Token) != 64 || subtle.ConstantTimeCompare([]byte(h.Token), []byte(s.token)) != 1 {
		return
	}
	id, e := hex.DecodeString(h.Session)
	if e != nil || len(id) != 16 {
		return
	}
	s.mu.Lock()
	ss := s.sessions[h.Session]
	if ss != nil {
		select {
		case <-ss.Done():
			delete(s.sessions, h.Session)
			ss = nil
		default:
		}
	}
	w := welcome{OK: true, Resumed: ss != nil, Attempt: h.Attempt}
	if ss == nil && h.Resume {
		w.OK = false
		w.Error = "session_lost"
	} else if ss == nil && len(s.sessions) >= s.cfg.MaxSessions {
		w.OK = false
		w.Error = "session_limit"
	} else if ss == nil {
		sc := s.cfg.Session()
		sc.Dial = s.dialTarget
		ss = session.New(h.Session, true, sc)
		s.sessions[h.Session] = ss
		go func(id string, ss *session.Session) {
			<-ss.Done()
			s.mu.Lock()
			if s.sessions[id] == ss {
				delete(s.sessions, id)
			}
			s.mu.Unlock()
		}(h.Session, ss)
	}
	s.mu.Unlock()
	if ss != nil {
		ss.RecoveryEvent("hello_valid", "carrier", l.Kind, "attempt", h.Attempt, "resuming", h.Resume)
	}
	b, _ := json.Marshal(w)
	if l.HandshakeWrite(wire.Frame{Kind: wire.Welcome, Payload: b}) != nil || !w.OK {
		return
	}
	l.SetHandshakeDeadline(time.Time{})
	ss.RecoveryEvent("welcome_sent", "carrier", l.Kind, "attempt", h.Attempt)
	if e = ss.AttachAttempt(l, h.Attempt); e != nil {
		ss.RecoveryEvent("attach_rejected", "carrier", l.Kind, "attempt", h.Attempt)
		return
	}
	accepted = true
}

func (s *Server) dialTarget(ctx context.Context, target string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(target)
	if e != nil {
		return nil, e
	}
	pn, e := strconv.Atoi(port)
	if e != nil || pn < 1 || pn > 65535 {
		return nil, errors.New("invalid port")
	}
	addrs, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if e != nil {
		return nil, e
	}
	var last error
	for _, a := range addrs {
		a = a.Unmap()
		if !s.cfg.AllowPrivate && blocked(a) {
			last = errors.New("private target disabled")
			continue
		}
		d := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
		c, e := d.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port))
		if e == nil {
			if t, ok := c.(*net.TCPConn); ok {
				_ = t.SetNoDelay(true)
			}
			return c, nil
		}
		last = e
	}
	if last == nil {
		last = fmt.Errorf("no address for target")
	}
	return nil, last
}
func blocked(a netip.Addr) bool {
	return !a.IsValid() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified()
}
