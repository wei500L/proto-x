// Package carrier carries records over TLS/TCP or independent QUIC streams.
// It implements neither cryptography nor packet loss recovery itself.
package carrier

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"proto-x/internal/wire"
)

const ALPN = "proto-x/1"

type Link struct {
	Kind         string
	TCP          net.Conn
	QUIC         *quic.Conn
	control      io.ReadWriteCloser
	ctx          context.Context
	cancel       context.CancelFunc
	in           chan wire.Frame
	done         chan struct{}
	once         sync.Once
	mu           sync.Mutex
	err          error
	writers      map[uint64]*writer
	seen         map[uint64]bool
	controlMu    sync.Mutex
	controlQueue chan wire.Frame
	Sent         atomic.Uint64
	Received     atomic.Uint64
}
type writer struct {
	mu     sync.Mutex
	stream *quic.SendStream
}

func TLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{ALPN}}
}

// ClientTLS uses an explicit certificate pin. InsecureSkipVerify only bypasses
// the public CA path; VerifyConnection always verifies the supplied SHA-256 pin.
func ClientTLS(pin, serverName string) (*tls.Config, error) {
	want, err := hex.DecodeString(pin)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("a 64-hex SHA-256 certificate pin is required")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, NextProtos: []string{ALPN}, InsecureSkipVerify: true, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.PeerCertificates) == 0 {
			return errors.New("missing certificate")
		}
		sum := sha256.Sum256(s.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare(sum[:], want) != 1 {
			return errors.New("certificate pin mismatch")
		}
		if s.NegotiatedProtocol != ALPN {
			return errors.New("ALPN mismatch")
		}
		return nil
	}}, nil
}

func QUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 3 * time.Second, MaxIdleTimeout: 12 * time.Second,
		InitialStreamReceiveWindow: 64 << 10, MaxStreamReceiveWindow: 128 << 10,
		InitialConnectionReceiveWindow: 512 << 10, MaxConnectionReceiveWindow: 4 << 20,
		MaxIncomingStreams: 1, MaxIncomingUniStreams: 128, Allow0RTT: false,
	}
}

func newLink(kind string, control io.ReadWriteCloser) *Link {
	ctx, cancel := context.WithCancel(context.Background())
	return &Link{Kind: kind, control: control, ctx: ctx, cancel: cancel, in: make(chan wire.Frame, 128), controlQueue: make(chan wire.Frame, 64), done: make(chan struct{}), writers: make(map[uint64]*writer), seen: make(map[uint64]bool)}
}

func Dial(ctx context.Context, kind, addr string, cfg *tls.Config) (*Link, error) {
	switch kind {
	case "tls":
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 15 * time.Second}, Config: cfg}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		if tc, ok := c.(*tls.Conn); ok {
			if t, ok := tc.NetConn().(*net.TCPConn); ok {
				_ = t.SetNoDelay(true)
				_ = t.SetWriteBuffer(16 << 10)
			}
		}
		l := newLink(kind, c)
		l.TCP = c
		return l, nil
	case "quic":
		c, err := quic.DialAddr(ctx, addr, cfg, QUICConfig())
		if err != nil {
			return nil, err
		}
		s, err := c.OpenStreamSync(ctx)
		if err != nil {
			_ = c.CloseWithError(0, "control stream")
			return nil, err
		}
		l := newLink(kind, s)
		l.QUIC = c
		return l, nil
	default:
		return nil, fmt.Errorf("unsupported carrier %q", kind)
	}
}

func AcceptTLS(c net.Conn) *Link { l := newLink("tls", c); l.TCP = c; return l }
func AcceptQUIC(ctx context.Context, c *quic.Conn) (*Link, error) {
	s, e := c.AcceptStream(ctx)
	if e != nil {
		return nil, e
	}
	l := newLink("quic", s)
	l.QUIC = c
	return l, nil
}

// Handshake operations must finish before Start; application records cannot be
// processed until the authenticated session has accepted this link.
func (l *Link) HandshakeWrite(f wire.Frame) error  { return wire.Write(l.control, f) }
func (l *Link) HandshakeRead() (wire.Frame, error) { return wire.Read(l.control) }
func (l *Link) SetHandshakeDeadline(t time.Time) {
	if d, ok := l.control.(interface{ SetDeadline(time.Time) error }); ok {
		_ = d.SetDeadline(t)
	}
}

func (l *Link) Start() {
	go l.controlLoop()
	go l.readLoop(l.control, 0, l.QUIC != nil)
	if l.QUIC != nil {
		go l.acceptStreams()
	}
}
func (l *Link) Frames() <-chan wire.Frame { return l.in }
func (l *Link) Done() <-chan struct{}     { return l.done }
func (l *Link) Err() error                { l.mu.Lock(); defer l.mu.Unlock(); return l.err }
func (l *Link) Close() error              { l.fail(io.EOF); return nil }
func (l *Link) fail(e error) {
	l.once.Do(func() {
		l.mu.Lock()
		l.err = e
		l.mu.Unlock()
		l.cancel()
		close(l.done)
		if l.QUIC != nil {
			_ = l.QUIC.CloseWithError(0, "link closed")
		} else if l.TCP != nil {
			_ = l.TCP.Close()
		}
	})
}

func (l *Link) readLoop(r io.Reader, id uint64, bound bool) {
	for {
		f, e := wire.Read(r)
		if e != nil {
			if bound && id != 0 && errors.Is(e, io.EOF) {
				l.mu.Lock()
				delete(l.seen, id)
				l.mu.Unlock()
				return
			}
			l.fail(e)
			return
		}
		validControl := id == 0 && (f.Kind == wire.Ack || f.Kind == wire.Opened || f.Kind == wire.Fin || f.Kind == wire.Reset)
		if bound && f.ID != id && !validControl {
			l.fail(wire.ErrFrame)
			return
		}
		l.Received.Add(uint64(wire.HeaderSize + len(f.Payload)))
		select {
		case l.in <- f:
		case <-l.done:
			return
		}
	}
}

// QueueControl never blocks the receiver on the peer's send window. It also
// carries terminal replies for retired flows without allocating new QUIC streams.
func (l *Link) QueueControl(f wire.Frame) bool {
	select {
	case <-l.done:
		return false
	default:
	}
	select {
	case l.controlQueue <- f:
		return true
	default:
		l.fail(errors.New("control queue exhausted"))
		return false
	}
}
func (l *Link) controlLoop() {
	for {
		select {
		case <-l.done:
			return
		case f := <-l.controlQueue:
			l.controlMu.Lock()
			e := wire.Write(l.control, f)
			l.controlMu.Unlock()
			if e != nil {
				l.fail(e)
				return
			}
			l.Sent.Add(uint64(wire.HeaderSize + len(f.Payload)))
		}
	}
}
func (l *Link) acceptStreams() {
	for {
		s, e := l.QUIC.AcceptUniStream(l.ctx)
		if e != nil {
			l.fail(e)
			return
		}
		go func() {
			f, e := wire.Read(s)
			if e != nil {
				l.fail(e)
				return
			}
			if f.ID == 0 {
				l.fail(wire.ErrFrame)
				return
			}
			l.mu.Lock()
			duplicate := l.seen[f.ID]
			l.seen[f.ID] = true
			l.mu.Unlock()
			if duplicate {
				l.fail(wire.ErrFrame)
				return
			}
			l.Received.Add(uint64(wire.HeaderSize + len(f.Payload)))
			select {
			case l.in <- f:
			case <-l.done:
				return
			}
			l.readLoop(s, f.ID, true)
		}()
	}
}

// Send serializes a virtual flow, but QUIC writers for different flows never
// wait on each other's stream flow-control window.
func (l *Link) Send(f wire.Frame) error {
	select {
	case <-l.done:
		return io.ErrClosedPipe
	default:
	}
	var err error
	if l.QUIC == nil || f.ID == 0 {
		l.controlMu.Lock()
		err = wire.Write(l.control, f)
		l.controlMu.Unlock()
	} else {
		l.mu.Lock()
		w := l.writers[f.ID]
		if w == nil {
			w = &writer{}
			l.writers[f.ID] = w
		}
		l.mu.Unlock()
		w.mu.Lock()
		if w.stream == nil {
			w.stream, err = l.QUIC.OpenUniStreamSync(l.ctx)
		}
		if err == nil {
			err = wire.Write(w.stream, f)
		}
		w.mu.Unlock()
	}
	if err != nil {
		l.fail(err)
	} else {
		l.Sent.Add(uint64(wire.HeaderSize + len(f.Payload)))
	}
	return err
}
func (l *Link) Forget(id uint64) {
	l.mu.Lock()
	w := l.writers[id]
	delete(l.writers, id)
	delete(l.seen, id)
	l.mu.Unlock()
	if w != nil {
		w.mu.Lock()
		if w.stream != nil {
			_ = w.stream.Close()
		}
		w.mu.Unlock()
	}
}
