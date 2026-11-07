package carrier

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"proto-x/internal/cover"
	"proto-x/internal/wire"
)

// WebOptions opens one real HTTP connection. A control POST and one duplex POST
// per virtual flow share that connection; no custom QUIC stream types are used.
type WebOptions struct {
	Network, Address, Authority, Path string
	TLSConfig                         *tls.Config
	Gate                              *cover.Gate
	Padding                           int
	// Initial sends HELLO in the first POST body after the TLS handshake.
	// It saves an HTTP response round trip without using TLS/QUIC early data.
	Initial *wire.Frame
}

func WebQUICConfig() *quic.Config {
	q := QUICConfig()
	q.MaxIncomingStreams = 128
	q.MaxIncomingUniStreams = 8 // HTTP/3 control and QPACK streams
	return q
}

type webSlot struct {
	ready   chan struct{}
	once    sync.Once
	writeMu sync.Mutex
	stream  *httpDuplex // published by closing ready
	err     error
}

type webLink struct {
	link      *Link
	client    bool
	padding   int
	cid       string
	base      *url.URL
	state     tls.ConnectionState
	gate      *cover.Gate
	rt        http.RoundTripper
	end       func()
	binding   [32]byte
	mu        sync.Mutex
	slots     map[uint64]*webSlot
	started   chan struct{}
	startOnce sync.Once
}

func newWebLink(kind string, client bool, padding int) *Link {
	l := newLink(kind, nil)
	l.web = &webLink{link: l, client: client, padding: padding,
		slots: make(map[uint64]*webSlot), started: make(chan struct{})}
	return l
}

func DialWeb(ctx context.Context, o WebOptions) (*Link, error) {
	if o.Gate == nil || o.TLSConfig == nil || !validWebPadding(o.Padding) || o.Authority == "" || o.Path == "" {
		return nil, errors.New("invalid HTTP carrier options")
	}
	if o.Initial != nil && (o.Initial.Kind != wire.Hello || o.Initial.ID != 0) {
		return nil, errors.New("HTTP initial record must be HELLO")
	}
	l := newWebLink(o.Network, true, o.Padding)
	w := l.web
	w.gate = o.Gate
	w.base = &url.URL{Scheme: "https", Host: o.Authority, Path: o.Path}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		_ = l.Close()
		return nil, err
	}
	w.cid = hex.EncodeToString(id[:])
	var err error
	switch o.Network {
	case "h2":
		d := tls.Dialer{NetDialer: &net.Dialer{KeepAlive: 15 * time.Second}, Config: o.TLSConfig}
		var c net.Conn
		c, err = d.DialContext(ctx, "tcp", o.Address)
		if err == nil {
			tc := c.(*tls.Conn)
			w.state = tc.ConnectionState()
			w.end = func() { _ = c.Close() }
			if w.state.NegotiatedProtocol != "h2" {
				err = errors.New("HTTP/2 was not negotiated")
			} else {
				w.rt, err = newWebHTTP2Conn(ctx, c, o.Address)
			}
		}
	case "h3":
		var c *quic.Conn
		c, err = quic.DialAddr(ctx, o.Address, o.TLSConfig, WebQUICConfig())
		if err == nil {
			w.state = c.ConnectionState().TLS
			w.end = func() { _ = c.CloseWithError(0, "") }
			if w.state.NegotiatedProtocol != "h3" {
				err = errors.New("HTTP/3 was not negotiated")
			} else {
				tr := &http3.Transport{DisableCompression: true, MaxResponseHeaderBytes: 16 << 10}
				w.rt = tr.NewClientConn(c)
			}
		}
	default:
		err = errors.New("invalid HTTP carrier network")
	}
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	// The HTTP request context belongs to the carrier, not the dial timeout:
	// canceling a successful dial must not terminate its long-lived POST body.
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	slot, err := w.slot(0)
	if err == nil {
		slot.once.Do(func() { slot.stream, slot.err = w.open(0, o.Initial); close(slot.ready) })
		err = slot.err
	}
	if !stop() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	l.control = slot.stream
	return l, nil
}

func (w *webLink) slot(id uint64) (*webSlot, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	select {
	case <-w.link.done:
		return nil, io.ErrClosedPipe
	default:
	}
	s := w.slots[id]
	if s == nil {
		if len(w.slots) >= 129 {
			return nil, errors.New("HTTP stream limit")
		}
		s = &webSlot{ready: make(chan struct{})}
		w.slots[id] = s
	}
	return s, nil
}

func (w *webLink) open(id uint64, initial *wire.Frame) (*httpDuplex, error) {
	u := *w.base
	q := u.Query()
	q.Set("carrier", w.cid)
	q.Set("stream", strconv.FormatUint(id, 10))
	u.RawQuery = q.Encode()
	ctx, cancel := context.WithCancel(w.link.ctx)
	reader, writer := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), reader)
	if err != nil {
		cancel()
		_ = reader.Close()
		_ = writer.Close()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Cache-Control", "no-store")
	err = w.gate.SignRequest(req, &w.state)
	var firstDone chan error
	if err == nil && initial != nil {
		// The peer may process the request body immediately. Do not wait for
		// response headers before sending OPEN: that adds one RTT to every
		// new application connection. The pipe is bounded and is closed on
		// every RoundTrip error, so this writer cannot outlive a failed open.
		firstDone = make(chan error, 1)
		go func() { firstDone <- w.link.writeRecord(writer, *initial) }()
	}
	var resp *http.Response
	if err == nil {
		resp, err = w.rt.RoundTrip(req)
	}
	if err == nil && (resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/octet-stream") {
		err = errors.New("HTTP carrier request was not accepted")
	}
	if err == nil && firstDone != nil {
		err = <-firstDone
		firstDone = nil
	}
	if err != nil {
		cancel()
		_ = reader.Close()
		_ = writer.Close()
		if resp != nil {
			_ = resp.Body.Close()
		}
		if firstDone != nil {
			<-firstDone
		}
		return nil, err
	}
	return &httpDuplex{r: resp.Body, w: writer, closeWrite: writer.Close, readEnd: cancel, abortFn: func() {
		cancel()
		_ = writer.CloseWithError(io.ErrClosedPipe)
		_ = reader.Close()
		_ = resp.Body.Close()
	}}, nil
}

func (w *webLink) send(f wire.Frame) error {
	slot, err := w.slot(f.ID)
	if err != nil {
		return err
	}
	if w.client {
		first := false
		slot.once.Do(func() {
			slot.stream, slot.err = w.open(f.ID, &f)
			first = true
			close(slot.ready)
			if slot.err == nil {
				go w.link.readLoop(slot.stream, f.ID, true)
			}
		})
		if first {
			return slot.err
		}
	}
	select {
	case <-w.link.done:
		return io.ErrClosedPipe
	case <-slot.ready:
	}
	if slot.err != nil {
		return slot.err
	}
	slot.writeMu.Lock()
	defer slot.writeMu.Unlock()
	return w.link.writeRecord(slot.stream, f)
}

func (w *webLink) forget(id uint64) {
	w.mu.Lock()
	slot := w.slots[id]
	delete(w.slots, id)
	w.mu.Unlock()
	if slot != nil {
		select {
		case <-slot.ready:
			if slot.stream != nil {
				_ = slot.stream.Close()
			}
		default:
		}
	}
}

func (w *webLink) close() {
	if w.end != nil {
		w.end()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, slot := range w.slots {
		select {
		case <-slot.ready:
			if slot.stream != nil {
				slot.stream.abort()
			}
		default:
		}
	}
}

type httpDuplex struct {
	r          io.ReadCloser
	w          io.Writer
	closeWrite func() error
	abortFn    func()
	readEnd    func()
	// ResponseWriter and its controller are valid only until ServeHTTP returns.
	// abort first interrupts blocked I/O, then waits for every call to leave this
	// barrier. The handler defers abort, including on request cancellation.
	ioMu      sync.RWMutex
	stopped   bool
	closed    atomic.Bool
	closeOnce sync.Once
	abortOnce sync.Once
	timerMu   sync.Mutex
	timer     *time.Timer
	aborted   bool
}

func (s *httpDuplex) Read(p []byte) (int, error) {
	s.ioMu.RLock()
	if s.stopped {
		s.ioMu.RUnlock()
		return 0, io.EOF
	}
	n, err := s.r.Read(p)
	s.ioMu.RUnlock()
	if err != nil && s.readEnd != nil {
		s.readEnd()
	}
	// A retired session flow has already consumed FIN and all bytes. An HTTP
	// reset caused by its completed handler is then a normal stream ending.
	if err != nil && s.closed.Load() {
		err = io.EOF
	}
	return n, err
}
func (s *httpDuplex) Write(p []byte) (int, error) {
	s.ioMu.RLock()
	defer s.ioMu.RUnlock()
	if s.stopped {
		return 0, io.ErrClosedPipe
	}
	return s.w.Write(p)
}
func (s *httpDuplex) Close() error {
	s.closeOnce.Do(func() { s.closed.Store(true); _ = s.closeWrite() })
	return nil
}
func (s *httpDuplex) abort() {
	s.abortOnce.Do(func() {
		s.timerMu.Lock()
		s.aborted = true
		if s.timer != nil {
			s.timer.Stop()
		}
		s.timerMu.Unlock()
		s.ioMu.RLock()
		s.abortFn()
		s.ioMu.RUnlock()
		s.ioMu.Lock()
		s.stopped = true
		s.ioMu.Unlock()
	})
}
func (s *httpDuplex) SetDeadline(t time.Time) error {
	s.timerMu.Lock()
	defer s.timerMu.Unlock()
	if s.aborted {
		return io.ErrClosedPipe
	}
	if s.timer != nil {
		s.timer.Stop()
	}
	if !t.IsZero() {
		s.timer = time.AfterFunc(time.Until(t), s.abort)
	}
	return nil
}

type flushingWriter struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (w flushingWriter) Write(b []byte) (int, error) {
	n, err := w.w.Write(b)
	if err == nil {
		err = w.rc.Flush()
	}
	return n, err
}

// WebHub serves both the public site and authenticated duplex HTTP streams.
// Rejected authentication follows the exact same site handler as ordinary use.
type WebHub struct {
	Gate      *cover.Gate
	Site      http.Handler
	Padding   int
	MaxLinks  int
	Handshake func(*Link)
	mu        sync.Mutex
	links     map[string]*Link
	closed    bool
}

func (h *WebHub) Close() {
	h.mu.Lock()
	h.closed = true
	links := make([]*Link, 0, len(h.links))
	for _, l := range h.links {
		links = append(links, l)
	}
	h.mu.Unlock()
	for _, l := range links {
		_ = l.Close()
	}
}

func connectionBinding(s *tls.ConnectionState) ([32]byte, error) {
	if s == nil {
		return [32]byte{}, errors.New("TLS required")
	}
	b, err := s.ExportKeyingMaterial("EXPORTER-HTTP-session-binding", nil, 32)
	return sha256.Sum256(b), err
}

func (h *WebHub) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if h.Gate == nil || h.Handshake == nil || (r.ProtoMajor != 2 && r.ProtoMajor != 3) || !h.Gate.Authorize(r) {
		h.Site.ServeHTTP(rw, r)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	cid := query.Get("carrier")
	decoded, de := hex.DecodeString(cid)
	id, ie := strconv.ParseUint(query.Get("stream"), 10, 64)
	binding, be := connectionBinding(r.TLS)
	if err != nil || de != nil || len(decoded) != 16 || ie != nil || be != nil || (id != 0 && id%2 == 0) || len(query) != 2 || len(query["carrier"]) != 1 || len(query["stream"]) != 1 {
		h.Site.ServeHTTP(rw, r)
		return
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		h.Site.ServeHTTP(rw, r)
		return
	}
	if h.links == nil {
		h.links = make(map[string]*Link)
	}
	l := h.links[cid]
	if id == 0 {
		if l != nil || len(h.links) >= h.MaxLinks || !validWebPadding(h.Padding) {
			h.mu.Unlock()
			h.Site.ServeHTTP(rw, r)
			return
		}
		l = newWebLink(fmt.Sprintf("h%d", r.ProtoMajor), false, h.Padding)
		l.web.binding = binding
		h.links[cid] = l
	} else if l == nil || subtle.ConstantTimeCompare(l.web.binding[:], binding[:]) != 1 {
		h.mu.Unlock()
		h.Site.ServeHTTP(rw, r)
		return
	}
	h.mu.Unlock()
	if id == 0 {
		defer func() {
			_ = l.Close()
			h.mu.Lock()
			if h.links[cid] == l {
				delete(h.links, cid)
			}
			h.mu.Unlock()
		}()
	} else {
		select {
		case <-l.web.started:
		case <-l.done:
			return
		case <-r.Context().Done():
			return
		}
	}
	slot, err := l.web.slot(id)
	if err != nil {
		h.Site.ServeHTTP(rw, r)
		return
	}
	finished := make(chan struct{})
	var finishOnce sync.Once
	finish := func() { finishOnce.Do(func() { close(finished) }) }
	rc := http.NewResponseController(rw)
	stream := &httpDuplex{r: r.Body, w: flushingWriter{rw, rc}, closeWrite: func() error { finish(); return nil }}
	stream.abortFn = func() {
		// A session-retired flow has no in-flight writer and all FINs have
		// been acknowledged. Let HTTP finish it normally; an immediate write
		// deadline here would turn normal retirement into an HTTP reset at the
		// peer before that peer's next retirement sweep.
		if !stream.closed.Load() {
			_ = rc.SetReadDeadline(time.Now())
			_ = rc.SetWriteDeadline(time.Now())
		}
		_ = r.Body.Close()
		finish()
	}
	claimed := false
	slot.once.Do(func() { claimed = true })
	if !claimed {
		h.Site.ServeHTTP(rw, r)
		return
	}
	defer stream.abort()
	rw.Header().Set("Content-Type", "application/octet-stream")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		slot.err = err
		close(slot.ready)
		l.fail(err)
		return
	}
	// Publish only after headers have been flushed: closing a link must not race
	// the initial ResponseWriter calls with deadline changes or frame writes.
	slot.stream = stream
	close(slot.ready)
	select {
	case <-l.done:
		return
	default:
	}
	if id == 0 {
		l.control = stream
		h.Handshake(l)
	} else {
		go l.readLoop(stream, id, true)
	}
	select {
	case <-finished:
	case <-l.done:
	case <-r.Context().Done():
		if !stream.closed.Load() {
			l.fail(r.Context().Err())
		}
	}
}
