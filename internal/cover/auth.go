// Package cover provides connection-bound HTTP authentication and an ordinary
// static site. It does not open proxy sessions or implement an HTTP transport.
package cover

import (
	"container/heap"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"math"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	AuthorizationHeader = "Authorization"
	DefaultWindow       = 30 * time.Second
	DefaultMaxNonces    = 4096
	MaxNonces           = 65536

	authVersion   = 1
	authPrefix    = "Bearer "
	authBytes     = 1 + 8 + 16 + sha256.Size
	authValueSize = len(authPrefix) + (authBytes*8+5)/6
	maxRequestURI = 4096
	maxAuthority  = 512
	exporterLabel = "EXPORTER-PROTO-X-HTTP-AUTH-v1"
	macDomain     = "PROTO-X HTTP authentication v1\x00"
)

// Config controls the authentication route and its bounded replay cache.
// Path is a required canonical ASCII path, without query or percent escapes.
// Window is an inclusive clock allowance in each direction, in whole seconds.
type Config struct {
	Path      string
	Window    time.Duration
	MaxNonces int
}

// Gate is safe for concurrent requests. Keep one Gate for at least the lifetime
// of the TLS connections it authenticates: replacing its replay cache while
// retaining those connections would allow previously accepted headers again.
type Gate struct {
	key       [32]byte
	path      string
	window    int64
	maxNonces int
	now       func() time.Time

	mu         sync.Mutex
	clockFloor int64
	nonces     map[nonce]int64
	expires    expiryQueue
}

type nonce [16]byte

// NewGate copies the shared 256-bit key. A hexadecimal token must be decoded by
// the caller first. Invalid configuration errors never contain the key.
func NewGate(token []byte, cfg Config) (*Gate, error) {
	if len(token) != 32 {
		return nil, errors.New("cover key must contain exactly 32 bytes")
	}
	if cfg.Path == "" || cfg.Path == "/" || len(cfg.Path) > 1024 || !strings.HasPrefix(cfg.Path, "/") ||
		path.Clean(cfg.Path) != cfg.Path || !visibleASCII(cfg.Path) ||
		strings.ContainsAny(cfg.Path, "?#%\\") || (&url.URL{Path: cfg.Path}).EscapedPath() != cfg.Path {
		return nil, errors.New("cover path must be a canonical non-root ASCII path without query or escapes")
	}
	if cfg.Window == 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.Window < time.Second || cfg.Window > 5*time.Minute || cfg.Window%time.Second != 0 {
		return nil, errors.New("cover clock window must be 1..300 whole seconds")
	}
	if cfg.MaxNonces == 0 {
		cfg.MaxNonces = DefaultMaxNonces
	}
	if cfg.MaxNonces < 1 || cfg.MaxNonces > MaxNonces {
		return nil, errors.New("cover nonce capacity must be 1..65536")
	}
	g := &Gate{path: cfg.Path, window: int64(cfg.Window / time.Second),
		maxNonces: cfg.MaxNonces, now: time.Now, nonces: make(map[nonce]int64)}
	copy(g.key[:], token)
	return g, nil
}

// SignRequest sets a fresh Authorization header using the explicitly supplied
// connection state. req.TLS may be nil, as it normally is on a client request.
// Call this anew for every HTTP request, including another stream on the same
// TLS connection, and after selecting a different TLS connection.
func (g *Gate) SignRequest(req *http.Request, state *tls.ConnectionState) error {
	authority, uri, ok := g.requestFields(req)
	if !ok {
		return errors.New("request does not match the cover authentication route")
	}
	exporter, err := keyMaterial(state)
	if err != nil {
		return err
	}
	now := g.now().Unix()
	if now < 0 || now > math.MaxInt64-g.window {
		return errors.New("unsupported authentication clock value")
	}
	var payload [authBytes]byte
	payload[0] = authVersion
	binary.BigEndian.PutUint64(payload[1:9], uint64(now))
	if _, err := rand.Read(payload[9:25]); err != nil {
		return errors.New("authentication nonce generation failed")
	}
	copy(payload[25:], g.mac(payload[:25], exporter, req.Method, authority, uri))
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set(AuthorizationHeader, authPrefix+base64.RawURLEncoding.EncodeToString(payload[:]))
	return nil
}

// Authorize consumes a valid request nonce exactly once. False always means
// the caller should use its ordinary site handler, without an authentication
// challenge, diagnostic body, cookie, or proxy-session allocation. This method
// writes no response, reads no body, and emits no log or authentication value.
func (g *Gate) Authorize(req *http.Request) bool {
	authority, uri, ok := g.requestFields(req)
	if !ok {
		return false
	}
	values := req.Header.Values(AuthorizationHeader)
	if len(values) != 1 || len(values[0]) != authValueSize || !strings.HasPrefix(values[0], authPrefix) {
		return false
	}
	var payload [authBytes]byte
	n, err := base64.RawURLEncoding.Strict().Decode(payload[:], []byte(values[0][len(authPrefix):]))
	if err != nil || n != len(payload) || payload[0] != authVersion {
		return false
	}
	exporter, err := keyMaterial(req.TLS)
	if err != nil {
		return false
	}
	if !hmac.Equal(payload[25:], g.mac(payload[:25], exporter, req.Method, authority, uri)) {
		return false
	}

	stamp := binary.BigEndian.Uint64(payload[1:9])
	if stamp > uint64(math.MaxInt64-g.window) {
		return false
	}
	issued := int64(stamp)
	var id nonce
	copy(id[:], payload[9:25])
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now().Unix()
	if now < 0 {
		return false
	}
	// Never let wall-clock rollback make an expired, removed nonce valid again.
	// A large clock correction can temporarily reject new authentications; it
	// does not affect ordinary site requests or already admitted HTTP streams.
	if now > g.clockFloor {
		g.clockFloor = now
	}
	now = g.clockFloor
	if (issued > now && issued-now > g.window) || (issued <= now && now-issued > g.window) {
		return false
	}
	for len(g.expires) > 0 && g.expires[0].until < now {
		old := heap.Pop(&g.expires).(expiry)
		delete(g.nonces, old.id)
	}
	if _, replay := g.nonces[id]; replay {
		return false
	}
	if len(g.nonces) >= g.maxNonces {
		// Evicting a live entry would silently turn replay protection off.
		return false
	}
	until := issued + g.window
	g.nonces[id] = until
	heap.Push(&g.expires, expiry{id: id, until: until})
	return true
}

func keyMaterial(state *tls.ConnectionState) ([]byte, error) {
	if state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 {
		return nil, errors.New("HTTP authentication requires completed TLS 1.3")
	}
	b, err := state.ExportKeyingMaterial(exporterLabel, nil, sha256.Size)
	if err != nil {
		return nil, errors.New("TLS exporter unavailable")
	}
	return b, nil
}

func (g *Gate) requestFields(req *http.Request) (authority, uri string, ok bool) {
	if req == nil || req.URL == nil || req.Method != http.MethodPost ||
		req.URL.User != nil || req.URL.Fragment != "" || req.URL.Opaque != "" ||
		req.URL.Path != g.path || len(req.URL.RawPath) > maxRequestURI ||
		len(req.URL.RawQuery) > maxRequestURI || len(req.RequestURI) > maxRequestURI {
		return "", "", false
	}
	// Reject oversized raw fields before EscapedPath or RequestURI can scan or
	// allocate from them. The decoded path must already equal the short route.
	if req.URL.EscapedPath() != g.path {
		return "", "", false
	}
	uri = req.URL.RequestURI()
	if len(uri) > maxRequestURI || (req.RequestURI != "" && req.RequestURI != uri) {
		return "", "", false
	}
	authority = req.Host
	if authority == "" {
		authority = req.URL.Host
	}
	// Require an already encoded ASCII authority so the HTTP transport will
	// not perform an IDNA transformation after the MAC has been calculated.
	if len(authority) == 0 || len(authority) > maxAuthority || !visibleASCII(authority) ||
		strings.ContainsAny(authority, "/?#\\@") {
		return "", "", false
	}
	return authority, uri, true
}

func visibleASCII(s string) bool {
	for i := range len(s) {
		if s[i] <= ' ' || s[i] >= 127 {
			return false
		}
	}
	return true
}

func (g *Gate) mac(prefix, exporter []byte, method, authority, uri string) []byte {
	m := hmac.New(sha256.New, g.key[:])
	_, _ = m.Write([]byte(macDomain))
	_, _ = m.Write(prefix)
	_, _ = m.Write(exporter)
	macField(m, method)
	macField(m, authority)
	macField(m, uri)
	return m.Sum(nil)
}

func macField(m hash.Hash, value string) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = m.Write(size[:])
	_, _ = m.Write([]byte(value))
}

type expiry struct {
	id    nonce
	until int64
}

type expiryQueue []expiry

func (q expiryQueue) Len() int           { return len(q) }
func (q expiryQueue) Less(i, j int) bool { return q[i].until < q[j].until }
func (q expiryQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *expiryQueue) Push(v any)        { *q = append(*q, v.(expiry)) }
func (q *expiryQueue) Pop() any {
	old := *q
	last := old[len(old)-1]
	old[len(old)-1] = expiry{}
	*q = old[:len(old)-1]
	return last
}
