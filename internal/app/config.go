package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"proto-x/internal/session"
)

type Endpoint struct {
	Network    string `json:"network"`
	Address    string `json:"address"`
	ServerName string `json:"server_name"`
}
type Config struct {
	TLSListen     string     `json:"tls_listen,omitempty"`
	QUICListen    string     `json:"quic_listen,omitempty"`
	SOCKSListen   string     `json:"socks_listen,omitempty"`
	Endpoints     []Endpoint `json:"endpoints,omitempty"`
	CertFile      string     `json:"cert_file,omitempty"`
	KeyFile       string     `json:"key_file,omitempty"`
	TokenFile     string     `json:"token_file"`
	Pin           string     `json:"pin_sha256,omitempty"`
	RateMbps      float64    `json:"rate_mbps"`
	Priority      bool       `json:"priority"`
	Adaptive      bool       `json:"adaptive"`
	AllowPrivate  bool       `json:"allow_private_targets,omitempty"`
	Window        int        `json:"window_bytes"`
	MaxFlows      int        `json:"max_flows"`
	MaxSessions   int        `json:"max_sessions,omitempty"`
	HeartbeatMS   int        `json:"heartbeat_ms"`
	DeadMS        int        `json:"dead_ms"`
	ResumeSeconds int        `json:"resume_seconds"`
	DialTimeoutMS int        `json:"dial_timeout_ms"`
	RotateSeconds int        `json:"test_rotate_seconds,omitempty"`
}

func Defaults() Config {
	return Config{RateMbps: 8, Priority: true, Window: 64 << 10, MaxFlows: 32, MaxSessions: 2, HeartbeatMS: 500, DeadMS: 2000, ResumeSeconds: 90, DialTimeoutMS: 1200}
}
func (c Config) Session() session.Config {
	return session.Config{Window: c.Window, MaxFlows: c.MaxFlows, Rate: c.RateMbps * 1e6 / 8, Priority: c.Priority, Adaptive: c.Adaptive, Heartbeat: time.Duration(c.HeartbeatMS) * time.Millisecond, DeadAfter: time.Duration(c.DeadMS) * time.Millisecond, ResumeTTL: time.Duration(c.ResumeSeconds) * time.Second}
}
func Load(path string) (Config, error) {
	c := Defaults()
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	if c.MaxSessions < 1 || c.MaxSessions > 16 || c.DialTimeoutMS < 100 || c.DialTimeoutMS > 30000 || c.RotateSeconds < 0 {
		return c, errors.New("invalid configuration limits")
	}
	if err := c.Session().Validate(); err != nil {
		return c, err
	}
	base := filepath.Dir(path)
	for _, p := range []*string{&c.CertFile, &c.KeyFile, &c.TokenFile} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	return c, nil
}
func Token(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	s := strings.TrimSpace(string(b))
	v, e := hex.DecodeString(s)
	if e != nil || len(v) != 32 {
		return "", errors.New("token must be 32 random bytes encoded as hex")
	}
	return s, nil
}
func RandomID() (string, error) {
	b := make([]byte, 16)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}

func Init(dir, host string, tlsPort, quicPort int) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	for _, name := range []string{"server.json", "client.json", "token", "server.key", "server.crt"} {
		if _, e := os.Stat(filepath.Join(dir, name)); e == nil {
			return fmt.Errorf("refusing to overwrite %s", name)
		}
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return e
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "proto-x"}, DNSNames: []string{"proto-x.local"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if e != nil {
		return e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return e
	}
	token := make([]byte, 32)
	if _, e = rand.Read(token); e != nil {
		return e
	}
	pin := sha256.Sum256(der)
	s := Defaults()
	s.TLSListen = fmt.Sprintf(":%d", tlsPort)
	s.QUICListen = fmt.Sprintf(":%d", quicPort)
	s.CertFile = "server.crt"
	s.KeyFile = "server.key"
	s.TokenFile = "token"
	c := Defaults()
	c.RateMbps = 2
	c.SOCKSListen = "127.0.0.1:1088"
	c.TokenFile = "token"
	c.Pin = hex.EncodeToString(pin[:])
	c.Endpoints = []Endpoint{{Network: "quic", Address: fmt.Sprintf("%s:%d", host, quicPort), ServerName: "proto-x.local"}, {Network: "tls", Address: fmt.Sprintf("%s:%d", host, tlsPort), ServerName: "proto-x.local"}}
	sb, _ := json.MarshalIndent(s, "", "  ")
	cb, _ := json.MarshalIndent(c, "", "  ")
	files := map[string][]byte{"server.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "server.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), "token": []byte(hex.EncodeToString(token)), "server.json": sb, "client.json": cb}
	for n, b := range files {
		if e = os.WriteFile(filepath.Join(dir, n), b, 0600); e != nil {
			return e
		}
	}
	return nil
}
