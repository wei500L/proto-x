package carrier

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// WebTLSClientOptions configures standard Go TLS for an actual HTTP transport.
// It does not reproduce a browser's TLS or HTTP fingerprint.
type WebTLSClientOptions struct {
	// ServerName is the certificate identity, and the inner SNI when using ECH.
	// It must be explicit; routing addresses belong to the HTTP dialer.
	ServerName string
	// RootCAs nil selects the platform's normal roots. A supplied pool is cloned.
	RootCAs *x509.CertPool
	// PinSHA256 is an optional 64-hex SHA-256 of the leaf certificate DER. It is
	// an additional requirement after normal chain and hostname verification.
	PinSHA256 string
	// ExperimentalPinOnly explicitly replaces chain/hostname verification with
	// the required leaf pin. Use only for controlled deployments. Even in this
	// mode, Go verifies the outer ECH provider certificate on ECH rejection.
	ExperimentalPinOnly bool
	// NextProtos must explicitly contain only h2, h3, and/or http/1.1. Use the
	// protocols implemented by the selected HTTP transport, not a custom ALPN.
	NextProtos []string
	// ECHConfigList is a serialized RFC 9849 ECHConfigList, not an ECHConfig or
	// base64 text. Nil disables ECH; any non-nil value requires successful ECH.
	// Rejection is terminal for this connection. No retry without ECH occurs.
	ECHConfigList []byte
}

// WebTLSServerOptions supplies certificates and optional ECH decryption keys.
// Certificates must cover the intended inner names and the ECH public name
// for ordinary HTTPS visitors and authenticated ECH rejection responses.
type WebTLSServerOptions struct {
	Certificates []tls.Certificate
	NextProtos   []string
	ECHKeys      []tls.EncryptedClientHelloKey
	// RequireECH rejects non-ECH connections. Leave false when the same server
	// serves ordinary website visitors. Clients with ECHConfigList still require
	// ECH regardless of this setting.
	RequireECH bool
}

// WebClientTLS builds TLS 1.3 with normal CA/hostname verification by default.
// No ECH rejection callback is installed: crypto/tls verifies the provider's
// outer certificate itself, then returns *tls.ECHRejectionError. That path
// deliberately does not apply an inner-origin pin to the provider certificate.
// Callers must propagate rejection and must not retry with ECH disabled.
//
// The returned configuration and its private-key objects must not be modified
// while in use. HTTP/3 may use a Clone; verification hooks survive cloning.
func WebClientTLS(opts WebTLSClientOptions) (*tls.Config, error) {
	if opts.ServerName == "" || strings.TrimSpace(opts.ServerName) != opts.ServerName {
		return nil, errors.New("web TLS requires an explicit server name")
	}
	protos, err := webALPN(opts.NextProtos)
	if err != nil {
		return nil, err
	}
	var pin []byte
	if opts.PinSHA256 != "" {
		pin, err = hex.DecodeString(opts.PinSHA256)
		if err != nil || len(pin) != sha256.Size {
			return nil, errors.New("web TLS leaf pin must be a 64-hex SHA-256")
		}
	}
	if opts.ExperimentalPinOnly && len(pin) == 0 {
		return nil, errors.New("experimental pin-only web TLS requires a leaf pin")
	}
	requireECH := opts.ECHConfigList != nil
	if requireECH {
		if !webECHDNSName(opts.ServerName) {
			return nil, errors.New("web ECH requires an explicit inner DNS name")
		}
		if err := validateWebECHList(opts.ECHConfigList); err != nil {
			return nil, err
		}
	}
	config := &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		MaxVersion:                     tls.VersionTLS13,
		ServerName:                     opts.ServerName,
		NextProtos:                     slices.Clone(protos),
		InsecureSkipVerify:             opts.ExperimentalPinOnly, // Explicit pin check below.
		EncryptedClientHelloConfigList: bytes.Clone(opts.ECHConfigList),
	}
	if opts.RootCAs != nil {
		config.RootCAs = opts.RootCAs.Clone()
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if err := verifyWebNegotiation(state, protos, requireECH, false); err != nil {
			return err
		}
		if len(pin) != 0 {
			if len(state.PeerCertificates) == 0 {
				return errors.New("web TLS peer sent no certificate")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(pin, sum[:]) != 1 {
				return errors.New("web TLS leaf certificate pin mismatch")
			}
		}
		return nil
	}
	return config, nil
}

// WebServerTLS builds a standard TLS 1.3 configuration. ECH key syntax,
// supported HPKE parameters, and public/private-key correspondence are checked
// before serving. Handshake encryption and ECH acceptance remain in crypto/tls.
// A TCP server implementing HTTP/1.1 also accepts ordinary visitors that omit
// ALPN. WebClientTLS always requires an explicitly negotiated HTTP protocol.
func WebServerTLS(opts WebTLSServerOptions) (*tls.Config, error) {
	protos, err := webALPN(opts.NextProtos)
	if err != nil {
		return nil, err
	}
	if len(opts.Certificates) == 0 {
		return nil, errors.New("web TLS server requires a certificate")
	}
	certificates := make([]tls.Certificate, len(opts.Certificates))
	for i, cert := range opts.Certificates {
		if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
			return nil, fmt.Errorf("web TLS certificate %d lacks a chain or private key", i)
		}
		cert.Certificate = cloneWebByteSlices(cert.Certificate)
		cert.OCSPStaple = bytes.Clone(cert.OCSPStaple)
		cert.SignedCertificateTimestamps = cloneWebByteSlices(cert.SignedCertificateTimestamps)
		cert.SupportedSignatureAlgorithms = slices.Clone(cert.SupportedSignatureAlgorithms)
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("web TLS certificate %d: %w", i, err)
		}
		certificates[i] = cert
	}
	if (opts.ECHKeys != nil || opts.RequireECH) && len(opts.ECHKeys) == 0 {
		return nil, errors.New("web TLS ECH key set is empty")
	}
	var keys []tls.EncryptedClientHelloKey
	for i, key := range opts.ECHKeys {
		if err := validateWebECHKey(key); err != nil {
			return nil, fmt.Errorf("web TLS ECH key %d: %w", i, err)
		}
		keys = append(keys, tls.EncryptedClientHelloKey{
			Config: bytes.Clone(key.Config), PrivateKey: bytes.Clone(key.PrivateKey), SendAsRetry: key.SendAsRetry,
		})
	}
	config := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		MaxVersion:               tls.VersionTLS13,
		Certificates:             certificates,
		NextProtos:               slices.Clone(protos),
		EncryptedClientHelloKeys: keys,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyWebNegotiation(state, protos, opts.RequireECH, slices.Contains(protos, "http/1.1"))
		},
	}
	return config, nil
}

// GenerateWebECH returns one RFC 9849 ECHConfigList and its server key. HPKE
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM are standard RFC 9180
// implementations from crypto/hpke. Only the public configuration's vector
// encoding is done here; crypto/tls performs all ECH encryption/decryption.
//
// publicName is the intentionally visible outer DNS name. It needs a valid
// server certificate and a reachable route; this function provisions neither.
// maximum_name_length=255 requests name-length padding; it does not hide the
// destination IP, traffic shape, Go fingerprint, or use of the ECH extension.
// Persist the returned key privately. Publish only configList. Key rotation
// should retain old keys while published configurations may remain cached.
func GenerateWebECH(publicName string) ([]byte, tls.EncryptedClientHelloKey, error) {
	if !webECHDNSName(publicName) {
		return nil, tls.EncryptedClientHelloKey{}, errors.New("ECH public name must be an ASCII DNS name without a trailing dot or IP literal")
	}
	kem := hpke.DHKEM(ecdh.X25519())
	private, err := kem.GenerateKey()
	if err != nil {
		return nil, tls.EncryptedClientHelloKey{}, err
	}
	privateBytes, err := private.Bytes()
	if err != nil {
		return nil, tls.EncryptedClientHelloKey{}, err
	}
	var id [1]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, tls.EncryptedClientHelloKey{}, err
	}
	publicBytes := private.PublicKey().Bytes()
	contents := binary.BigEndian.AppendUint16(id[:], kem.ID())
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(publicBytes)))
	contents = append(contents, publicBytes...)
	contents = binary.BigEndian.AppendUint16(contents, 4) // One HPKE symmetric suite.
	contents = binary.BigEndian.AppendUint16(contents, hpke.HKDFSHA256().ID())
	contents = binary.BigEndian.AppendUint16(contents, hpke.AES128GCM().ID())
	contents = append(contents, 255, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = binary.BigEndian.AppendUint16(contents, 0) // No ECHConfig extensions.
	config := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	config = binary.BigEndian.AppendUint16(config, uint16(len(contents)))
	config = append(config, contents...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	list = append(list, config...)
	return list, tls.EncryptedClientHelloKey{Config: config, PrivateKey: privateBytes, SendAsRetry: true}, nil
}

func webALPN(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, errors.New("web TLS requires explicit HTTP ALPN protocols")
	}
	out := make([]string, 0, len(in))
	for _, proto := range in {
		if proto != "h2" && proto != "h3" && proto != "http/1.1" {
			return nil, fmt.Errorf("unsupported web TLS ALPN %q", proto)
		}
		if slices.Contains(out, proto) {
			return nil, fmt.Errorf("duplicate web TLS ALPN %q", proto)
		}
		out = append(out, proto)
	}
	return out, nil
}

func verifyWebNegotiation(state tls.ConnectionState, protos []string, requireECH, allowNoALPN bool) error {
	if state.Version != tls.VersionTLS13 {
		return errors.New("web TLS requires TLS 1.3")
	}
	if !slices.Contains(protos, state.NegotiatedProtocol) && !(allowNoALPN && state.NegotiatedProtocol == "") {
		return errors.New("web TLS HTTP ALPN was not negotiated")
	}
	if requireECH && !state.ECHAccepted {
		return errors.New("web TLS requires accepted ECH")
	}
	return nil
}

func cloneWebByteSlices(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = bytes.Clone(in[i])
	}
	return out
}

// validateWebECHList checks framing without selecting, rewriting or filtering
// configs. crypto/tls handles unsupported versions/suites and fails the
// handshake if none are usable. In particular, an unknown config cannot turn
// a configured ECH connection into a successful plaintext-SNI connection.
func validateWebECHList(list []byte) error {
	if len(list) < 6 || len(list)-2 > 65535 || int(binary.BigEndian.Uint16(list)) != len(list)-2 {
		return errors.New("invalid or empty web TLS ECHConfigList")
	}
	for rest := list[2:]; len(rest) > 0; {
		if len(rest) < 4 {
			return errors.New("truncated web TLS ECHConfig")
		}
		n := 4 + int(binary.BigEndian.Uint16(rest[2:4]))
		if n > len(rest) {
			return errors.New("truncated web TLS ECHConfig contents")
		}
		rest = rest[n:]
	}
	return nil
}

// readWebECHVector consumes one TLS length-prefixed vector. It returns views
// only while validating immutable caller input; stored configs are cloned.
func readWebECHVector(rest *[]byte, width int) ([]byte, bool) {
	if len(*rest) < width {
		return nil, false
	}
	n := int((*rest)[0])
	if width == 2 {
		n = int(binary.BigEndian.Uint16(*rest))
	}
	if n > len(*rest)-width {
		return nil, false
	}
	data := (*rest)[width : width+n]
	*rest = (*rest)[width+n:]
	return data, true
}

func validateWebECHKey(key tls.EncryptedClientHelloKey) error {
	config := key.Config
	if len(config) < 7 || len(config)-4 > 65535 || binary.BigEndian.Uint16(config) != 0xfe0d ||
		int(binary.BigEndian.Uint16(config[2:4])) != len(config)-4 {
		return errors.New("expected one complete RFC 9849 ECHConfig")
	}
	kem, err := hpke.NewKEM(binary.BigEndian.Uint16(config[5:7]))
	if err != nil {
		return fmt.Errorf("unsupported ECH KEM: %w", err)
	}
	rest := config[7:]
	public, ok := readWebECHVector(&rest, 2)
	if !ok || len(public) == 0 {
		return errors.New("invalid ECH public key vector")
	}
	if _, err := kem.NewPublicKey(public); err != nil {
		return fmt.Errorf("invalid ECH public key: %w", err)
	}
	private, err := kem.NewPrivateKey(key.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid ECH private key: %w", err)
	}
	if !bytes.Equal(private.PublicKey().Bytes(), public) {
		return errors.New("ECH public and private keys do not match")
	}
	suites, ok := readWebECHVector(&rest, 2)
	if !ok || len(suites) == 0 || len(suites)%4 != 0 {
		return errors.New("invalid ECH cipher suite vector")
	}
	usable := false
	for len(suites) > 0 {
		_, kdfErr := hpke.NewKDF(binary.BigEndian.Uint16(suites))
		aeadID := binary.BigEndian.Uint16(suites[2:4])
		_, aeadErr := hpke.NewAEAD(aeadID)
		usable = usable || (kdfErr == nil && aeadErr == nil && aeadID != 0xffff)
		suites = suites[4:]
	}
	if !usable {
		return errors.New("ECH config contains no usable cipher suite")
	}
	if len(rest) == 0 {
		return errors.New("missing ECH maximum_name_length")
	}
	rest = rest[1:]
	publicName, ok := readWebECHVector(&rest, 1)
	if !ok || !webECHDNSName(string(publicName)) {
		return errors.New("invalid ECH public DNS name")
	}
	extensions, ok := readWebECHVector(&rest, 2)
	if !ok || len(rest) != 0 {
		return errors.New("invalid ECH extensions vector")
	}
	for len(extensions) > 0 {
		if len(extensions) < 2 {
			return errors.New("truncated ECH extension type")
		}
		typeID := binary.BigEndian.Uint16(extensions)
		extensions = extensions[2:]
		if _, ok := readWebECHVector(&extensions, 2); !ok {
			return errors.New("truncated ECH extension data")
		}
		if typeID&0x8000 != 0 {
			return errors.New("unsupported mandatory ECH extension")
		}
	}
	return nil
}

func webECHDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return false
			}
		}
	}
	return true
}
