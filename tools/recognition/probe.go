package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type probeCase struct {
	Name, Method, Path, Auth string
}

func httpClient(c config) (*http.Client, func(), error) {
	t, err := clientTLS(c, c.Network)
	if err != nil {
		return nil, nil, err
	}
	switch c.Network {
	case "h2":
		transport := &http2.Transport{TLSClientConfig: t, DisableCompression: true,
			DialTLSContext: func(ctx context.Context, _, _ string, cfg *tls.Config) (net.Conn, error) {
				return (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", c.Address)
			}}
		return &http.Client{Transport: transport, CheckRedirect: noRedirect}, transport.CloseIdleConnections, nil
	case "h3":
		transport := &http3.Transport{TLSClientConfig: t, DisableCompression: true,
			Dial: func(ctx context.Context, _ string, cfg *tls.Config, q *quic.Config) (*quic.Conn, error) {
				return quic.DialAddr(ctx, c.Address, cfg, q)
			}}
		return &http.Client{Transport: transport, CheckRedirect: noRedirect}, func() { _ = transport.Close() }, nil
	default:
		return nil, nil, errors.New("probe network must be h2 or h3")
	}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func headerView(header http.Header) map[string]any {
	safe := map[string]bool{"Content-Type": true, "Content-Length": true, "Allow": true, "Accept-Ranges": true,
		"Cache-Control": true, "Content-Encoding": true, "X-Content-Type-Options": true, "Vary": true,
		"Last-Modified": true}
	out := map[string]any{}
	for key, values := range header {
		key = http.CanonicalHeaderKey(key)
		if key == "Date" {
			continue
		}
		if safe[key] {
			v := append([]string(nil), values...)
			sort.Strings(v)
			out[key] = v
		} else {
			out[key] = map[string]any{"value_count": len(values), "values_redacted": true}
		}
	}
	return out
}

func oneHTTP(c config, item probeCase) map[string]any {
	result := map[string]any{"case": item.Name, "method": item.Method, "path_class": item.Name,
		"authentication_class": "absent", "connection_policy": "fresh transport per case"}
	if item.Auth != "" {
		result["authentication_class"] = "deliberately_invalid"
	}
	client, closeClient, err := httpClient(c)
	if err != nil {
		result["status"], result["error"] = "client_setup_failed", errorView(err)
		return result
	}
	defer closeClient()
	uri, err := url.Parse("https://" + c.ServerName + item.Path)
	if err != nil {
		result["status"], result["error"] = "request_setup_failed", errorView(err)
		return result
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.TimeoutMS)*time.Millisecond)
	defer cancel()
	var body io.Reader
	if item.Method == "POST" || item.Method == "PUT" {
		body = strings.NewReader("ordinary invalid probe body\n")
	}
	req, err := http.NewRequestWithContext(ctx, item.Method, uri.String(), body)
	if err != nil {
		result["status"], result["error"] = "request_setup_failed", errorView(err)
		return result
	}
	if item.Auth != "" {
		req.Header.Set(c.AuthHeader, item.Auth)
	}
	start := time.Now()
	response, err := client.Do(req)
	result["headers_elapsed_ms"] = float64(time.Since(start)) / float64(time.Millisecond)
	if err != nil {
		result["status"], result["error"] = "request_failed", errorView(err)
		return result
	}
	defer response.Body.Close()
	result["http_status"] = response.StatusCode
	result["http_protocol"] = response.Proto
	result["headers"] = headerView(response.Header)
	result["content_length"] = response.ContentLength
	if response.TLS != nil {
		result["negotiated_alpn"] = response.TLS.NegotiatedProtocol
		result["tls_version"] = response.TLS.Version
		result["alpn_observation_method"] = "active client TLS connection state"
		result["certificate_chain_verified"] = len(response.TLS.VerifiedChains) > 0
	}
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
	result["complete_elapsed_ms"] = float64(time.Since(start)) / float64(time.Millisecond)
	result["body_bytes_observed"] = len(payload)
	result["body_truncated_at_bound"] = len(payload) > 65536
	sum := sha256.Sum256(payload)
	result["body_sha256"] = hex.EncodeToString(sum[:])
	result["status"] = "response_observed"
	if readErr != nil {
		result["status"], result["body_error"] = "response_body_failed", errorView(readErr)
	}
	return result
}

// The original record format starts with a 32-byte HELLO header. The empty
// body is deliberately unauthenticated; it is not a valid session request.
func oldHelloPrefix() []byte {
	value := make([]byte, 32)
	value[0] = 1
	return value
}

func oneLegacy(c config, oldALPN bool) map[string]any {
	name, alpn := "old_bare_record_over_standard_alpn", c.Network
	if oldALPN {
		name, alpn = "old_custom_alpn_offer", c.LegacyALPN
	}
	result := map[string]any{"case": name, "offered_alpn": []string{alpn},
		"payload_class": "empty_unauthenticated_legacy_HELLO_record", "legacy_record_bytes": 32}
	t, err := clientTLS(c, alpn)
	if err != nil {
		result["status"], result["error"] = "client_setup_failed", errorView(err)
		return result
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.TimeoutMS)*time.Millisecond)
	defer cancel()
	start := time.Now()
	var stream io.ReadWriteCloser
	var negotiated string
	if c.Network == "h2" {
		conn, e := (&tls.Dialer{Config: t}).DialContext(ctx, "tcp", c.Address)
		err = e
		if err == nil {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Duration(c.TimeoutMS) * time.Millisecond))
			negotiated = conn.(*tls.Conn).ConnectionState().NegotiatedProtocol
			stream = conn
		}
	} else {
		conn, e := quic.DialAddr(ctx, c.Address, t, &quic.Config{HandshakeIdleTimeout: time.Duration(c.TimeoutMS) * time.Millisecond})
		err = e
		if err == nil {
			defer conn.CloseWithError(0, "probe complete")
			negotiated = conn.ConnectionState().TLS.NegotiatedProtocol
			var qstream *quic.Stream
			qstream, err = conn.OpenStreamSync(ctx)
			if err == nil {
				_ = qstream.SetDeadline(time.Now().Add(time.Duration(c.TimeoutMS) * time.Millisecond))
				stream = qstream
			}
		}
	}
	result["handshake_elapsed_ms"] = float64(time.Since(start)) / float64(time.Millisecond)
	if err != nil {
		result["status"], result["error"] = "handshake_or_stream_rejected", errorView(err)
		return result
	}
	result["negotiated_alpn"] = negotiated
	_, err = io.Copy(stream, bytes.NewReader(oldHelloPrefix()))
	if err != nil {
		result["status"], result["error"] = "legacy_write_rejected", errorView(err)
		return result
	}
	payload, readErr := io.ReadAll(io.LimitReader(stream, 4097))
	sum := sha256.Sum256(payload)
	result["status"] = "legacy_response_observed"
	result["response_bytes"] = len(payload)
	result["response_sha256"] = hex.EncodeToString(sum[:])
	result["response_truncated_at_bound"] = len(payload) > 4096
	result["read_error"] = errorView(readErr)
	result["complete_elapsed_ms"] = float64(time.Since(start)) / float64(time.Millisecond)
	return result
}

func probe(c config, output string) error {
	if output == "" {
		return errors.New("new report output path is required")
	}
	if _, err := os.Stat(output); err == nil {
		return errors.New("refusing to replace an existing report")
	}
	if c.Network != "h2" && c.Network != "h3" {
		return errors.New("probe network must be h2 or h3")
	}
	if _, _, err := net.SplitHostPort(c.Address); err != nil {
		return errors.New("configured target must include a port")
	}
	if !strings.HasPrefix(c.ProtocolPath, "/") || strings.HasPrefix(c.ProtocolPath, "//") {
		return errors.New("protocol path must be an origin-form request target")
	}
	// Match the actual envelope length/version/current timestamp and a fresh
	// nonce. The zero MAC is deliberately invalid; no real token is required.
	badAuth, err := invalidAuth()
	if err != nil {
		return err
	}
	cases := []probeCase{
		{"root_get", "GET", "/", ""}, {"root_head", "HEAD", "/", ""},
		{"protocol_get", "GET", c.ProtocolPath, ""}, {"protocol_head", "HEAD", c.ProtocolPath, ""},
		{"protocol_post_no_auth", "POST", c.ProtocolPath, ""},
		{"protocol_post_wrong_auth", "POST", c.ProtocolPath, badAuth},
		{"protocol_post_malformed_auth", "POST", c.ProtocolPath, "Bearer invalid"},
		{"protocol_wrong_method_put", "PUT", c.ProtocolPath, ""},
		{"unknown_get", "GET", "/__recognition_unknown_7c88a8", ""},
		{"unknown_post", "POST", "/__recognition_unknown_7c88a8", ""},
		{"root_options", "OPTIONS", "/", ""},
	}
	observations := []map[string]any{}
	for repeat := 0; repeat < c.Repeats; repeat++ {
		for _, item := range cases {
			row := oneHTTP(c, item)
			row["repeat"] = repeat
			observations = append(observations, row)
		}
		for _, legacy := range []bool{true, false} {
			row := oneLegacy(c, legacy)
			row["repeat"] = repeat
			observations = append(observations, row)
		}
	}
	report := map[string]any{
		"schema": 1, "label": c.Label, "network": c.Network, "created_utc": time.Now().UTC(),
		"tool": buildIdentity(), "target_host_class": "configured_target_redacted", "target_values_exported": false,
		"observations": observations, "attempted_cases": len(observations), "timeout_ms": c.TimeoutMS,
		"certificate_policy":   "ordinary CA/name verification with optional additional pin; no insecure TLS",
		"header_normalization": "Date omitted; selected generic headers retained; all other header values redacted",
		"limitations": []string{
			"These active probes test declared requests; they do not establish resistance to arbitrary probes or classifiers.",
			"Wrong authentication has the actual 57-byte envelope, version, current timestamp and random nonce, with a deliberately invalid zero MAC. It does not test a valid MAC, expiry or authenticated replay.",
			"Positive authenticated native-client interoperability must be checked separately through the same endpoint.",
			"Comparisons require the same runtime/HTTP stack, TLS configuration, content directory and declared request cases.",
			"Connection and response timing are local samples, not a statistical classifier or Russian reachability measurement.",
			"The legacy ALPN case intentionally offers the old fingerprint; do not label its ClientHello as native new-client traffic.",
		},
	}
	if err := writeJSON(output, report, false); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"report": output, "attempted_cases": len(observations)})
}

func invalidAuth() (string, error) {
	payload := make([]byte, 1+8+16+32)
	payload[0] = 1
	binary.BigEndian.PutUint64(payload[1:9], uint64(time.Now().Unix()))
	if _, err := rand.Read(payload[9:25]); err != nil {
		return "", err
	}
	return "Bearer " + base64.RawURLEncoding.EncodeToString(payload), nil
}
