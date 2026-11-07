package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// oneVisitor uses stock crypto/tls and net/http's HTTP/1.1 serializer/parser.
// A nil NextProtos slice really omits ALPN; no HTTP transport can inject it.
func oneVisitor(c config, item probeCase, offerALPN bool) map[string]any {
	profile := "https_no_alpn"
	if offerALPN {
		profile = "http11_explicit_alpn"
	}
	result := map[string]any{"case": profile + "_" + item.Name, "method": item.Method,
		"visitor_profile": profile, "authentication_class": "absent", "connection_policy": "fresh TLS connection per case"}
	if item.Auth != "" {
		result["authentication_class"] = "deliberately_invalid"
	}
	t, err := clientTLS(c, "http/1.1")
	if err != nil {
		result["status"], result["error"] = "client_setup_failed", errorView(err)
		return result
	}
	if !offerALPN {
		t.NextProtos = nil
	}
	result["offered_alpn"] = append([]string{}, t.NextProtos...)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.TimeoutMS)*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := (&tls.Dialer{Config: t}).DialContext(ctx, "tcp", c.Address)
	result["handshake_elapsed_ms"] = float64(time.Since(start)) / float64(time.Millisecond)
	if err != nil {
		result["status"], result["error"] = "handshake_rejected", errorView(err)
		return result
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	state := conn.(*tls.Conn).ConnectionState()
	result["negotiated_alpn"] = state.NegotiatedProtocol
	result["tls_version"] = state.Version
	result["certificate_chain_verified"] = len(state.VerifiedChains) > 0
	var body io.Reader
	if item.Method == "POST" {
		body = strings.NewReader("ordinary invalid probe body\n")
	}
	req, err := http.NewRequestWithContext(ctx, item.Method, "https://"+c.ServerName+item.Path, body)
	if err != nil {
		result["status"], result["error"] = "request_setup_failed", errorView(err)
		return result
	}
	req.Close = true
	if item.Auth != "" {
		req.Header.Set(c.AuthHeader, item.Auth)
	}
	if err := req.Write(conn); err != nil {
		result["status"], result["error"] = "request_write_failed", errorView(err)
		return result
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), req)
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

func visitors(c config, output string) error {
	if output == "" {
		return errors.New("new visitor report output path is required")
	}
	if _, err := os.Stat(output); err == nil {
		return errors.New("refusing to replace an existing visitor report")
	}
	bad, err := invalidAuth()
	if err != nil {
		return err
	}
	cases := []probeCase{{"root_get", "GET", "/", ""}, {"root_head", "HEAD", "/", ""},
		{"protocol_post_no_auth", "POST", c.ProtocolPath, ""}, {"protocol_post_wrong_auth", "POST", c.ProtocolPath, bad}}
	observations := []map[string]any{}
	for repeat := 0; repeat < c.Repeats; repeat++ {
		for _, offer := range []bool{false, true} {
			for _, item := range cases {
				row := oneVisitor(c, item, offer)
				row["repeat"] = repeat
				observations = append(observations, row)
			}
		}
	}
	report := map[string]any{"schema": 1, "label": c.Label, "network": "https_visitor_tcp", "created_utc": time.Now().UTC(),
		"tool": buildIdentity(), "target_host_class": "configured_target_redacted", "target_values_exported": false,
		"observations": observations, "attempted_cases": len(observations), "timeout_ms": c.TimeoutMS,
		"certificate_policy": "ordinary CA/name verification with optional additional pin; no insecure TLS",
		"client_stack":       "stock crypto/tls and net/http HTTP/1.1 request serializer/parser; no candidate client TLS helper",
		"limitations": []string{"These are declared HTTP/1.1 visitors, not browser traffic or a broad cover corpus.",
			"The no-ALPN offer must also be checked in the separate observed ClientHello bytes.",
			"Successful ordinary visitors do not prove authenticated proxy success, ECH acceptance or resistance to classifiers."}}
	if err := writeJSON(output, report, false); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"report": output, "attempted_cases": len(observations)})
}
