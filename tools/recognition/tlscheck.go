package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

// tlscheck records actual TLS connection state independently of the passive
// inspector. It is not native proxy traffic and must be labeled separately.
func tlscheck(c config, output string) error {
	if output == "" || (c.Network != "h2" && c.Network != "h3") {
		return errors.New("tlscheck requires h2/h3 and a new output path")
	}
	t, err := clientTLS(c, c.Network)
	if err != nil {
		return err
	}
	if c.ECHConfigFile != "" {
		t.EncryptedClientHelloConfigList, err = os.ReadFile(c.ECHConfigFile)
		if err != nil {
			return err
		}
		if len(t.EncryptedClientHelloConfigList) == 0 {
			return errors.New("empty ECH configuration is not an enabled-ECH check")
		}
	}
	result := map[string]any{"schema": 1, "label": c.Label, "network": c.Network, "created_utc": time.Now().UTC(),
		"tool": buildIdentity(), "ech_configured": c.ECHConfigFile != "", "target_values_exported": false,
		"observation_method": "active standard TLS client's actual ConnectionState; separate from native client capture",
		"certificate_policy": "normal CA/name verification with optional additional pin; local test CA is not a public identity claim"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.TimeoutMS)*time.Millisecond)
	defer cancel()
	var state tls.ConnectionState
	start := time.Now()
	if c.Network == "h2" {
		conn, e := (&tls.Dialer{Config: t}).DialContext(ctx, "tcp", c.Address)
		err = e
		if err == nil {
			state = conn.(*tls.Conn).ConnectionState()
			_ = conn.Close()
		}
	} else {
		conn, e := quic.DialAddr(ctx, c.Address, t, &quic.Config{})
		err = e
		if err == nil {
			state = conn.ConnectionState().TLS
			_ = conn.CloseWithError(0, "")
		}
	}
	result["elapsed_ms"] = float64(time.Since(start)) / float64(time.Millisecond)
	if err != nil {
		result["status"], result["error"] = "handshake_failed", errorView(err)
	} else {
		result["status"] = "handshake_completed"
		result["ech_accepted"] = state.ECHAccepted
		result["negotiated_alpn"] = state.NegotiatedProtocol
		result["tls_version"] = state.Version
		result["certificate_chain_verified"] = len(state.VerifiedChains) > 0
		result["handshake_complete"] = state.HandshakeComplete
	}
	if err := writeJSON(output, result, false); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"report": output, "status": result["status"]})
}
