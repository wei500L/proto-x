// Command recognition runs controlled HTTP/2 and HTTP/3 observation probes.
// It is research tooling and is not linked into the proxy implementation.
package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"time"
)

type config struct {
	Label         string `json:"label"`
	Network       string `json:"network"`
	Address       string `json:"address"`
	ServerName    string `json:"server_name"`
	CAFile        string `json:"ca_file"`
	PinSHA256     string `json:"pin_sha256,omitempty"`
	ProtocolPath  string `json:"protocol_path"`
	AuthHeader    string `json:"auth_header,omitempty"`
	TimeoutMS     int    `json:"timeout_ms,omitempty"`
	Repeats       int    `json:"repeats,omitempty"`
	LegacyALPN    string `json:"legacy_alpn,omitempty"`
	TCPListen     string `json:"tcp_listen,omitempty"`
	UDPListen     string `json:"udp_listen,omitempty"`
	CertFile      string `json:"cert_file,omitempty"`
	KeyFile       string `json:"key_file,omitempty"`
	SiteRoot      string `json:"site_root,omitempty"`
	ReadyFile     string `json:"ready_file,omitempty"`
	TLSProfile    string `json:"tls_profile,omitempty"`
	ECHConfigFile string `json:"ech_config_file,omitempty"`
}

func loadConfig(path string) (config, error) {
	var c config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("configuration must contain one JSON object")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,48}$`).MatchString(c.Label) {
		return c, errors.New("label must be a redacted ASCII category")
	}
	if c.TimeoutMS == 0 {
		c.TimeoutMS = 2500
	}
	if c.TimeoutMS < 100 || c.TimeoutMS > 30000 {
		return c, errors.New("timeout outside research bound")
	}
	if c.Repeats == 0 {
		c.Repeats = 1
	}
	if c.Repeats < 1 || c.Repeats > 20 {
		return c, errors.New("repeat count outside research bound")
	}
	if c.ProtocolPath == "" {
		c.ProtocolPath = "/api/sync?carrier=recognition&stream=1"
	}
	if c.AuthHeader == "" {
		c.AuthHeader = "Authorization"
	}
	if c.LegacyALPN == "" {
		c.LegacyALPN = "proto-x/1"
	}
	return c, nil
}

func clientTLS(c config, alpn string) (*tls.Config, error) {
	if c.ServerName == "" {
		return nil, errors.New("explicit expected server name is required")
	}
	var roots *x509.CertPool
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("configured CA file contains no certificates")
		}
	}
	t := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: c.ServerName, NextProtos: []string{alpn}}
	if c.PinSHA256 != "" {
		pin, err := hex.DecodeString(c.PinSHA256)
		if err != nil || len(pin) != 32 {
			return nil, errors.New("invalid configured certificate pin")
		}
		t.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			digest := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(pin, digest[:]) != 1 {
				return errors.New("additional certificate pin mismatch")
			}
			return nil
		}
	}
	return t, nil
}

// Error messages can contain target hostnames, URLs and certificate names.
// Public evidence retains types and timeout state, never the raw message.
func errorView(err error) map[string]any {
	if err == nil {
		return nil
	}
	types := []string{}
	for e := err; e != nil && len(types) < 12; e = errors.Unwrap(e) {
		types = append(types, fmt.Sprintf("%T", e))
	}
	var ne net.Error
	return map[string]any{"types": types, "timeout": errors.As(err, &ne) && ne.Timeout(), "message_redacted": true}
}

func buildIdentity() map[string]any {
	result := map[string]any{"go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH}
	if info, ok := debug.ReadBuildInfo(); ok {
		modules := map[string]string{}
		for _, dep := range info.Deps {
			modules[dep.Path] = dep.Version
		}
		result["modules"] = modules
	}
	if executable, err := os.Executable(); err == nil {
		if data, err := os.ReadFile(executable); err == nil {
			sum := sha256.Sum256(data)
			result["binary_sha256"] = hex.EncodeToString(sum[:])
		}
	}
	return result
}

func writeJSON(path string, data any, private bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	mode := os.FileMode(0644)
	if private {
		mode = 0600
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: recognition probe|visitors|tlscheck|ordinary|cert -config PRIVATE_JSON -out OUTPUT")
		os.Exit(2)
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	configFile := flags.String("config", "", "private JSON configuration")
	output := flags.String("out", "", "new output path; cert uses a new private directory")
	flags.Parse(os.Args[2:])
	var err error
	if command == "cert" {
		err = makeCert(*output)
	} else {
		var c config
		c, err = loadConfig(*configFile)
		if err == nil {
			switch command {
			case "probe":
				err = probe(c, *output)
			case "visitors":
				err = visitors(c, *output)
			case "tlscheck":
				err = tlscheck(c, *output)
			case "ordinary":
				err = ordinary(c)
			default:
				err = errors.New("unknown command")
			}
		}
	}
	if err != nil {
		// Full diagnostic is private; the public terminal output is redacted.
		if *configFile != "" {
			_ = writeJSON(*configFile+".error-"+fmt.Sprint(time.Now().UnixNano())+".json", map[string]any{"error": err.Error()}, true)
		}
		_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"status": "tool_error", "error": errorView(err)})
		os.Exit(1)
	}
}
