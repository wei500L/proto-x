// securitycheck exercises a small set of authentication and admission boundaries
// against an isolated, loopback-only PROTO-X server. It is not a DoS benchmark.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
	"proto-x/internal/app"
	"proto-x/internal/carrier"
	"proto-x/internal/wire"
)

type event struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

type result struct {
	Kind           string            `json:"kind"`
	TimeUTC        string            `json:"time_utc"`
	Network        string            `json:"network"`
	ServerMode     string            `json:"server_mode"`
	Platform       string            `json:"check_platform"`
	GoVersion      string            `json:"check_go_version"`
	BinarySHA256   string            `json:"server_binary_sha256,omitempty"`
	SourceSHA256   map[string]string `json:"observed_source_sha256,omitempty"`
	SourceNote     string            `json:"source_note"`
	WireVersion    int               `json:"wire_version"`
	TimeoutMS      int64             `json:"probe_timeout_ms"`
	BusyTimeoutMS  int64             `json:"busy_timeout_ms"`
	PreauthSlots   int               `json:"expected_preauth_slots"`
	Tests          []event           `json:"tests"`
	ExecutionError string            `json:"execution_error,omitempty"`
}

type options struct {
	binary, privateDir, out, sourceRoot string
	timeout, busyTimeout                time.Duration
	slots                               int
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	var o options
	flag.StringVar(&o.binary, "binary", "", "optional protox server binary; empty runs current source in-process")
	flag.StringVar(&o.privateDir, "private-dir", ".local/securitycheck", "owner-only directory for generated private configs and server logs")
	flag.StringVar(&o.out, "out", "", "sanitized JSON result path; default results/security-<UTC>-<nanoseconds>/checks.json")
	flag.StringVar(&o.sourceRoot, "source-root", ".", "source tree to hash; empty omits source hashes")
	flag.DurationVar(&o.timeout, "timeout", 2*time.Second, "per-handshake timeout")
	flag.DurationVar(&o.busyTimeout, "busy-timeout", 500*time.Millisecond, "maximum wait for rejection after filling pre-auth slots")
	flag.IntVar(&o.slots, "preauth-slots", 8, "expected pre-authentication slot limit (1..32)")
	flag.Parse()
	if o.timeout <= 0 || o.busyTimeout <= 0 || o.slots < 1 || o.slots > 32 {
		fmt.Fprintln(os.Stderr, "invalid check limits")
		os.Exit(2)
	}
	now := time.Now().UTC()
	if o.out == "" {
		o.out = filepath.Join("results", "security-"+now.Format("20060102T150405Z")+"-"+strconv.FormatInt(now.UnixNano()%1e9, 10), "checks.json")
	}
	r := result{Kind: "local-security-boundary-checks", TimeUTC: now.Format(time.RFC3339),
		Network: "loopback only", ServerMode: "in-process source", WireVersion: wire.Version,
		Platform: runtime.GOOS + "/" + runtime.GOARCH, GoVersion: runtime.Version(),
		TimeoutMS: o.timeout.Milliseconds(), BusyTimeoutMS: o.busyTimeout.Milliseconds(),
		PreauthSlots: o.slots,
		SourceNote:   "Source hashes describe files observed at check startup; they are not a reproducible-build attestation."}
	if o.binary != "" {
		r.ServerMode = "external binary"
		r.SourceNote += " In external-binary mode, the binary hash identifies the tested server; source hashes describe the local test/client source and do not prove binary provenance."
	}
	if err := run(o, &r); err != nil {
		r.ExecutionError = err.Error()
		if abs, e := filepath.Abs(o.privateDir); e == nil {
			r.ExecutionError = strings.ReplaceAll(r.ExecutionError, abs, "<private-dir>")
		}
		r.ExecutionError = strings.ReplaceAll(r.ExecutionError, o.privateDir, "<private-dir>")
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err == nil {
		err = os.MkdirAll(filepath.Dir(o.out), 0755)
	}
	if err == nil {
		err = os.WriteFile(o.out, append(b, '\n'), 0644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot save result:", err)
		os.Exit(1)
	}
	pass := 0
	for _, e := range r.Tests {
		if e.Pass {
			pass++
		}
		fmt.Printf("%s: %v\n", e.Name, e.Pass)
	}
	fmt.Printf("%d/%d checks passed; results: %s\n", pass, len(r.Tests), o.out)
	if r.ExecutionError != "" {
		fmt.Fprintln(os.Stderr, "check execution failed:", r.ExecutionError)
	}
	if r.ExecutionError != "" || pass != len(r.Tests) || len(r.Tests) != 10 {
		os.Exit(1)
	}
}

func run(o options, r *result) error {
	if o.sourceRoot != "" {
		r.SourceSHA256 = make(map[string]string)
		for _, path := range []string{"go.mod", "go.sum", "tools/securitycheck/main.go", "cmd/protox/main.go", "internal/carrier/carrier.go", "internal/app/server.go", "internal/app/client.go", "internal/app/config.go", "internal/session/session.go", "internal/scheduler/budget.go", "internal/wire/frame.go"} {
			sum, err := hashFile(filepath.Join(o.sourceRoot, path))
			if err != nil {
				return fmt.Errorf("hash source %s: %w", path, err)
			}
			r.SourceSHA256[path] = sum
		}
	}
	privateBase, err := filepath.Abs(o.privateDir)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(privateBase, 0700); err != nil {
		return err
	}
	st, err := os.Stat(privateBase)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0077 != 0 {
		return errors.New("private-dir must have owner-only permissions (0700)")
	}
	dir, err := os.MkdirTemp(privateBase, "run-")
	if err != nil {
		return err
	}
	tcp, tcpPort, err := freeAddress("tcp")
	if err != nil {
		return err
	}
	udp, udpPort, err := freeAddress("udp")
	if err != nil {
		return err
	}
	if err = app.Init(dir, "127.0.0.1", tcpPort, udpPort); err != nil {
		return err
	}
	cfg, err := app.Load(filepath.Join(dir, "server.json"))
	if err != nil {
		return err
	}
	client, err := app.Load(filepath.Join(dir, "client.json"))
	if err != nil {
		return err
	}
	cfg.TLSListen, cfg.QUICListen = tcp, udp
	// Only isolated, generated credentials are used. Existing deployments are never contacted.
	configBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	configPath := filepath.Join(dir, "server-check.json")
	if err = os.WriteFile(configPath, configBytes, 0600); err != nil {
		return err
	}
	token, err := app.Token(cfg.TokenFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	var command *exec.Cmd
	if o.binary == "" {
		go func() { serverDone <- app.RunServer(ctx, cfg) }()
	} else {
		binaryPath, err := filepath.Abs(o.binary)
		if err != nil {
			return err
		}
		r.BinarySHA256, err = hashFile(binaryPath)
		if err != nil {
			return err
		}
		logFile, err := os.OpenFile(filepath.Join(dir, "server.log"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer logFile.Close()
		command = exec.Command(binaryPath, "server", "-config", configPath)
		command.Stdout, command.Stderr = logFile, logFile
		if err = command.Start(); err != nil {
			return err
		}
		go func() { serverDone <- command.Wait() }()
	}
	defer func() {
		cancel()
		if command != nil {
			_ = command.Process.Signal(os.Interrupt)
		}
		select {
		case <-serverDone:
		case <-time.After(4 * time.Second):
			if command != nil {
				_ = command.Process.Kill()
				<-serverDone
			}
		}
	}()
	deadline := time.Now().Add(o.timeout)
	for {
		c, e := net.DialTimeout("tcp", tcp, 50*time.Millisecond)
		if e == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			return errors.New("isolated server listener did not start; inspect private server log")
		}
		time.Sleep(10 * time.Millisecond)
	}
	goodTLS, err := carrier.ClientTLS(client.Pin, "proto-x.local")
	if err != nil {
		return err
	}
	badPin := strings.Repeat("0", 64)
	if badPin == client.Pin {
		badPin = strings.Repeat("f", 64)
	}
	wrongTLS, err := carrier.ClientTLS(badPin, "proto-x.local")
	if err != nil {
		return err
	}
	dctx, dcancel := context.WithTimeout(ctx, o.timeout)
	l, err := carrier.Dial(dctx, "tls", tcp, wrongTLS)
	dcancel()
	if l != nil {
		_ = l.Close()
	}
	r.Tests = append(r.Tests, event{"wrong_certificate_pin_rejected", err != nil && strings.Contains(err.Error(), "certificate pin mismatch"), "TLS handshake failed specifically at certificate pin verification"})
	hello := func(secret, id string, resume bool, version, window int) (wire.Frame, error) {
		dctx, dcancel := context.WithTimeout(ctx, o.timeout)
		defer dcancel()
		l, err := carrier.Dial(dctx, "tls", tcp, goodTLS)
		if err != nil {
			return wire.Frame{}, err
		}
		defer l.Close()
		l.SetHandshakeDeadline(time.Now().Add(o.timeout))
		b, _ := json.Marshal(map[string]any{"version": version, "session": id, "token": secret, "resume": resume, "window": window})
		if err = l.HandshakeWrite(wire.Frame{Kind: wire.Hello, Payload: b}); err != nil {
			return wire.Frame{}, err
		}
		return l.HandshakeRead()
	}
	testID, err := app.RandomID()
	if err != nil {
		return err
	}
	unknownID, err := app.RandomID()
	if err != nil {
		return err
	}
	badToken := strings.Repeat("0", 64)
	if badToken == token {
		badToken = strings.Repeat("f", 64)
	}
	_, err = hello(badToken, testID, false, wire.Version, cfg.Window)
	r.Tests = append(r.Tests, event{"wrong_token_rejected", remoteClosed(err), "valid pinned TLS plus wrong bearer token must be closed, not time out"})
	_, err = hello(token, testID, false, wire.Version+1, cfg.Window)
	r.Tests = append(r.Tests, event{"wrong_protocol_version_rejected", remoteClosed(err), "unsupported version must be closed, not time out"})
	_, err = hello(token, testID, false, wire.Version, cfg.Window*2)
	r.Tests = append(r.Tests, event{"incompatible_flow_window_rejected", remoteClosed(err), "mismatched flow window must be closed, not time out"})
	_, err = hello(token, "not-a-session-id", false, wire.Version, cfg.Window)
	r.Tests = append(r.Tests, event{"malformed_session_id_rejected", remoteClosed(err), "malformed session ID must be closed, not time out"})
	f, err := hello(token, unknownID, true, wire.Version, cfg.Window)
	w := parseWelcome(f, err)
	r.Tests = append(r.Tests, event{"unknown_resume_explicitly_lost", w != nil && w["ok"] == false && w["error"] == "session_lost", "resumption of absent state is explicitly refused"})
	f, err = hello(token, testID, false, wire.Version, cfg.Window)
	w = parseWelcome(f, err)
	r.Tests = append(r.Tests, event{"valid_new_session_accepted", w != nil && w["ok"] == true && w["resumed"] == false, "first authenticated hello creates a new session"})
	f, err = hello(token, testID, true, wire.Version, cfg.Window)
	w = parseWelcome(f, err)
	r.Tests = append(r.Tests, event{"known_session_resume_accepted", w != nil && w["ok"] == true && w["resumed"] == true, "same live server recognizes the detached session; no target socket was created by this check"})
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: o.timeout}, "tcp", tcp, goodTLS)
	if err != nil {
		return err
	}
	_ = c.SetDeadline(time.Now().Add(o.timeout))
	header := make([]byte, wire.HeaderSize)
	header[0] = wire.Hello
	binary.BigEndian.PutUint32(header[28:32], wire.MaxPayload+1)
	_, err = c.Write(header)
	if err != nil {
		_ = c.Close()
		return err
	}
	var one [1]byte
	_, err = c.Read(one[:])
	_ = c.Close()
	r.Tests = append(r.Tests, event{"oversized_hello_length_rejected", remoteClosed(err), "oversized declared payload is rejected without waiting for the absent body"})
	// Allow completed TLS handlers to release the shared pre-auth slots.
	time.Sleep(100 * time.Millisecond)
	var idle []*quic.Conn
	defer func() {
		for _, q := range idle {
			_ = q.CloseWithError(0, "check finished")
		}
	}()
	for i := 0; i <= o.slots; i++ {
		dctx, dcancel := context.WithTimeout(ctx, o.timeout)
		q, err := quic.DialAddr(dctx, udp, goodTLS, carrier.QUICConfig())
		dcancel()
		if err != nil {
			return fmt.Errorf("create pre-auth slot probe %d: %w", i+1, err)
		}
		idle = append(idle, q)
	}
	lastClosed := false
	select {
	case <-idle[o.slots].Context().Done():
		lastClosed = true
	case <-time.After(o.busyTimeout):
	}
	firstOpen := true
	for _, q := range idle[:o.slots] {
		select {
		case <-q.Context().Done():
			firstOpen = false
		default:
		}
	}
	r.Tests = append(r.Tests, event{"quic_preauth_slot_boundary", lastClosed && firstOpen, fmt.Sprintf("%d idle QUIC peers retained; peer %d rejected within %s before opening a control stream", o.slots, o.slots+1, o.busyTimeout)})
	return nil
}

func parseWelcome(f wire.Frame, err error) map[string]any {
	if err != nil || f.Kind != wire.Welcome || f.ID != 0 {
		return nil
	}
	var w map[string]any
	if json.Unmarshal(f.Payload, &w) != nil {
		return nil
	}
	return w
}

func remoteClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET)
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func freeAddress(network string) (string, int, error) {
	var address string
	if network == "tcp" {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return "", 0, err
		}
		address = l.Addr().String()
		_ = l.Close()
	} else {
		l, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return "", 0, err
		}
		address = l.LocalAddr().String()
		_ = l.Close()
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	n, err := strconv.Atoi(port)
	return address, n, err
}
