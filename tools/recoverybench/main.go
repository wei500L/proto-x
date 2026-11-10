// Command recoverybench runs real HTTP carriers against an owned loopback server.
// Only the supplied proxy executable is varied. The fixture, relay, clock and
// application workload live in this process. No host network state is changed.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"proto-x/internal/bench"
	"proto-x/internal/carrier"
)

type eventLog struct {
	mu    sync.Mutex
	start time.Time
	f     *os.File
	rows  []map[string]any
	err   error
}

func newLog(path string) (*eventLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	return &eventLog{start: time.Now(), f: f}, err
}
func (l *eventLog) record(event string, fields map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if fields == nil {
		fields = map[string]any{}
	}
	now := time.Now()
	fields["event"], fields["elapsed_ns"], fields["wall_ns"] = event, now.Sub(l.start).Nanoseconds(), now.UnixNano()
	l.rows = append(l.rows, fields)
	if l.err == nil {
		l.err = json.NewEncoder(l.f).Encode(fields)
	}
}
func (l *eventLog) close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.f.Close(); l.err == nil {
		l.err = err
	}
	return l.err
}

type child struct {
	cmd      *exec.Cmd
	done     chan struct{}
	mu       sync.Mutex
	err      error
	attached chan struct{}
	ready    chan struct{}
}

func startChild(ctx context.Context, binary, role, config, private string, logs *eventLog) (*child, error) {
	cmd := exec.CommandContext(ctx, binary, role, "-config", config)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	full, err := os.OpenFile(filepath.Join(private, role+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		full.Close()
		return nil, err
	}
	c := &child{cmd: cmd, done: make(chan struct{}), attached: make(chan struct{}), ready: make(chan struct{})}
	logs.record("process_started", map[string]any{"role": role})
	go func() {
		defer full.Close()
		var attachOnce, readyOnce sync.Once
		scanner := bufio.NewScanner(io.TeeReader(pipe, full))
		for scanner.Scan() {
			var row map[string]any
			if json.Unmarshal(scanner.Bytes(), &row) != nil {
				continue
			}
			msg, _ := row["msg"].(string)
			// Full diagnostic logs remain private. Public event fields deliberately
			// exclude addresses, session identifiers and arbitrary error strings.
			safe := map[string]any{"role": role, "message": msg}
			for k, v := range row {
				switch v.(type) {
				case float64, bool:
					safe[k] = v
				}
				if k == "carrier" || k == "event" || k == "time" || k == "reason" {
					safe["child_"+k] = v
				}
			}
			logs.record("proxy_event", safe)
			if msg == "carrier attached" {
				attachOnce.Do(func() { close(c.attached) })
			}
			if (role == "server" && msg == "HTTP/3 listener ready") || (role == "client" && msg == "SOCKS5 listener ready") {
				readyOnce.Do(func() { close(c.ready) })
			}
		}
		waitErr := cmd.Wait()
		if scanner.Err() != nil && waitErr == nil {
			waitErr = scanner.Err()
		}
		c.mu.Lock()
		c.err = waitErr
		c.mu.Unlock()
		logs.record("process_exited", map[string]any{"role": role, "success": waitErr == nil})
		close(c.done)
	}()
	return c, nil
}
func (c *child) waitReady(ch <-chan struct{}, timeout time.Duration) error {
	select {
	case <-ch:
		return nil
	case <-c.done:
		return errors.New("proxy process exited before readiness; inspect private log")
	case <-time.After(timeout):
		return errors.New("proxy readiness deadline exceeded; inspect private log")
	}
}
func (c *child) stop() {
	select {
	case <-c.done:
		return
	default:
	}
	_ = c.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		_ = c.cmd.Process.Kill()
		<-c.done
	}
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if e := f.Close(); err == nil {
		err = e
	}
	return err
}
func hashFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func freshPort() (string, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	a := l.Addr().String()
	err = l.Close()
	return a, err
}

func credentials(dir string) (map[string]any, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Recovery laboratory CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true,
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: true}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{SerialNumber: new(big.Int).Add(serial, big.NewInt(1)),
		Subject: pkix.Name{CommonName: "recovery.inner.test"}, DNSNames: []string{"recovery.inner.test", "recovery.outer.test"},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	for name, block := range map[string]*pem.Block{
		"ca.pem": {Type: "CERTIFICATE", Bytes: caDER}, "leaf.pem": {Type: "CERTIFICATE", Bytes: leafDER},
		"leaf.key": {Type: "PRIVATE KEY", Bytes: keyDER},
	} {
		if err = os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0600); err != nil {
			return nil, err
		}
	}
	list, echKey, err := carrier.GenerateWebECH("recovery.outer.test")
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(dir, "ech.bin"), list, 0600); err != nil {
		return nil, err
	}
	if err = writeJSON(filepath.Join(dir, "ech-keys.json"), []tls.EncryptedClientHelloKey{echKey}); err != nil {
		return nil, err
	}
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(dir, "token"), []byte(hex.EncodeToString(token)), 0600); err != nil {
		return nil, err
	}
	pin := sha256.Sum256(leafDER)
	return map[string]any{"pin": hex.EncodeToString(pin[:])}, nil
}

type options struct {
	protox, private, out, label, clientPatch, serverPatch, expectedSHA  string
	duration, after, faultFor, udpDelay, tcpDelay, spikeFor, spikeDelay time.Duration
	blackhole, direction                                                string
	heartbeat, dead, padding                                            int
	background                                                          float64
	idle                                                                bool
}

func main() {
	var o options
	var fixture bool
	var fixtureHTTP, fixtureEcho, fixtureCert, fixtureKey, fixtureLog string
	flag.BoolVar(&fixture, "fixture", false, "serve an instrumented owned origin only, until terminated")
	flag.StringVar(&fixtureHTTP, "fixture-http", "127.0.0.1:18443", "fixture HTTP(S) listener")
	flag.StringVar(&fixtureEcho, "fixture-echo", "127.0.0.1:18081", "fixture echo listener")
	flag.StringVar(&fixtureCert, "fixture-cert", "", "fixture TLS certificate")
	flag.StringVar(&fixtureKey, "fixture-key", "", "fixture TLS key")
	flag.StringVar(&fixtureLog, "fixture-log", "", "new JSONL target connection log")
	flag.StringVar(&o.protox, "protox", "", "reviewed executable to freeze and execute")
	flag.StringVar(&o.expectedSHA, "sha256", "", "required expected executable SHA256")
	flag.StringVar(&o.private, "private", "", "new private directory under .local")
	flag.StringVar(&o.out, "out", "", "new result directory under results")
	flag.StringVar(&o.label, "label", "trial", "redacted trial label")
	flag.StringVar(&o.clientPatch, "client-patch", "", "private JSON object with extra client config fields")
	flag.StringVar(&o.serverPatch, "server-patch", "", "private JSON object with extra server config fields")
	flag.DurationVar(&o.duration, "duration", 14*time.Second, "actual workload window")
	flag.DurationVar(&o.after, "fault-after", 5*time.Second, "fault offset from workload start")
	flag.DurationVar(&o.faultFor, "fault-for", 5*time.Second, "UDP blackout duration")
	flag.StringVar(&o.blackhole, "fault", "blackhole", "blackhole, delay, or none")
	flag.StringVar(&o.direction, "direction", "both", "blackhole direction: both, up, down")
	flag.DurationVar(&o.udpDelay, "udp-delay", 0, "one-way UDP datagram delay on both directions")
	flag.DurationVar(&o.tcpDelay, "tcp-delay", 0, "one-way TLS byte-chunk delay; NOT TCP packet emulation")
	flag.DurationVar(&o.spikeFor, "spike-for", 600*time.Millisecond, "temporary delay spike duration")
	flag.DurationVar(&o.spikeDelay, "spike-delay", 500*time.Millisecond, "one-way additional UDP delay while fault=delay")
	flag.IntVar(&o.heartbeat, "heartbeat-ms", 500, "client and server heartbeat interval")
	flag.IntVar(&o.dead, "dead-ms", 2000, "client and server fixed dead interval")
	flag.IntVar(&o.padding, "padding", 127, "legacy maximum per-record padding")
	flag.Float64Var(&o.background, "background-mbps", 2, "source paced download Mbps; zero disables download")
	flag.BoolVar(&o.idle, "idle", false, "no application workload; observe false failovers and path cost")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if fixture {
		if err := serveOrigin(ctx, fixtureLog, fixtureHTTP, fixtureEcho, fixtureCert, fixtureKey); err != nil {
			fmt.Fprintln(os.Stderr, "recoverybench fixture:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(ctx, o); err != nil {
		fmt.Fprintln(os.Stderr, "recoverybench:", err)
		os.Exit(1)
	}
}

func serveOrigin(ctx context.Context, path, httpAddress, echoAddress, cert, key string) error {
	logs, err := newLog(path)
	if err != nil {
		return err
	}
	o, err := newOriginAt(ctx, logs, httpAddress, echoAddress, cert, key)
	if err != nil {
		logs.close()
		return err
	}
	logs.record("fixture_ready", nil)
	<-ctx.Done()
	o.close()
	logs.record("fixture_stopped", nil)
	return logs.close()
}

func run(ctx context.Context, o options) (runErr error) {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if _, err = os.Stat(filepath.Join(root, "AGENTS.md")); err != nil {
		return errors.New("run from repository root")
	}
	if o.protox == "" || o.private == "" || o.out == "" || len(o.expectedSHA) != 64 {
		return errors.New("-protox, -sha256, -private, -out required")
	}
	if o.duration < time.Second || o.after < 0 || o.after+o.faultFor >= o.duration || o.udpDelay < 0 || o.tcpDelay < 0 {
		return errors.New("invalid durations or fault window")
	}
	if o.blackhole != "blackhole" && o.blackhole != "delay" && o.blackhole != "none" {
		return errors.New("invalid fault mode")
	}
	if o.direction != "both" && o.direction != "up" && o.direction != "down" {
		return errors.New("invalid fault direction")
	}
	if strings.ContainsAny(o.label, "/\\\n\r") {
		return errors.New("invalid label")
	}
	o.private, _ = filepath.Abs(o.private)
	o.out, _ = filepath.Abs(o.out)
	o.protox, _ = filepath.Abs(o.protox)
	if !strings.HasPrefix(o.private, filepath.Join(root, ".local")+string(os.PathSeparator)) || !strings.HasPrefix(o.out, filepath.Join(root, "results")+string(os.PathSeparator)) {
		return errors.New("private/result paths must be in repository .local/results")
	}
	sum, err := hashFile(o.protox)
	if err != nil {
		return err
	}
	if sum != o.expectedSHA {
		return errors.New("executable hash mismatch")
	}
	if err = os.MkdirAll(filepath.Dir(o.private), 0700); err != nil {
		return err
	}
	if err = os.Mkdir(o.private, 0700); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(o.out), 0755); err != nil {
		return err
	}
	if err = os.Mkdir(o.out, 0755); err != nil {
		return err
	}
	data, err := os.ReadFile(o.protox)
	if err != nil {
		return err
	}
	frozen := filepath.Join(o.private, "protox")
	if err = os.WriteFile(frozen, data, 0700); err != nil {
		return err
	}
	if s, e := hashFile(frozen); e != nil || s != sum {
		return errors.New("frozen executable changed")
	}
	logs, err := newLog(filepath.Join(o.out, "timeline.jsonl"))
	if err != nil {
		return err
	}
	manifest := map[string]any{"label": o.label, "started_utc": time.Now().UTC(), "protox_sha256": sum, "scope": "real loopback H3/H2 with UDP datagram delay/drop and independent TLS byte-chunk relay; not kernel packet emulation", "ech_required": true, "trust": "fresh private CA, hostname and leaf pin; no public trust claim", "planned_duration_ns": o.duration.Nanoseconds(), "fault_after_ns": o.after.Nanoseconds(), "fault_for_ns": o.faultFor.Nanoseconds(), "fault": o.blackhole, "direction": o.direction, "udp_one_way_delay_ns": o.udpDelay.Nanoseconds(), "tcp_one_way_chunk_delay_ns": o.tcpDelay.Nanoseconds(), "heartbeat_ms": o.heartbeat, "dead_ms": o.dead, "padding": o.padding, "background_mbps": o.background, "idle": o.idle}
	if exe, e := os.Executable(); e == nil {
		manifest["harness_sha256"], _ = hashFile(exe)
	}
	manifest["timeline_epoch_wall_ns"] = logs.start.UnixNano()
	manifest["clock_notes"] = "Injection, relay, target and proxy-log receipt use one monotonic clock. Benchmark has a separate monotonic start in the same process: align via StartedUTC only when wall-minus-monotonic offsets remain stable. Proxy internal event durations use their own session clocks; log receipt is an upper bound."
	defer func() {
		manifest["ended_utc"] = time.Now().UTC()
		manifest["completed"] = runErr == nil
		if runErr != nil {
			manifest["error_type"] = fmt.Sprintf("%T", runErr)
		}
		if e := writeJSON(filepath.Join(o.out, "manifest.json"), manifest); runErr == nil {
			runErr = e
		}
		if e := logs.close(); runErr == nil {
			runErr = e
		}
	}()
	logs.record("start", nil)
	childCtx, cancelChildren := context.WithCancel(ctx)
	defer cancelChildren()
	identity, err := credentials(o.private)
	if err != nil {
		return err
	}
	cover := filepath.Join(o.private, "cover")
	if err = os.Mkdir(cover, 0700); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(cover, "index.html"), []byte("<!doctype html><title>Laboratory</title><p>Controlled endpoint.</p>"), 0600); err != nil {
		return err
	}
	h2Addr, err := freshPort()
	if err != nil {
		return err
	}
	h3Reserve, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	h3Addr := h3Reserve.LocalAddr().String()
	h3Reserve.Close()
	socksAddr, err := freshPort()
	if err != nil {
		return err
	}
	base := func() map[string]any {
		return map[string]any{"token_file": filepath.Join(o.private, "token"), "rate_mbps": 8, "priority": true, "adaptive": false, "window_bytes": 65536, "max_flows": 32, "max_sessions": 2, "heartbeat_ms": o.heartbeat, "dead_ms": o.dead, "resume_seconds": 90, "dial_timeout_ms": 3000, "web_path": "/api/sync", "web_padding": o.padding}
	}
	server, client := base(), base()
	server["web_listen"], server["http3_listen"] = h2Addr, h3Addr
	server["cert_file"], server["key_file"], server["ech_keys_file"], server["cover_dir"] = filepath.Join(o.private, "leaf.pem"), filepath.Join(o.private, "leaf.key"), filepath.Join(o.private, "ech-keys.json"), cover
	server["allow_private_targets"] = true
	client["socks_listen"], client["rate_mbps"] = socksAddr, 2
	client["ca_file"], client["pin_sha256"], client["ech_config_file"], client["experimental_pin_only"] = filepath.Join(o.private, "ca.pem"), identity["pin"], filepath.Join(o.private, "ech.bin"), false
	for _, entry := range []struct {
		path, role string
		cfg        map[string]any
	}{{o.clientPatch, "client", client}, {o.serverPatch, "server", server}} {
		if entry.path == "" {
			continue
		}
		b, e := os.ReadFile(entry.path)
		if e != nil {
			return e
		}
		var p map[string]any
		if e = json.Unmarshal(b, &p); e != nil {
			return e
		}
		for k, v := range p {
			if k != "recovery_mode" && k != "recovery_no_prepare" && k != "recovery_count_history" && k != "recovery_probe_only" && k != "recovery_trace" && k != "heartbeat_ms" && k != "dead_ms" && k != "dial_timeout_ms" && k != "adaptive" && k != "priority" {
				return fmt.Errorf("unsupported %s patch field %s", entry.role, k)
			}
			entry.cfg[k] = v
		}
		manifest[entry.role+"_patch"] = p
	}
	if err = writeJSON(filepath.Join(o.private, "server.json"), server); err != nil {
		return err
	}
	srv, err := startChild(childCtx, frozen, "server", filepath.Join(o.private, "server.json"), o.private, logs)
	if err != nil {
		return err
	}
	defer srv.stop()
	if err = srv.waitReady(srv.ready, 10*time.Second); err != nil {
		return err
	}
	relayCtx, stopRelays := context.WithCancel(ctx)
	defer stopRelays()
	udp, err := newUDPRelay(relayCtx, h3Addr, o.udpDelay, logs)
	if err != nil {
		return err
	}
	defer udp.close()
	tcp, err := newTCPRelay(relayCtx, h2Addr, o.tcpDelay, logs)
	if err != nil {
		return err
	}
	defer tcp.close()
	client["endpoints"] = []map[string]any{{"network": "h3", "address": udp.address(), "server_name": "recovery.inner.test"}, {"network": "h2", "address": tcp.address(), "server_name": "recovery.inner.test"}}
	if err = writeJSON(filepath.Join(o.private, "client.json"), client); err != nil {
		return err
	}
	for role, path := range map[string]string{"client": filepath.Join(o.private, "client.json"), "server": filepath.Join(o.private, "server.json")} {
		manifest[role+"_private_config_sha256"], _ = hashFile(path)
	}
	cl, err := startChild(childCtx, frozen, "client", filepath.Join(o.private, "client.json"), o.private, logs)
	if err != nil {
		return err
	}
	defer cl.stop()
	if err = cl.waitReady(cl.attached, 12*time.Second); err != nil {
		return err
	}
	origin, err := newOrigin(ctx, logs)
	if err != nil {
		return err
	}
	defer origin.close()
	benchCtx, cancelBench := context.WithCancel(ctx)
	defer cancelBench()
	logs.record("workload_start", nil)
	faultDone := make(chan struct{})
	go func() {
		defer close(faultDone)
		if !waitFor(benchCtx, o.after) {
			return
		}
		logs.record("fault_start", map[string]any{"kind": o.blackhole, "direction": o.direction})
		if o.blackhole == "blackhole" {
			udp.setBlackhole(o.direction, true)
		}
		if o.blackhole == "delay" {
			udp.extraDelay.Store(o.spikeDelay.Nanoseconds())
		}
		faultDuration := o.faultFor
		if o.blackhole == "delay" {
			faultDuration = o.spikeFor
		}
		complete := waitFor(benchCtx, faultDuration)
		udp.setBlackhole(o.direction, false)
		udp.extraDelay.Store(0)
		logs.record("fault_end", map[string]any{"kind": o.blackhole, "full_duration": complete})
	}()
	if o.idle {
		if !waitFor(ctx, o.duration) {
			runErr = ctx.Err()
		}
	} else {
		background := 0
		if o.background > 0 {
			background = 1
		}
		cfg := bench.RunConfig{Proxy: socksAddr, HTTPTarget: "http://" + origin.httpAddress(), EchoTarget: origin.echoAddress(), Duration: o.duration, Timeout: 3 * time.Second, RPS: 5, HTTPMethod: "POST", HTTPBytes: 1024, Concurrency: 32, EchoInterval: 100 * time.Millisecond, SSEInterval: 50 * time.Millisecond, Background: background, BackgroundMbps: o.background, UploadBytes: 256 << 10, Output: filepath.Join(o.out, "bench.jsonl"), Summary: filepath.Join(o.out, "bench.summary.json"), RunID: o.label}
		var summary bench.Summary
		summary, runErr = bench.Run(ctx, cfg)
		if start, e := time.Parse(time.RFC3339Nano, summary.StartedUTC); e == nil {
			manifest["benchmark_epoch_wall_ns"] = start.UnixNano()
			manifest["benchmark_epoch_offset_ns"] = start.UnixNano() - logs.start.UnixNano()
		}
	}
	logs.record("workload_end", nil)
	cancelBench()
	<-faultDone
	cl.stop()
	srv.stop()
	origin.close()
	udp.close()
	tcp.close()
	manifest["udp_counts"] = udp.counts()
	manifest["tcp_counts"] = tcp.counts()
	logs.record("end", nil)
	return runErr
}

func waitFor(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
