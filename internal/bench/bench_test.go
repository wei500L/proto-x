package bench

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSOCKSAddressEncoding(t *testing.T) {
	for _, tt := range []struct {
		address string
		want    []byte
	}{
		{"192.0.2.9:443", []byte{5, 1, 0, 1, 192, 0, 2, 9, 1, 187}},
		{"fixture.example:80", append(append([]byte{5, 1, 0, 3, 15}, []byte("fixture.example")...), 0, 80)},
		{"[2001:db8::1]:8080", []byte{5, 1, 0, 4, 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 31, 144}},
	} {
		t.Run(tt.address, func(t *testing.T) {
			got, err := socksRequest(tt.address)
			if err != nil || !bytes.Equal(got, tt.want) {
				t.Fatalf("got %v (%v), want %v", got, err, tt.want)
			}
		})
	}
	for _, bad := range []string{"host", "host:0", "host:65536", ":80", strings.Repeat("a", 256) + ":80"} {
		if _, err := socksRequest(bad); err == nil {
			t.Errorf("accepted invalid address %q", bad)
		}
	}
}

func TestSOCKSHandshakeRejectsWrongAuthentication(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.CopyN(io.Discard, c, 3)
		c.Write([]byte{5, 2})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, err := DialSOCKS5(ctx, l.Addr().String(), "fixture.example:80", time.Second); err == nil {
		c.Close()
		t.Fatal("accepted an authentication method the client did not offer")
	}
}

func TestPayloadHasStableWirePatternAndRejectsCorruption(t *testing.T) {
	b := make([]byte, 8)
	fillPayload(b, 0)
	if !bytes.Equal(b, []byte{17, 48, 79, 110, 141, 172, 203, 234}) {
		t.Fatalf("unexpected first bytes %v", b)
	}
	fillPayload(b[:4], 249)
	if !bytes.Equal(b[:4], []byte{206, 237, 17, 48}) || !validPayload(b[:4], 249) {
		t.Fatalf("period boundary is wrong: %v", b[:4])
	}
	b[2] ^= 1
	if validPayload(b[:4], 249) {
		t.Fatal("corruption was accepted")
	}
	r := &payloadReader{left: 3, offset: 251}
	n, err := r.Read(b)
	if err != nil || n != 3 || !bytes.Equal(b[:n], []byte{17, 48, 79}) {
		t.Fatalf("bounded reader: %v %d %v", b, n, err)
	}
	if n, err := r.Read(b); n != 0 || err != io.EOF {
		t.Fatalf("reader did not stop: n=%d err=%v", n, err)
	}
}

func TestSummaryRetainsFailureTimeoutAndCensoringDenominators(t *testing.T) {
	cfg := RunConfig{RunID: "denominators", Output: filepath.Join(t.TempDir(), "raw.jsonl")}
	r, err := newRecorder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"success", "failure", "timeout", "censored", "rejected"} {
		r.record(Event{Kind: "http", Status: status, LatencyMS: 123})
	}
	r.record(Event{Kind: "sse_end", Status: "censored", TerminalGapMS: 1300})
	s, err := r.finish()
	if err != nil {
		t.Fatal(err)
	}
	o := s.Operations["http"]
	if o.Total != 5 || o.Success != 1 || o.Failure != 1 || o.Timeout != 1 || o.Censored != 1 || o.Rejected != 1 || o.SuccessRateTotal != .2 || o.LatencyMS.N != 1 {
		t.Fatalf("denominators were lost: %+v", o)
	}
	if s.SSE.TerminalOver1000MS != 1 || s.SSE.UnexpectedEnds != 0 {
		t.Fatalf("terminal stall disappeared or was mislabeled: %+v", s.SSE)
	}
	b, _ := os.ReadFile(cfg.Output)
	if bytes.Count(b, []byte("\n")) != 6 {
		t.Fatal("raw events were lost")
	}
	if _, err := newRecorder(cfg); err == nil {
		t.Fatal("raw observations were overwritten")
	}
	d := distribution([]float64{100, 1, 10, 2})
	if d.N != 4 || d.P50 != 2 || d.P95 != 100 || d.P99 != 100 || d.Mean != 28.25 {
		t.Fatalf("incorrect nearest-rank distribution: %+v", d)
	}
}

func TestFixturesValidateUploadAndStreamSequence(t *testing.T) {
	srv := httptest.NewServer(FixtureHandler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/upload", "application/octet-stream", bytes.NewReader([]byte{17, 48, 79}))
	if err != nil {
		t.Fatal(err)
	}
	var ack struct {
		Bytes int64 `json:"bytes"`
		Valid bool  `json:"valid"`
	}
	err = json.NewDecoder(resp.Body).Decode(&ack)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || ack.Bytes != 3 || !ack.Valid {
		t.Fatalf("valid upload rejected: %d %+v %v", resp.StatusCode, ack, err)
	}
	resp, err = http.Post(srv.URL+"/upload", "application/octet-stream", bytes.NewReader([]byte{17, 48, 80}))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatal("fixture accepted corrupted upload")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/sse?interval=10ms", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	var firstScheduled int64
	seen := 0
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var token sourceToken
		if err := json.Unmarshal([]byte(line[6:]), &token); err != nil {
			t.Fatal(err)
		}
		if token.Seq != int64(seen) || token.Payload != tokenPayload || token.GeneratedElapsedNS < token.ScheduledElapsedNS || token.GeneratedElapsedNS <= 0 {
			t.Fatalf("bad token %+v", token)
		}
		if seen == 0 {
			firstScheduled = token.ScheduledNS
		} else if token.ScheduledNS-firstScheduled != int64(seen)*int64(10*time.Millisecond) {
			t.Fatal("source schedule drifted")
		}
		if token.ScheduledElapsedNS != int64(seen)*int64(10*time.Millisecond) {
			t.Fatal("monotonic source schedule drifted")
		}
		seen++
		if seen == 3 {
			return
		}
	}
	t.Fatalf("stream ended before three tokens: %v", scanner.Err())
}

func TestDownloadSourcePacingAndValidation(t *testing.T) {
	srv := httptest.NewServer(FixtureHandler())
	defer srv.Close()
	start := time.Now()
	resp, err := http.Get(srv.URL + "/download?bytes=16384&mbps=1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	elapsed := time.Since(start)
	if err != nil || len(b) != 16384 || !validPayload(b, 0) || resp.Header.Get("X-PXBench-Source-Pacing-Mbps") != "1" {
		t.Fatalf("paced download was incorrect: bytes=%d err=%v headers=%v", len(b), err, resp.Header)
	}
	// Four 4 KiB chunks at 1 Mbps require three pacing gaps. The first
	// chunk is intentionally immediate; no assertion claims a wire rate.
	if elapsed < 85*time.Millisecond {
		t.Fatalf("source pacing was bypassed: 16 KiB arrived in %s", elapsed)
	}
	for _, bad := range []string{"-1", "NaN", "Inf", "10001", "invalid"} {
		resp, err := http.Get(srv.URL + "/download?bytes=1&mbps=" + bad)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("accepted invalid pacing value %s", bad)
		}
	}
}

func TestSSESourceGapIgnoresWallClockJumps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		wall := time.Now().UnixNano()
		for seq, jump := range []int64{0, int64(10 * time.Second), -int64(time.Hour)} {
			token := sourceToken{Seq: int64(seq), ScheduledNS: wall + jump, GeneratedNS: wall + jump + 1,
				ScheduledElapsedNS: int64(seq) * int64(10*time.Millisecond), GeneratedElapsedNS: int64(seq)*int64(10*time.Millisecond) + 1, Payload: tokenPayload}
			b, _ := json.Marshal(token)
			fmt.Fprintf(w, "data: %s\n\n", b)
			w.(http.Flusher).Flush()
			if !waitUntil(r.Context(), time.Now().Add(10*time.Millisecond)) {
				return
			}
		}
		<-r.Context().Done()
	}))
	defer srv.Close()
	cfg := RunConfig{Proxy: "direct", HTTPTarget: srv.URL, EchoTarget: "127.0.0.1:1",
		Duration: 100 * time.Millisecond, Timeout: time.Second, HTTPBytes: 1, Concurrency: 1,
		SSEInterval: 10 * time.Millisecond, UploadBytes: 1, Output: filepath.Join(t.TempDir(), "clock-jumps.jsonl"), RunID: "clock-jumps"}
	s, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.SSE.Tokens != 3 || s.SSE.SourceErrors != 0 || s.SSE.SourceGapMS.N != 2 || s.SSE.SourceGapMS.P50 != 10 || s.SSE.SourceGapMS.Max != 10 {
		t.Fatalf("wall-clock jumps contaminated source gap statistics: %+v", s.SSE)
	}
}

type unpublishedDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c unpublishedDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestRunEndCensoringPrecedesContextNotification(t *testing.T) {
	// Model the actual race observed in the Linux VM: the socket poller's
	// deadline has elapsed but the context callback has not published Err.
	expired := unpublishedDeadlineContext{Context: context.Background(), deadline: time.Now().Add(-time.Millisecond)}
	if expired.Err() != nil {
		t.Fatal("fixture must retain a nil Err to test notification lag")
	}
	if status, _ := outcome(expired, os.ErrDeadlineExceeded); status != "censored" {
		t.Fatalf("run-end socket timeout mislabeled as %s", status)
	}
	if waitUntil(expired, time.Now().Add(-time.Second)) {
		t.Fatal("an elapsed cadence started new work after the run deadline")
	}
	active := unpublishedDeadlineContext{Context: context.Background(), deadline: time.Now().Add(time.Second)}
	if status, _ := outcome(active, os.ErrDeadlineExceeded); status != "timeout" {
		t.Fatalf("real within-run deadline mislabeled as %s", status)
	}
}

func TestUnansweredEchoAtRunEndIsCensoredOnce(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c) // accept bytes but deliberately never echo them
	}()
	cfg := RunConfig{Proxy: "direct", HTTPTarget: "http://127.0.0.1:1", EchoTarget: l.Addr().String(),
		Duration: 100 * time.Millisecond, Timeout: 3 * time.Second, HTTPBytes: 1, Concurrency: 1,
		EchoInterval: time.Millisecond, UploadBytes: 1, Output: filepath.Join(t.TempDir(), "echo-censor.jsonl"), RunID: "echo-censor"}
	s, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := s.Operations["echo"]
	if e == nil || e.Total != 1 || e.Censored != 1 || e.Timeout != 0 || e.Failure != 0 || s.EchoConnections != 1 {
		t.Fatalf("run end fabricated extra requests or timeouts: echo=%+v connections=%d", e, s.EchoConnections)
	}
}

func TestRunUsesSOCKSForEveryWorkload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	httpSrv := httptest.NewServer(FixtureHandler())
	defer httpSrv.Close()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go ServeEcho(ctx, echo)
	proxy, destinations, closeProxy := testSOCKS(t)
	defer closeProxy()
	cfg := RunConfig{Proxy: proxy, HTTPTarget: httpSrv.URL, EchoTarget: echo.Addr().String(),
		Duration: 500 * time.Millisecond, Timeout: 250 * time.Millisecond, RPS: 20,
		HTTPBytes: 1024, Concurrency: 8, EchoInterval: 25 * time.Millisecond, SSEInterval: 10 * time.Millisecond,
		Background: 1, BackgroundMbps: 1, Uploads: 1, UploadBytes: 8192, Output: filepath.Join(t.TempDir(), "integration.jsonl"), RunID: "integration"}
	s, err := Run(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Operations["http"] == nil || s.Operations["http"].Success == 0 || s.Operations["echo"] == nil || s.Operations["echo"].Success == 0 {
		t.Fatalf("no verified interactive successes: %+v", s.Operations)
	}
	if s.SSE.Tokens < 2 || s.SSE.SequenceErrors != 0 || s.SSE.SourceErrors != 0 || s.DownloadBytes == 0 || s.UploadConfirmedBytes == 0 {
		t.Fatalf("mixed workloads failed: tokens=%d seqerr=%d sourceerr=%d down=%d up=%d", s.SSE.Tokens, s.SSE.SequenceErrors, s.SSE.SourceErrors, s.DownloadBytes, s.UploadConfirmedBytes)
	}
	if destinations.count.Load() < 5 {
		t.Fatalf("workloads bypassed SOCKS: only %d CONNECT requests", destinations.count.Load())
	}
	destinations.mu.Lock()
	defer destinations.mu.Unlock()
	u, _ := strings.CutPrefix(httpSrv.URL, "http://")
	if destinations.hosts[u] < 4 || destinations.hosts[echo.Addr().String()] < 1 {
		t.Fatalf("wrong SOCKS destinations: %+v", destinations.hosts)
	}
}

type testDestinations struct {
	count atomic.Int64
	mu    sync.Mutex
	hosts map[string]int
}

// testSOCKS is a fixture, not part of the product. Fragmented replies exercise
// RFC 1928 read boundaries independently of the benchmark dialer implementation.
func testSOCKS(t *testing.T) (string, *testDestinations, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &testDestinations{hosts: map[string]int{}}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				var greeting [3]byte
				if _, err := io.ReadFull(c, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
					return
				}
				c.Write([]byte{5})
				c.Write([]byte{0})
				var h [4]byte
				if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 || h[1] != 1 {
					return
				}
				var n int
				switch h[3] {
				case 1:
					n = 4
				case 4:
					n = 16
				case 3:
					var size [1]byte
					if _, err := io.ReadFull(c, size[:]); err != nil {
						return
					}
					n = int(size[0])
				default:
					return
				}
				host := make([]byte, n)
				if _, err := io.ReadFull(c, host); err != nil {
					return
				}
				var port [2]byte
				if _, err := io.ReadFull(c, port[:]); err != nil {
					return
				}
				name := string(host)
				if h[3] == 1 || h[3] == 4 {
					name = net.IP(host).String()
				}
				address := net.JoinHostPort(name, strconv.Itoa(int(binary.BigEndian.Uint16(port[:]))))
				upstream, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer upstream.Close()
				d.count.Add(1)
				d.mu.Lock()
				d.hosts[address]++
				d.mu.Unlock()
				c.Write([]byte{5, 0, 0, 1, 127})
				c.Write([]byte{0, 0, 1, 0, 0})
				done := make(chan struct{})
				go func() { io.Copy(upstream, c); upstream.Close(); close(done) }()
				io.Copy(c, upstream)
				c.Close()
				<-done
			}()
		}
	}()
	return l.Addr().String(), d, func() { cancel(); l.Close() }
}

func ExampleRunConfig() {
	c := RunConfig{Proxy: "127.0.0.1:1080", HTTPTarget: "https://fixture.test:18443", EchoTarget: "127.0.0.1:18081"}
	fmt.Println(c.Proxy, c.HTTPTarget, c.EchoTarget)
	// Output: 127.0.0.1:1080 https://fixture.test:18443 127.0.0.1:18081
}
