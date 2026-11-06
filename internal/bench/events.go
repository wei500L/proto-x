package bench

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Event is a raw observation. Status is success, failure, timeout, censored
// (the run ended), or rejected (the load generator's explicit concurrency cap).
// Latency percentiles never discard those statuses from their denominators.
type Event struct {
	RunID                    string  `json:"run_id"`
	Kind                     string  `json:"kind"`
	Status                   string  `json:"status,omitempty"`
	Seq                      int64   `json:"seq"`
	Connection               int64   `json:"connection,omitempty"`
	Worker                   int     `json:"worker,omitempty"`
	AtNS                     int64   `json:"at_ns"`
	RecordedElapsedNS        int64   `json:"recorded_elapsed_ns"`
	ScheduledNS              int64   `json:"scheduled_ns,omitempty"`
	StartedNS                int64   `json:"started_ns,omitempty"`
	LatencyMS                float64 `json:"latency_ms,omitempty"`
	ScheduledLatencyMS       float64 `json:"scheduled_latency_ms,omitempty"`
	QueueDelayMS             float64 `json:"queue_delay_ms,omitempty"`
	TTFBMS                   float64 `json:"ttfb_ms,omitempty"`
	Bytes                    int64   `json:"bytes,omitempty"`
	ElapsedSeconds           float64 `json:"elapsed_seconds,omitempty"`
	ReceiveGapMS             float64 `json:"receive_gap_ms,omitempty"`
	SourceGapMS              float64 `json:"source_gap_ms,omitempty"`
	ExcessGapMS              float64 `json:"excess_gap_ms,omitempty"`
	SourceScheduledNS        int64   `json:"source_scheduled_ns,omitempty"`
	SourceGeneratedNS        int64   `json:"source_generated_ns,omitempty"`
	SourceScheduledElapsedNS int64   `json:"source_scheduled_elapsed_ns"`
	SourceGeneratedElapsedNS int64   `json:"source_generated_elapsed_ns"`
	SourceDelayMS            float64 `json:"source_generation_delay_ms,omitempty"`
	TerminalGapMS            float64 `json:"terminal_gap_ms,omitempty"`
	HTTPReused               bool    `json:"http_reused,omitempty"`
	Attempts                 int     `json:"attempts,omitempty"`
	Missing                  int64   `json:"missing,omitempty"`
	Duplicate                bool    `json:"duplicate,omitempty"`
	Error                    string  `json:"error,omitempty"`
	Detail                   any     `json:"detail,omitempty"`
}

type Distribution struct {
	N    int     `json:"n"`
	P50  float64 `json:"p50"`
	P95  float64 `json:"p95"`
	P99  float64 `json:"p99"`
	Max  float64 `json:"max"`
	Mean float64 `json:"mean"`
}

type OperationStats struct {
	Total              int          `json:"total"`
	Success            int          `json:"success"`
	Failure            int          `json:"failure"`
	Timeout            int          `json:"timeout"`
	Censored           int          `json:"censored"`
	Rejected           int          `json:"rejected"`
	ConnectionAttempts int          `json:"connection_attempts"`
	SuccessRateTotal   float64      `json:"success_rate_total"`
	LatencyMS          Distribution `json:"successful_latency_ms"`
	ScheduledLatencyMS Distribution `json:"successful_scheduled_latency_ms"`
	TTFBMS             Distribution `json:"successful_ttfb_ms"`
	latencies          []float64
	scheduled          []float64
	ttfb               []float64
}

type StreamStats struct {
	Connections        int          `json:"connections"`
	ConnectFailure     int          `json:"connect_failure"`
	Tokens             int          `json:"tokens"`
	SequenceErrors     int          `json:"sequence_errors"`
	SourceErrors       int          `json:"source_errors"`
	UnexpectedEnds     int          `json:"unexpected_ends"`
	ReceiveGapMS       Distribution `json:"receive_gap_ms"`
	SourceGapMS        Distribution `json:"source_gap_ms"`
	ExcessGapMS        Distribution `json:"excess_gap_ms"`
	GapsOver250MS      int          `json:"gaps_over_250ms"`
	GapsOver1000MS     int          `json:"gaps_over_1000ms"`
	ExcessOver250MS    int          `json:"excess_over_250ms"`
	ExcessOver1000MS   int          `json:"excess_over_1000ms"`
	TerminalOver250MS  int          `json:"terminal_gaps_over_250ms"`
	TerminalOver1000MS int          `json:"terminal_gaps_over_1000ms"`
	MaxTerminalGapMS   float64      `json:"max_terminal_gap_ms"`
	RunTailGapMS       float64      `json:"run_tail_gap_ms"`
	SourceDelayMS      Distribution `json:"source_generation_delay_ms"`
	receiveGaps        []float64
	sourceGaps         []float64
	excessGaps         []float64
	sourceDelays       []float64
}

type Summary struct {
	RunID                string                     `json:"run_id"`
	StartedUTC           string                     `json:"started_utc"`
	DurationSeconds      float64                    `json:"duration_seconds"`
	Config               RunConfig                  `json:"config"`
	Notes                []string                   `json:"notes"`
	Operations           map[string]*OperationStats `json:"operations"`
	SSE                  StreamStats                `json:"sse"`
	DownloadBytes        int64                      `json:"download_validated_bytes"`
	DownloadGoodputMbps  float64                    `json:"download_goodput_mbps"`
	UploadConfirmedBytes int64                      `json:"upload_server_confirmed_bytes"`
	UploadGoodputMbps    float64                    `json:"upload_confirmed_goodput_mbps"`
	EchoConnections      int                        `json:"echo_connections"`
	LogError             string                     `json:"log_error,omitempty"`
}

type recorder struct {
	mu      sync.Mutex
	f       *os.File
	enc     *json.Encoder
	err     error
	summary Summary
	start   time.Time
}

func newRecorder(cfg RunConfig) (*recorder, error) {
	if err := os.MkdirAll(filepath.Dir(cfg.Output), 0700); err != nil {
		return nil, err
	}
	// Refuse accidental overwrites: every measurement should have its own
	// run id and output path, including failed trials.
	f, err := os.OpenFile(cfg.Output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	r := &recorder{f: f, enc: json.NewEncoder(f), start: time.Now()}
	r.summary = Summary{RunID: cfg.RunID, StartedUTC: r.start.UTC().Format(time.RFC3339Nano), Config: cfg,
		Operations: map[string]*OperationStats{}, Notes: []string{
			"Percentiles use nearest-rank ceil(p*N); only successful operations contribute values. Total/status counts include failures, timeouts, censored requests and concurrency rejections.",
			"Run-end censoring checks the monotonic context deadline as well as ctx.Err(), because network deadlines may fire before cancellation publication. Recorded elapsed time is monotonic; wall-clock event times are correlation metadata.",
			"HTTP arrivals are open-loop and scheduled latency includes load-generator delay. Echo uses one persistent connection with at most one outstanding request; it is closed-loop.",
			"Small HTTP requests default to a side-effect-free POST fixture to prevent replay after any request bytes were written. Optional GET permits standard-library idempotent retries; connection/write attempts are logged in both modes.",
			"SSE receipt gaps use client monotonic time; source/excess gaps and production delay use monotonic elapsed fields relative to that source connection. Wall-clock nanoseconds are only correlation metadata. Clock synchronization and one-way delivery latency are not assumed.",
			"SSE terminal gaps are right-censored and reported separately, including run termination; a missing final token cannot hide an outage.",
			"SSE receive-gap statistics include gaps across reconnections; source/excess gaps are only meaningful within one source connection. Inspect cross_connection_gap raw annotations before attributing a stall.",
			"Download goodput counts validated application bytes received; upload goodput counts bytes acknowledged by the fixture's completed response. Neither is outer-wire throughput.",
			"Optional background-mbps is source-side application pacing per download worker with 4 KiB chunks. It applies identically to every proxy, excludes interactive and protocol overhead bytes, and is not a whole-proxy wire-rate cap.",
		}}
	return r, nil
}

func (r *recorder) record(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.RunID = r.summary.RunID
	if e.AtNS == 0 {
		e.AtNS = time.Now().UnixNano()
	}
	e.RecordedElapsedNS = int64(time.Since(r.start))
	if r.err == nil {
		r.err = r.enc.Encode(e)
	}
	s := &r.summary
	switch e.Kind {
	case "http", "echo", "upload", "download_end":
		o := s.Operations[e.Kind]
		if o == nil {
			o = &OperationStats{}
			s.Operations[e.Kind] = o
		}
		o.Total++
		o.ConnectionAttempts += e.Attempts
		switch e.Status {
		case "success":
			o.Success++
			o.latencies = append(o.latencies, e.LatencyMS)
			if e.ScheduledNS != 0 {
				o.scheduled = append(o.scheduled, e.ScheduledLatencyMS)
			}
			if e.TTFBMS > 0 {
				o.ttfb = append(o.ttfb, e.TTFBMS)
			}
		case "failure":
			o.Failure++
		case "timeout":
			o.Timeout++
		case "censored":
			o.Censored++
		case "rejected":
			o.Rejected++
		}
		if e.Kind == "download_end" {
			s.DownloadBytes += e.Bytes
		}
		if e.Kind == "upload" && e.Status == "success" {
			s.UploadConfirmedBytes += e.Bytes
		}
	case "echo_connect":
		if e.Status == "success" {
			s.EchoConnections++
		}
	case "sse_connect":
		if e.Status == "success" {
			s.SSE.Connections++
		} else if e.Status != "censored" {
			s.SSE.ConnectFailure++
		}
	case "sse_token":
		ss := &s.SSE
		ss.Tokens++
		if e.Status != "success" {
			ss.SequenceErrors++
		}
		ss.sourceDelays = append(ss.sourceDelays, e.SourceDelayMS)
		if e.ReceiveGapMS > 0 {
			ss.receiveGaps = append(ss.receiveGaps, e.ReceiveGapMS)
			if e.SourceGapMS > 0 {
				ss.sourceGaps = append(ss.sourceGaps, e.SourceGapMS)
				ss.excessGaps = append(ss.excessGaps, e.ExcessGapMS)
			}
			if e.ReceiveGapMS > 250 {
				ss.GapsOver250MS++
			}
			if e.ReceiveGapMS > 1000 {
				ss.GapsOver1000MS++
			}
			if e.ExcessGapMS > 250 {
				ss.ExcessOver250MS++
			}
			if e.ExcessGapMS > 1000 {
				ss.ExcessOver1000MS++
			}
		}
	case "sse_source_error":
		s.SSE.SourceErrors++
	case "sse_run_tail":
		s.SSE.RunTailGapMS = e.TerminalGapMS
	case "sse_end":
		ss := &s.SSE
		if e.Status != "censored" {
			ss.UnexpectedEnds++
		}
		if e.TerminalGapMS > 250 {
			ss.TerminalOver250MS++
		}
		if e.TerminalGapMS > 1000 {
			ss.TerminalOver1000MS++
		}
		ss.MaxTerminalGapMS = math.Max(ss.MaxTerminalGapMS, e.TerminalGapMS)
	}
}

func distribution(values []float64) Distribution {
	if len(values) == 0 {
		return Distribution{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	var sum float64
	for _, v := range sorted {
		sum += v
	}
	p := func(p float64) float64 { return sorted[int(math.Ceil(float64(len(sorted))*p))-1] }
	return Distribution{N: len(sorted), P50: p(.5), P95: p(.95), P99: p(.99), Max: sorted[len(sorted)-1], Mean: sum / float64(len(sorted))}
}

func (r *recorder) finish() (Summary, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := &r.summary
	s.DurationSeconds = time.Since(r.start).Seconds()
	for _, o := range s.Operations {
		o.SuccessRateTotal = float64(o.Success) / float64(o.Total)
		o.LatencyMS = distribution(o.latencies)
		o.ScheduledLatencyMS = distribution(o.scheduled)
		o.TTFBMS = distribution(o.ttfb)
	}
	s.SSE.ReceiveGapMS = distribution(s.SSE.receiveGaps)
	s.SSE.SourceGapMS = distribution(s.SSE.sourceGaps)
	s.SSE.ExcessGapMS = distribution(s.SSE.excessGaps)
	s.SSE.SourceDelayMS = distribution(s.SSE.sourceDelays)
	s.DownloadGoodputMbps = float64(s.DownloadBytes) * 8 / s.DurationSeconds / 1e6
	s.UploadGoodputMbps = float64(s.UploadConfirmedBytes) * 8 / s.DurationSeconds / 1e6
	if r.err != nil {
		s.LogError = r.err.Error()
	}
	if err := r.f.Close(); r.err == nil {
		r.err = err
	}
	path := s.Config.Summary
	if path == "" {
		path = strings.TrimSuffix(s.Config.Output, ".jsonl") + ".summary.json"
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return *s, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return *s, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return *s, fmt.Errorf("summary output: %w", err)
	}
	_, err = f.Write(append(b, '\n'))
	closeErr := f.Close()
	if err != nil {
		return *s, err
	}
	if closeErr != nil {
		return *s, closeErr
	}
	return *s, r.err
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
