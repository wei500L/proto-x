// faultrelay forwards one local UDP client to an owned test endpoint and injects
// a bounded outage or a server-facing source-port change. It is a test fixture,
// not a proxy service or a QUIC implementation.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type options struct {
	listen, target, fault, events string
	after, forTime, duration      time.Duration
	maxDatagram                   int
}

type packetCount struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

func (p *packetCount) add(n int) { p.Packets++; p.Bytes += uint64(n) }

type directionCounters struct {
	Received      packetCount `json:"received"`
	Forwarded     packetCount `json:"forwarded"`
	Dropped       packetCount `json:"dropped"`
	Blackhole     packetCount `json:"blackhole"`
	Oversize      packetCount `json:"oversize"`
	ForeignClient packetCount `json:"foreign_client"`
	NoClient      packetCount `json:"no_client"`
	StaleSocket   packetCount `json:"stale_socket"`
	WriteError    packetCount `json:"write_error"`
	ReadErrors    uint64      `json:"read_errors"`
	Truncated     uint64      `json:"truncated_packets"`
}

func (c *directionCounters) drop(reason *packetCount, n int) {
	c.Dropped.add(n)
	reason.add(n)
}

type counters struct {
	Up             directionCounters `json:"up"`
	Down           directionCounters `json:"down"`
	ClientSwitches uint64            `json:"client_switches"`
	Rebinds        uint64            `json:"rebinds"`
}

type event struct {
	Event              string    `json:"event"`
	ElapsedNS          int64     `json:"elapsed_ns"`
	Fault              string    `json:"fault,omitempty"`
	Reason             string    `json:"reason,omitempty"`
	AfterNS            int64     `json:"after_ns,omitempty"`
	ForNS              int64     `json:"for_ns,omitempty"`
	DurationNS         int64     `json:"duration_ns,omitempty"`
	MaxDatagram        int       `json:"max_datagram,omitempty"`
	ListenPort         int       `json:"listen_port,omitempty"`
	SourcePort         int       `json:"source_port,omitempty"`
	PreviousSourcePort int       `json:"previous_source_port,omitempty"`
	UpstreamGeneration uint64    `json:"upstream_generation,omitempty"`
	ClientGeneration   uint64    `json:"client_generation,omitempty"`
	Counters           *counters `json:"counters,omitempty"`
}

type eventSink struct {
	encoder *json.Encoder
	file    *os.File
	err     error
}

// Calls are serialized by relay.mu; no userspace event buffering is used.
func (s *eventSink) write(e event) {
	if s.err == nil {
		if s.encoder.Encode(e) != nil {
			s.err = errors.New("event_write_failed")
		}
	}
}

func (s *eventSink) close() error {
	if s.file != nil {
		if s.file.Sync() != nil && s.err == nil {
			s.err = errors.New("event_sync_failed")
		}
		if s.file.Close() != nil && s.err == nil {
			s.err = errors.New("event_close_failed")
		}
	}
	return s.err
}

type relay struct {
	o         options
	started   time.Time
	listener  *net.UDPConn
	remote    *net.UDPAddr
	sink      *eventSink
	failures  chan string
	wg        sync.WaitGroup
	mu        sync.Mutex
	upstream  *net.UDPConn
	client    *net.UDPAddr
	blackhole bool
	stopped   bool
	upGen     uint64
	clientGen uint64
	stats     counters
}

func main() {
	o, err := parseOptions(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "faultrelay: invalid options (use -h)")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r, err := newRelay(ctx, o)
	if err == nil {
		err = r.run(ctx)
	}
	if err != nil {
		// All returned errors are fixed categories, never raw network errors.
		fmt.Fprintln(os.Stderr, "faultrelay:", err)
		os.Exit(1)
	}
}

func parseOptions(args []string, help io.Writer) (options, error) {
	var o options
	f := flag.NewFlagSet("faultrelay", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&o.listen, "listen", "127.0.0.1:16660", "numeric loopback UDP address; port 0 is allowed")
	f.StringVar(&o.target, "target", "", "owned UDP test endpoint host:port (required; never recorded)")
	f.StringVar(&o.fault, "fault", "blackhole", "blackhole or rebind")
	f.DurationVar(&o.after, "after", 6*time.Second, "delay from ready until fault injection")
	f.DurationVar(&o.forTime, "for", 8*time.Second, "blackhole duration; ignored for rebind")
	f.DurationVar(&o.duration, "duration", 25*time.Second, "total forwarding lifetime from ready")
	f.StringVar(&o.events, "events", "-", "new JSONL file, or - for stdout; existing files are refused")
	f.IntVar(&o.maxDatagram, "max-datagram", 2048, "largest UDP payload to forward (1..65507)")
	f.Usage = func() {
		fmt.Fprintln(help, "Usage: faultrelay -target HOST:PORT [options]")
		f.SetOutput(help)
		f.PrintDefaults()
		f.SetOutput(io.Discard)
	}
	if err := f.Parse(args); err != nil {
		return o, err
	}
	if len(f.Args()) != 0 {
		return o, errors.New("unexpected_arguments")
	}
	return o, validateOptions(o)
}

func validateOptions(o options) error {
	host, port, err := net.SplitHostPort(o.listen)
	ip, ipErr := netip.ParseAddr(host)
	p, portErr := strconv.Atoi(port)
	if err != nil || ipErr != nil || !ip.IsLoopback() || ip.Zone() != "" || portErr != nil || p < 0 || p > 65535 {
		return errors.New("listen_must_be_numeric_loopback")
	}
	host, port, err = net.SplitHostPort(o.target)
	p, portErr = strconv.Atoi(port)
	if err != nil || host == "" || portErr != nil || p < 1 || p > 65535 {
		return errors.New("invalid_target")
	}
	if o.fault != "blackhole" && o.fault != "rebind" {
		return errors.New("invalid_fault")
	}
	if o.duration <= 0 || o.after < 0 || o.after >= o.duration || o.maxDatagram < 1 || o.maxDatagram > 65507 || o.events == "" {
		return errors.New("invalid_limits")
	}
	if o.fault == "blackhole" && (o.forTime <= 0 || o.forTime > o.duration-o.after) {
		return errors.New("blackhole_must_fit_duration")
	}
	return nil
}

func newRelay(ctx context.Context, o options) (*relay, error) {
	if err := validateOptions(o); err != nil {
		return nil, err
	}
	addr, _ := net.ResolveUDPAddr("udp", o.listen) // already validated as numeric
	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, errors.New("listen_failed")
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", o.target)
	if err != nil {
		listener.Close()
		return nil, errors.New("target_resolve_or_socket_failed")
	}
	upstream := conn.(*net.UDPConn)
	var sink *eventSink
	if o.events == "-" {
		sink = &eventSink{encoder: json.NewEncoder(os.Stdout)}
	} else {
		if os.MkdirAll(filepath.Dir(o.events), 0755) != nil {
			listener.Close()
			upstream.Close()
			return nil, errors.New("event_directory_failed")
		}
		file, err := os.OpenFile(o.events, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			listener.Close()
			upstream.Close()
			return nil, errors.New("event_open_failed")
		}
		sink = &eventSink{encoder: json.NewEncoder(file), file: file}
	}
	setBuffers(listener)
	setBuffers(upstream)
	r := &relay{o: o, started: time.Now(), listener: listener, upstream: upstream,
		remote: upstream.RemoteAddr().(*net.UDPAddr), sink: sink, failures: make(chan string, 1), upGen: 1}
	r.emitLocked(event{Event: "start", Fault: o.fault, AfterNS: int64(o.after), ForNS: int64(o.forTime),
		DurationNS: int64(o.duration), MaxDatagram: o.maxDatagram,
		ListenPort: listener.LocalAddr().(*net.UDPAddr).Port, SourcePort: upstream.LocalAddr().(*net.UDPAddr).Port})
	r.wg.Add(2)
	go r.readClient()
	go r.readUpstream(upstream)
	return r, nil
}

func setBuffers(c *net.UDPConn) {
	// Requests only: operating systems may clamp or double these socket limits.
	_ = c.SetReadBuffer(64 << 10)
	_ = c.SetWriteBuffer(64 << 10)
}

func (r *relay) emitLocked(e event) {
	e.ElapsedNS = time.Since(r.started).Nanoseconds()
	e.UpstreamGeneration = r.upGen
	snapshot := r.stats
	e.Counters = &snapshot
	r.sink.write(e)
	if r.sink.err != nil {
		select {
		case r.failures <- "event_write_failed":
		default:
		}
	}
}

func (r *relay) run(ctx context.Context) error {
	after := time.NewTimer(time.Until(r.started.Add(r.o.after)))
	end := time.NewTimer(time.Until(r.started.Add(r.o.duration)))
	defer after.Stop()
	defer end.Stop()
	var restore *time.Timer
	var restoreC <-chan time.Time
	defer func() {
		if restore != nil {
			restore.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return r.shutdown("context_cancelled")
		case reason := <-r.failures:
			_ = r.shutdown(reason)
			return errors.New(reason)
		case <-end.C:
			return r.shutdown("duration")
		case <-after.C:
			if r.o.fault == "rebind" {
				if err := r.rebind(); err != nil {
					_ = r.shutdown("rebind_failed")
					return err
				}
			} else {
				r.mu.Lock()
				r.blackhole = true
				r.emitLocked(event{Event: "fault_start", Fault: "blackhole"})
				restore = time.NewTimer(r.o.forTime)
				restoreC = restore.C
				r.mu.Unlock()
			}
		case <-restoreC:
			r.mu.Lock()
			r.blackhole = false
			r.emitLocked(event{Event: "fault_end", Fault: "blackhole", Reason: "restored"})
			r.mu.Unlock()
			restoreC = nil
		}
	}
}

func (r *relay) rebind() error {
	// Open before closing the old socket so the OS cannot reuse its source port.
	next, err := net.DialUDP("udp", nil, r.remote)
	if err != nil {
		return errors.New("rebind_socket_failed")
	}
	setBuffers(next)
	r.mu.Lock()
	old := r.upstream
	oldPort := old.LocalAddr().(*net.UDPAddr).Port
	nextPort := next.LocalAddr().(*net.UDPAddr).Port
	if r.stopped || oldPort == nextPort {
		r.mu.Unlock()
		next.Close()
		return errors.New("rebind_port_change_failed")
	}
	r.upstream = next
	r.upGen++
	r.stats.Rebinds++
	r.emitLocked(event{Event: "fault_start", Fault: "rebind", SourcePort: nextPort, PreviousSourcePort: oldPort})
	r.wg.Add(1)
	go r.readUpstream(next)
	r.mu.Unlock()
	old.Close()
	r.mu.Lock()
	r.emitLocked(event{Event: "fault_end", Fault: "rebind", Reason: "socket_replaced"})
	r.mu.Unlock()
	return nil
}

func (r *relay) readClient() {
	defer r.wg.Done()
	var buf [65536]byte // read complete ordinary UDP datagrams before size rejection
	for {
		n, _, flags, addr, err := r.listener.ReadMsgUDP(buf[:], nil)
		if err != nil {
			r.mu.Lock()
			stopped := r.stopped
			if !stopped {
				r.stats.Up.ReadErrors++
			}
			r.mu.Unlock()
			if !stopped {
				select {
				case r.failures <- "listener_read_failed":
				default:
				}
			}
			return
		}
		r.mu.Lock()
		if r.stopped {
			r.mu.Unlock()
			return
		}
		c := &r.stats.Up
		c.Received.add(n)
		clientEvent := ""
		if flags&syscall.MSG_TRUNC != 0 {
			c.Truncated++
		}
		switch {
		case n > r.o.maxDatagram || flags&syscall.MSG_TRUNC != 0:
			c.drop(&c.Oversize, n)
		case !addr.IP.IsLoopback() || (r.client != nil && !addr.IP.Equal(r.client.IP)):
			c.drop(&c.ForeignClient, n)
		default:
			if r.client == nil || addr.Port != r.client.Port {
				clientEvent = "client_bound"
				if r.client != nil {
					clientEvent = "client_switched"
					r.stats.ClientSwitches++
				}
				r.client = addr
				r.clientGen++
			}
			if r.blackhole {
				c.drop(&c.Blackhole, n)
			} else {
				_ = r.upstream.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
				written, err := r.upstream.Write(buf[:n])
				if err != nil || written != n {
					c.drop(&c.WriteError, n)
				} else {
					c.Forwarded.add(n)
				}
			}
		}
		if clientEvent != "" {
			r.emitLocked(event{Event: clientEvent, ClientGeneration: r.clientGen})
		}
		r.mu.Unlock()
	}
}

func (r *relay) readUpstream(conn *net.UDPConn) {
	defer r.wg.Done()
	var buf [65536]byte
	for {
		n, _, flags, _, err := conn.ReadMsgUDP(buf[:], nil)
		if err != nil {
			r.mu.Lock()
			finished := r.stopped || conn != r.upstream
			if !finished {
				r.stats.Down.ReadErrors++
			}
			r.mu.Unlock()
			if finished {
				return
			}
			// ICMP errors from the owned endpoint must not terminate the test.
			time.Sleep(time.Millisecond)
			continue
		}
		r.mu.Lock()
		if r.stopped {
			r.mu.Unlock()
			return
		}
		c := &r.stats.Down
		c.Received.add(n)
		if flags&syscall.MSG_TRUNC != 0 {
			c.Truncated++
		}
		switch {
		case n > r.o.maxDatagram || flags&syscall.MSG_TRUNC != 0:
			c.drop(&c.Oversize, n)
		case conn != r.upstream:
			c.drop(&c.StaleSocket, n)
		case r.blackhole:
			c.drop(&c.Blackhole, n)
		case r.client == nil:
			c.drop(&c.NoClient, n)
		default:
			_ = r.listener.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			written, err := r.listener.WriteToUDP(buf[:n], r.client)
			if err != nil || written != n {
				c.drop(&c.WriteError, n)
			} else {
				c.Forwarded.add(n)
			}
		}
		r.mu.Unlock()
	}
}

func (r *relay) shutdown(reason string) error {
	r.mu.Lock()
	r.stopped = true
	if r.blackhole {
		r.blackhole = false
		r.emitLocked(event{Event: "fault_end", Fault: "blackhole", Reason: "shutdown_before_restore"})
	}
	conn := r.upstream
	r.mu.Unlock()
	r.listener.Close()
	conn.Close()
	r.wg.Wait()
	r.mu.Lock()
	r.emitLocked(event{Event: "end", Fault: r.o.fault, Reason: reason})
	err := r.sink.close()
	r.mu.Unlock()
	return err
}
