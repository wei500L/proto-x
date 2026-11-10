package session

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// Coalescing must neither exhaust the retained-byte window nor delay a FIN
// indefinitely. Drop a carrier during a request and check the resumed request/response
// the same origin socket receives exactly one byte stream and one half-close.
func TestCoalescedACKRecoveryWindowAndHalfClose(t *testing.T) {
	request := deterministicBytes(512<<10, 311)
	originDone := make(chan error, 1)
	o := listenOrigin(t, func(c *net.TCPConn) {
		body, err := io.ReadAll(c)
		if err == nil && !bytes.Equal(body, request) {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = c.Write(body)
		}
		if err == nil {
			err = c.CloseWrite()
		}
		originDone <- err
	})
	cfg := testConfig()
	cfg.ACKCoalesce = true
	p := newMemorySessions(t, cfg)
	f := openTestFlow(t, p.client, o.address)
	result := make(chan error, 1)
	go func() {
		_, err := f.Write(request)
		if err == nil {
			err = f.CloseWrite()
		}
		if err == nil {
			var b []byte
			b, err = io.ReadAll(f)
			if err == nil && !bytes.Equal(b, request) {
				err = io.ErrUnexpectedEOF
			}
		}
		result <- err
	}()
	waitCondition(t, time.Second, "data in flight", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.txEnd >= uint64(cfg.Window)
	})
	p.drop()
	p.attach(t)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("coalesced ACKs blocked window or FIN progress")
	}
	if err := <-originDone; err != nil || o.count.Load() != 1 {
		t.Fatalf("origin err=%v accepts=%d", err, o.count.Load())
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	waitCondition(t, time.Second, "coalesced flow retirement", func() bool {
		return p.client.FlowCount() == 0 && p.server.FlowCount() == 0
	})
}

func TestCoalescedACKDoesNotBlockSmallApplicationReply(t *testing.T) {
	cfg := testConfig()
	cfg.ACKCoalesce = true
	o := listenOrigin(t, func(c *net.TCPConn) { _, _ = io.Copy(c, c) })
	p := newMemorySessions(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, err := p.client.Open(ctx, o.address)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 50; i++ {
			if _, err := f.Write([]byte{byte(i)}); err != nil {
				done <- err
				return
			}
			var b [1]byte
			if _, err := io.ReadFull(f, b[:]); err != nil {
				done <- err
				return
			}
			if b[0] != byte(i) {
				done <- io.ErrUnexpectedEOF
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("small replies stalled behind cumulative acknowledgement")
	}
}
