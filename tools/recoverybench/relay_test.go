package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func testLog(t *testing.T) *eventLog {
	t.Helper()
	l, err := newLog(filepath.Join(t.TempDir(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := l.close(); e != nil {
			t.Error(e)
		}
	})
	return l
}

func TestUDPDelayAndOneDirectionBlackhole(t *testing.T) {
	up, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		b := make([]byte, 4096)
		for {
			n, a, e := up.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = up.WriteToUDP(b[:n], a)
		}
	}()
	r, err := newUDPRelay(context.Background(), up.LocalAddr().String(), 15*time.Millisecond, testLog(t))
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	a, _ := net.ResolveUDPAddr("udp4", r.address())
	c, err := net.DialUDP("udp4", nil, a)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := []byte{0, 1, 2, 3, 255, 12, 0, 42}
	b := make([]byte, 128)
	start := time.Now()
	c.SetDeadline(start.Add(time.Second))
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	n, err := c.Read(b)
	if err != nil || !bytes.Equal(payload, b[:n]) {
		t.Fatalf("round trip %x %v", b[:n], err)
	}
	if elapsed := time.Since(start); elapsed < 25*time.Millisecond {
		t.Fatalf("configured two way delay missing: %v", elapsed)
	}
	r.setBlackhole("down", true)
	c.SetDeadline(time.Now().Add(80 * time.Millisecond))
	c.Write([]byte("must be dropped"))
	if _, err = c.Read(b); err == nil {
		t.Fatal("downstream blackhole forwarded a response")
	}
	r.setBlackhole("down", false)
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write(payload)
	n, err = c.Read(b)
	if err != nil || !bytes.Equal(payload, b[:n]) {
		t.Fatalf("recovery %x %v", b[:n], err)
	}
	r.close()
	if r.up.txPackets.Load() != 3 || r.down.txPackets.Load() != 2 || r.down.drops.Load() != 1 || r.up.drops.Load() != 0 {
		t.Fatalf("directional counters: %#v", r.counts())
	}
}

func TestTCPChunkDelayPreservesStreamAndStops(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()
	r, err := newTCPRelay(context.Background(), l.Addr().String(), 10*time.Millisecond, testLog(t))
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	c, err := net.DialTimeout("tcp4", r.address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	data := bytes.Repeat([]byte{0, 13, 10, 255, 42}, 1500)
	back := make([]byte, len(data))
	start := time.Now()
	c.SetDeadline(start.Add(time.Second))
	if _, err = c.Write(data); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(c, back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, back) || time.Since(start) < 18*time.Millisecond {
		t.Fatal("stream integrity/delay check failed")
	}
	done := make(chan struct{})
	go func() { r.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not close live streams")
	}
	if r.up.txBytes.Load() != int64(len(data)) || r.down.txBytes.Load() != int64(len(data)) {
		t.Fatalf("TLS byte counters %v", r.counts())
	}
}
