package wire

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestRejectOversizeBeforeAllocation(t *testing.T) {
	b := make([]byte, HeaderSize)
	b[0] = Data
	binary.BigEndian.PutUint32(b[28:], ^uint32(0))
	if _, e := Read(bytes.NewReader(b)); e != ErrFrame {
		t.Fatalf("oversize: %v", e)
	}
}
func TestTruncatedRecordCannotSucceed(t *testing.T) {
	var b bytes.Buffer
	if e := Write(&b, Frame{Kind: Data, ID: 1, Offset: 45, Payload: bytes.Repeat([]byte{7}, MaxPayload)}); e != nil {
		t.Fatal(e)
	}
	for _, n := range []int{0, 1, 31, 32, 33, b.Len() - 1} {
		if _, e := Read(bytes.NewReader(b.Bytes()[:n])); e == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
}
func FuzzRead(f *testing.F) {
	var b bytes.Buffer
	_ = Write(&b, Frame{Kind: Data, ID: 1, Payload: []byte("seed")})
	f.Add(b.Bytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := Read(bytes.NewReader(b))
		if e != nil {
			return
		}
		if len(p.Payload) > MaxPayload {
			t.Fatal("oversize")
		}
		var out bytes.Buffer
		if e = Write(&out, p); e != nil {
			t.Fatal(e)
		}
		q, e := Read(&out)
		if e != nil || q.ID != p.ID || q.Offset != p.Offset || !bytes.Equal(q.Payload, p.Payload) {
			t.Fatal("round trip corruption")
		}
		if _, e = Read(&out); e != io.EOF {
			t.Fatal(e)
		}
	})
}
