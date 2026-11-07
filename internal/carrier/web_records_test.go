package carrier

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"proto-x/internal/wire"
)

func TestWebRecordPaddingAndBoundaries(t *testing.T) {
	for _, pad := range []int{0, 63, 127, 255} {
		l := newWebLink("h3", true, pad)
		for _, n := range []int{0, 17, wire.DataPayload, wire.MaxPayload} {
			f := wire.Frame{Kind: wire.Data, ID: 7, Offset: 12, Limit: 100, Payload: bytes.Repeat([]byte{9}, n)}
			var b bytes.Buffer
			if err := l.writeRecord(&b, f); err != nil {
				t.Fatal(err)
			}
			if b.Len() < wire.HeaderSize+n+4 || b.Len() > l.RecordCost(f) {
				t.Fatal("padding escaped budget bounds")
			}
			got, err := l.readRecord(&b)
			if err != nil || got.ID != f.ID || got.Offset != f.Offset || !bytes.Equal(got.Payload, f.Payload) || b.Len() != 0 {
				t.Fatalf("roundtrip: %+v %v", got, err)
			}
		}
		_ = l.Close()
	}
	for _, header := range [][2]uint16{{0, 0}, {31, 0}, {wire.HeaderSize + wire.MaxPayload + 1, 0}, {32, 256}} {
		var b [4]byte
		binary.BigEndian.PutUint16(b[:2], header[0])
		binary.BigEndian.PutUint16(b[2:], header[1])
		l := newWebLink("h2", true, 0)
		if _, err := l.readRecord(bytes.NewReader(b[:])); !errors.Is(err, wire.ErrFrame) {
			t.Fatalf("invalid length must fail before reading body: %v", err)
		}
		_ = l.Close()
	}
}

func FuzzWebRecord(f *testing.F) {
	var b bytes.Buffer
	l := newWebLink("h3", true, 127)
	_ = l.writeRecord(&b, wire.Frame{Kind: wire.Data, ID: 1, Payload: []byte("record")})
	f.Add(b.Bytes())
	_ = l.Close()
	f.Fuzz(func(t *testing.T, b []byte) {
		l := newWebLink("h3", true, 127)
		defer l.Close()
		got, err := l.readRecord(bytes.NewReader(b))
		if err != nil {
			return
		}
		if len(got.Payload) > wire.MaxPayload {
			t.Fatal("unbounded payload")
		}
		if err := l.writeRecord(io.Discard, got); err != nil {
			t.Fatal(err)
		}
	})
}
