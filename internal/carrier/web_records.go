package carrier

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"

	"proto-x/internal/wire"
)

// HTTP request bodies carry bounded envelopes. Padding changes record lengths,
// not traffic timing, and is not a claim of browser indistinguishability.
const maxWebPadding = 255

func validWebPadding(n int) bool { return n == 0 || n == 63 || n == 127 || n == 255 }

func (l *Link) RecordCost(f wire.Frame) int {
	n := wire.HeaderSize + len(f.Payload)
	if l.web != nil {
		// Reserve the upper bound before sending. Actual random padding can be
		// smaller; the budget must not silently exclude padding overhead.
		n += 4 + l.web.padding
	}
	return n
}

func (l *Link) writeRecord(w io.Writer, f wire.Frame) error {
	if l.web == nil {
		return wire.Write(w, f)
	}
	var inner bytes.Buffer
	if err := wire.Write(&inner, f); err != nil {
		return err
	}
	var random [maxWebPadding + 1]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	pad := int(random[0]) & l.web.padding
	b := make([]byte, 4+inner.Len()+pad)
	binary.BigEndian.PutUint16(b[:2], uint16(inner.Len()))
	binary.BigEndian.PutUint16(b[2:4], uint16(pad))
	copy(b[4:], inner.Bytes())
	copy(b[4+inner.Len():], random[1:])
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	l.PaddingSent.Add(uint64(4 + pad))
	return nil
}

func (l *Link) readRecord(r io.Reader) (wire.Frame, error) {
	if l.web == nil {
		return wire.Read(r)
	}
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return wire.Frame{}, err
	}
	n, pad := int(binary.BigEndian.Uint16(header[:2])), int(binary.BigEndian.Uint16(header[2:]))
	if n < wire.HeaderSize || n > wire.HeaderSize+wire.MaxPayload || pad > maxWebPadding {
		return wire.Frame{}, wire.ErrFrame
	}
	b := make([]byte, n+pad)
	if _, err := io.ReadFull(r, b); err != nil {
		return wire.Frame{}, err
	}
	inner := bytes.NewReader(b[:n])
	f, err := wire.Read(inner)
	if err == nil && inner.Len() != 0 {
		err = wire.ErrFrame
	}
	if err == nil {
		l.PaddingReceived.Add(uint64(4 + pad))
	}
	return f, err
}
