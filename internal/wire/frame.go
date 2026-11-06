// Package wire defines the bounded, offset-addressed records carried inside TLS.
package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	Version     = 1
	HeaderSize  = 32
	MaxPayload  = 4096
	DataPayload = 2048
)

const (
	Hello uint8 = iota + 1
	Welcome
	Open
	Opened
	Data
	Ack
	Fin
	Reset
	Ping
	Pong
)

const FlagFIN uint8 = 1

type Frame struct {
	Kind    uint8
	Flags   uint8
	ID      uint64
	Offset  uint64
	Limit   uint64
	Payload []byte
}

var ErrFrame = errors.New("invalid protocol record")

func Write(w io.Writer, f Frame) error {
	if len(f.Payload) > MaxPayload || f.Kind < Hello || f.Kind > Pong {
		return ErrFrame
	}
	b := make([]byte, HeaderSize+len(f.Payload))
	b[0], b[1] = f.Kind, f.Flags
	binary.BigEndian.PutUint64(b[4:12], f.ID)
	binary.BigEndian.PutUint64(b[12:20], f.Offset)
	binary.BigEndian.PutUint64(b[20:28], f.Limit)
	binary.BigEndian.PutUint32(b[28:32], uint32(len(f.Payload)))
	copy(b[HeaderSize:], f.Payload)
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
	return nil
}

func Read(r io.Reader) (Frame, error) {
	var b [HeaderSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(b[28:32])
	if b[2] != 0 || b[3] != 0 || n > MaxPayload || b[0] < Hello || b[0] > Pong || b[1]&^FlagFIN != 0 {
		return Frame{}, ErrFrame
	}
	f := Frame{Kind: b[0], Flags: b[1], ID: binary.BigEndian.Uint64(b[4:12]), Offset: binary.BigEndian.Uint64(b[12:20]), Limit: binary.BigEndian.Uint64(b[20:28]), Payload: make([]byte, int(n))}
	_, err := io.ReadFull(r, f.Payload)
	return f, err
}
