package bench

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// DialSOCKS5 connects through an explicit SOCKS5 endpoint. DNS names are sent to
// that endpoint, so the benchmark never silently uses the host's system proxy
// or resolves target names locally. Only CONNECT and unauthenticated SOCKS5 are
// used; benchmark proxy listeners should be restricted to the test environment.
func DialSOCKS5(ctx context.Context, proxy, address string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	c, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("SOCKS dial: %w", err)
	}
	good := false
	defer func() {
		if !good {
			c.Close()
		}
	}()
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if err = writeAll(c, []byte{5, 1, 0}); err != nil {
		return nil, fmt.Errorf("SOCKS greeting: %w", err)
	}
	var hello [2]byte
	if _, err = io.ReadFull(c, hello[:]); err != nil {
		return nil, fmt.Errorf("SOCKS greeting: %w", err)
	}
	if hello != [2]byte{5, 0} {
		return nil, errors.New("SOCKS endpoint did not accept unauthenticated SOCKS5")
	}
	req, err := socksRequest(address)
	if err != nil {
		return nil, err
	}
	if err = writeAll(c, req); err != nil {
		return nil, fmt.Errorf("SOCKS CONNECT: %w", err)
	}
	var reply [4]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil {
		return nil, fmt.Errorf("SOCKS CONNECT response: %w", err)
	}
	if reply[0] != 5 || reply[2] != 0 {
		return nil, errors.New("invalid SOCKS response header")
	}
	if reply[1] != 0 {
		return nil, fmt.Errorf("SOCKS CONNECT rejected, code %d", reply[1])
	}
	var n int
	switch reply[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var b [1]byte
		if _, err = io.ReadFull(c, b[:]); err != nil {
			return nil, err
		}
		n = int(b[0])
	default:
		return nil, errors.New("invalid SOCKS bound-address type")
	}
	if _, err = io.CopyN(io.Discard, c, int64(n+2)); err != nil {
		return nil, fmt.Errorf("SOCKS bound address: %w", err)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	c.SetDeadline(time.Time{})
	good = true
	return c, nil
}

func socksRequest(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid target port")
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 1)
			req = append(req, v4...)
		} else {
			req = append(req, 4)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("SOCKS hostname length outside 1..255")
		}
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	return append(req, p[:]...), nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
