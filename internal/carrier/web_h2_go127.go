//go:build go1.27

package carrier

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
)

// Go 1.27 exposes a standard-library single-connection HTTP transport. Avoid
// x/net v0.56's compatibility wrapper here: its Reserve -> stateHook callback
// can reenter its own mutex under concurrent long-lived requests. The one-shot
// dialer ensures exporter authentication stays on the exact TLS connection.
func newWebHTTP2Conn(ctx context.Context, c net.Conn, address string) (http.RoundTripper, error) {
	var handed atomic.Bool
	tr := &http.Transport{
		DisableCompression: true, MaxResponseHeaderBytes: 16 << 10,
		HTTP2: &http.HTTP2Config{MaxReadFrameSize: 16 << 10,
			MaxReceiveBufferPerConnection: 512 << 10, MaxReceiveBufferPerStream: 128 << 10},
		Protocols: new(http.Protocols),
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			if !handed.CompareAndSwap(false, true) {
				return nil, errors.New("HTTP carrier cannot replace its TLS connection")
			}
			return c, nil
		},
	}
	tr.Protocols.SetHTTP2(true)
	return tr.NewClientConn(ctx, "https", address)
}
