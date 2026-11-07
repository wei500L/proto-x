//go:build !go1.27

package carrier

import (
	"context"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

func newWebHTTP2Conn(_ context.Context, c net.Conn, _ string) (http.RoundTripper, error) {
	t1 := &http.Transport{HTTP2: &http.HTTP2Config{
		MaxReceiveBufferPerConnection: 512 << 10, MaxReceiveBufferPerStream: 128 << 10}}
	tr, err := http2.ConfigureTransports(t1)
	if err != nil {
		return nil, err
	}
	tr.DisableCompression = true
	tr.MaxReadFrameSize = 16 << 10
	tr.MaxHeaderListSize = 16 << 10
	return tr.NewClientConn(c)
}
