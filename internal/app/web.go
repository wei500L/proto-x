package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/netutil"
	"proto-x/internal/carrier"
	"proto-x/internal/cover"
)

// validateWeb rejects ambiguous role settings before opening any listener.
func (c Config) validateWeb(server bool) error {
	if server && c.ECHConfigFile != "" {
		return errors.New("server requires ech_keys_file, not ech_config_file")
	}
	if !server && c.ECHKeysFile != "" {
		return errors.New("client requires ech_config_file, not ech_keys_file")
	}
	if c.WebPadding != 0 && c.WebPadding != 63 && c.WebPadding != 127 && c.WebPadding != 255 {
		return errors.New("web_padding must be 0, 63, 127 or 255")
	}
	if server && c.ECHKeysFile != "" && c.WebListen == "" && c.HTTP3Listen == "" {
		return errors.New("ECH keys require an HTTP listener")
	}
	if server && (c.WebListen != "" || c.HTTP3Listen != "") && c.CoverDir == "" {
		return errors.New("HTTP listeners require cover_dir")
	}
	return nil
}

func (c Config) webTLS(ep Endpoint) (*tls.Config, error) {
	o := carrier.WebTLSClientOptions{ServerName: ep.ServerName, PinSHA256: c.Pin,
		ExperimentalPinOnly: c.ExperimentalPinOnly, NextProtos: []string{"h2", "http/1.1"}}
	if ep.Network == "h3" {
		o.NextProtos = []string{"h3"}
	}
	if c.CAFile != "" {
		b, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		o.RootCAs = x509.NewCertPool()
		if !o.RootCAs.AppendCertsFromPEM(b) {
			return nil, errors.New("CA file contains no certificates")
		}
	}
	if c.ECHConfigFile != "" {
		b, err := os.ReadFile(c.ECHConfigFile)
		if err != nil {
			return nil, err
		}
		o.ECHConfigList = b
	}
	return carrier.WebClientTLS(o)
}

func (s *Server) serveWeb(ctx context.Context, cert tls.Certificate, errs chan<- error) ([]func(), error) {
	if s.cfg.WebListen == "" && s.cfg.HTTP3Listen == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(s.token)
	if err != nil {
		return nil, err
	}
	gate, err := cover.NewGate(key, cover.Config{Path: s.cfg.WebPath})
	if err != nil {
		return nil, err
	}
	site, err := cover.NewSite(s.cfg.CoverDir)
	if err != nil {
		return nil, err
	}
	var closers []func()
	ok := false
	defer func() {
		if !ok {
			for _, close := range closers {
				close()
			}
			_ = site.Close()
		}
	}()
	hub := &carrier.WebHub{Gate: gate, Site: site, Padding: s.cfg.WebPadding, MaxLinks: s.cfg.MaxSessions + 2,
		Handshake: func(l *carrier.Link) {
			select {
			case s.slots <- struct{}{}:
				defer func() { <-s.slots }()
				s.handshake(ctx, l)
			default:
				_ = l.Close()
			}
		}}
	closers = append(closers, hub.Close)
	o := carrier.WebTLSServerOptions{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
	if s.cfg.ECHKeysFile != "" {
		b, err := os.ReadFile(s.cfg.ECHKeysFile)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &o.ECHKeys); err != nil || len(o.ECHKeys) == 0 {
			return nil, errors.New("invalid ECH server key file")
		}
	}
	if s.cfg.WebListen != "" {
		tc, err := carrier.WebServerTLS(o)
		if err != nil {
			return nil, err
		}
		server := &http.Server{Handler: hub, TLSConfig: tc, ReadHeaderTimeout: 3 * time.Second,
			IdleTimeout: 20 * time.Second, MaxHeaderBytes: 16 << 10,
			BaseContext: func(net.Listener) context.Context { return ctx },
			// HTTP handshake logs can contain peer addresses; keep them out of
			// ordinary service logs rather than exposing deployment identifiers.
			ErrorLog: log.New(io.Discard, "", 0)}
		if err := http2.ConfigureServer(server, &http2.Server{MaxConcurrentStreams: 128, MaxReadFrameSize: 16 << 10,
			MaxUploadBufferPerConnection: 512 << 10, MaxUploadBufferPerStream: 128 << 10}); err != nil {
			return nil, err
		}
		ln, err := net.Listen("tcp", s.cfg.WebListen)
		if err != nil {
			return nil, err
		}
		limited := netutil.LimitListener(ln, 16)
		closers = append(closers, func() { _ = server.Close(); _ = limited.Close() })
		go func() { errs <- server.ServeTLS(limited, "", "") }()
		slog.Info("HTTPS listener ready", "listen", s.cfg.WebListen)
	}
	if s.cfg.HTTP3Listen != "" {
		o.NextProtos = []string{"h3"}
		tc, err := carrier.WebServerTLS(o)
		if err != nil {
			return nil, err
		}
		ln, err := quic.ListenAddr(s.cfg.HTTP3Listen, http3.ConfigureTLSConfig(tc), carrier.WebQUICConfig())
		if err != nil {
			return nil, err
		}
		server := &http3.Server{Handler: hub, MaxHeaderBytes: 16 << 10, IdleTimeout: 20 * time.Second}
		closers = append(closers, func() { _ = ln.Close(); _ = server.Close() })
		connections := make(chan struct{}, 16)
		go func() {
			for {
				c, err := ln.Accept(ctx)
				if err != nil {
					errs <- err
					return
				}
				select {
				case connections <- struct{}{}:
					go func() { defer func() { <-connections }(); _ = server.ServeQUICConn(c) }()
				default:
					_ = c.CloseWithError(0, "")
				}
			}
		}()
		slog.Info("HTTP/3 listener ready", "listen", s.cfg.HTTP3Listen)
	}
	closers = append(closers, func() { _ = site.Close() })
	ok = true
	return closers, nil
}
