package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/netutil"
	"proto-x/internal/carrier"
	"proto-x/internal/cover"
)

// makeCert creates an owned, private local CA and a hostname-verified test leaf.
// Nothing is added to the system trust store. The CA signing key is not saved.
func makeCert(output string) error {
	if output == "" {
		return errors.New("new private certificate directory is required")
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return err
	}
	serial := func() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caSerial, err := serial()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "Local recognition fixture CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true,
		BasicConstraintsValid: true, MaxPathLenZero: true}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leafSerial, err := serial()
	if err != nil {
		return err
	}
	// This is a reserved, locally generated test name, not a discovered domain.
	name := "fixture-" + leafSerial.Text(16) + ".test"
	outerName := "cover-" + leafSerial.Text(16) + ".test"
	leaf := &x509.Certificate{SerialNumber: leafSerial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name, outerName},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return err
	}
	files := map[string]*pem.Block{
		"ca.pem":   {Type: "CERTIFICATE", Bytes: caDER},
		"leaf.pem": {Type: "CERTIFICATE", Bytes: leafDER},
		"key.pem":  {Type: "PRIVATE KEY", Bytes: keyDER},
	}
	for name, block := range files {
		if err := os.WriteFile(filepath.Join(output, name), pem.EncodeToMemory(block), 0600); err != nil {
			return err
		}
	}
	pin := sha256.Sum256(leafDER)
	if err := writeJSON(filepath.Join(output, "identity.json"), map[string]any{
		"server_name": name, "ech_public_name": outerName, "ca_file": filepath.Join(output, "ca.pem"),
		"cert_file": filepath.Join(output, "leaf.pem"), "key_file": filepath.Join(output, "key.pem"),
		"pin_sha256": hex.EncodeToString(pin[:]), "generated_utc": now, "expires_utc": leaf.NotAfter,
		"trust_scope": "explicit CA file in local probes only; system trust unchanged",
	}, true); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "private_fixture_certificate_created"})
}

// ordinary normally reuses candidate TLS/HTTP/QUIC options and cover.Site but
// has no Gate, WebHub or authenticated route. stock_go skips the candidate TLS
// helper and uses default HTTP2/QUIC options. Neither models all real websites.
func ordinary(c config) error {
	if c.ReadyFile == "" || (c.TCPListen == "" && c.UDPListen == "") {
		return errors.New("ordinary fixture requires ready_file and at least one listener")
	}
	if c.TLSProfile != "" && c.TLSProfile != "candidate_options" && c.TLSProfile != "stock_go" {
		return errors.New("ordinary tls_profile must be candidate_options or stock_go")
	}
	stock := c.TLSProfile == "stock_go"
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return err
	}
	site, err := cover.NewSite(c.SiteRoot)
	if err != nil {
		return err
	}
	defer site.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	errs := make(chan error, 4)
	var running sync.WaitGroup
	closers := []func(){}
	defer func() {
		cancel()
		for _, close := range closers {
			close()
		}
		running.Wait()
	}()
	ready := map[string]any{"pid": os.Getpid(), "label": c.Label, "tool": buildIdentity(),
		"handler":              "cover.Site directly, without authentication or a proxy route",
		"tls_and_http_options": "same exported TLS/QUIC configuration and listener limits as candidate"}
	if stock {
		ready["tls_and_http_options"] = "stock crypto/tls and net/http HTTP2 defaults; stock quic-go QUIC defaults"
	}
	options := carrier.WebTLSServerOptions{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
	serverTLS := func(o carrier.WebTLSServerOptions) (*tls.Config, error) {
		if stock {
			return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: o.NextProtos}, nil
		}
		return carrier.WebServerTLS(o)
	}
	if c.TCPListen != "" {
		tc, err := serverTLS(options)
		if err != nil {
			return err
		}
		server := &http.Server{Handler: site, TLSConfig: tc, ReadHeaderTimeout: 3 * time.Second,
			IdleTimeout: 20 * time.Second, MaxHeaderBytes: 16 << 10,
			BaseContext: func(net.Listener) context.Context { return ctx }, ErrorLog: log.New(io.Discard, "", 0)}
		if !stock {
			if err := http2.ConfigureServer(server, &http2.Server{MaxConcurrentStreams: 128, MaxReadFrameSize: 16 << 10,
				MaxUploadBufferPerConnection: 512 << 10, MaxUploadBufferPerStream: 128 << 10}); err != nil {
				return err
			}
		}
		ln, err := net.Listen("tcp", c.TCPListen)
		if err != nil {
			return err
		}
		limited := netutil.LimitListener(ln, 16)
		closers = append(closers, func() {
			end, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			_ = server.Shutdown(end)
			_ = server.Close()
			_ = limited.Close()
		})
		ready["tcp_listen"] = ln.Addr().String()
		running.Add(1)
		go func() { defer running.Done(); errs <- server.ServeTLS(limited, "", "") }()
	}
	if c.UDPListen != "" {
		options.NextProtos = []string{"h3"}
		tc, err := serverTLS(options)
		if err != nil {
			return err
		}
		quicConfig := carrier.WebQUICConfig()
		if stock {
			quicConfig = &quic.Config{}
		}
		ln, err := quic.ListenAddr(c.UDPListen, http3.ConfigureTLSConfig(tc), quicConfig)
		if err != nil {
			return err
		}
		server := &http3.Server{Handler: site, MaxHeaderBytes: 16 << 10, IdleTimeout: 20 * time.Second}
		closers = append(closers, func() { _ = ln.Close(); _ = server.Close() })
		ready["udp_listen"] = ln.Addr().String()
		connections := make(chan struct{}, 16)
		running.Add(1)
		go func() {
			defer running.Done()
			for {
				conn, err := ln.Accept(ctx)
				if err != nil {
					errs <- err
					return
				}
				select {
				case connections <- struct{}{}:
					running.Add(1)
					go func() {
						defer running.Done()
						defer func() { <-connections }()
						_ = server.ServeQUICConn(conn)
					}()
				default:
					_ = conn.CloseWithError(0, "")
				}
			}
		}()
	}
	if err := writeJSON(c.ReadyFile, ready, true); err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "ordinary_fixture_ready", "label": c.Label}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		return err
	}
}
