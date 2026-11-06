// tlscover supplies an owned TLS 1.3 endpoint for controlled REALITY benchmarks.
// It is a real HTTPS server, not a claim of traffic indistinguishability.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:39443", "listen address")
	cert := flag.String("cert", "", "certificate path")
	key := flag.String("key", "", "private key path")
	flag.Parse()
	srv := &http.Server{Addr: *listen, ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("PROTO-X owned TLS test origin\n"))
		})}
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}
