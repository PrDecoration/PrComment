package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	p, err := filepath.Abs(filepath.Join("run", "docker", "plugins"))
	if err != nil {
		panic(err)
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		panic(err)
	}
	l, err := net.Listen("unix", filepath.Join(p, "basic.sock"))
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1.1+json")
		fmt.Println(w, `{"Implements": ["dummy"]}`)
	})

	// Configure TLS with secure settings to prevent plain text transport
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12, // Enforce TLS 1.2 as minimum
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	server := http.Server{
		Addr:              l.Addr().String(),
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second, // This server is not for production code; picked an arbitrary timeout to satisfy gosec (G112: Potential Slowloris Attack)
		TLSConfig:         tlsConfig,
	}

	// Use TLS certificates - in production, load from secure storage
	// For now, expect cert.pem and key.pem in the current directory or use environment variables
	certFile := os.Getenv("TLS_CERT_FILE")
	if certFile == "" {
		certFile = "cert.pem"
	}
	keyFile := os.Getenv("TLS_KEY_FILE")
	if keyFile == "" {
		keyFile = "key.pem"
	}

	// ServeTLS provides encrypted communication, preventing Man-in-the-Middle attacks
	if err := server.ServeTLS(l, certFile, keyFile); err != nil {
		panic(err)
	}
}
