package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"claude-environment-check/internal/probe"
)

func main() {
	listen := flag.String("listen", ":8443", "HTTPS/HTTP listen address")
	cert := flag.String("cert", "", "TLS certificate PEM")
	key := flag.String("key", "", "TLS private key PEM")
	dnsListen := flag.String("dns-listen", ":53", "authoritative DNS UDP/TCP address; empty disables")
	zone := flag.String("dns-zone", "", "delegated authoritative zone")
	answer := flag.String("dns-answer-ip", "192.0.2.1", "A record answer")
	geoCity := flag.String("geoip-city", "", "GeoLite2 City database path")
	geoASN := flag.String("geoip-asn", "", "GeoLite2 ASN database path")
	secret := flag.String("secret", os.Getenv("PROBE_SECRET"), "HMAC secret (or PROBE_SECRET)")
	flag.Parse()
	secretBytes := []byte(*secret)
	if len(secretBytes) < 32 {
		secretBytes = make([]byte, 32)
		_, _ = rand.Read(secretBytes)
		fmt.Fprintln(os.Stderr, "warning: generated ephemeral probe secret:", base64.RawURLEncoding.EncodeToString(secretBytes))
	}
	s, err := probe.New(probe.Config{Zone: *zone, AnswerIPv4: net.ParseIP(*answer), TTL: 10 * time.Minute, Secret: secretBytes, GeoIPCityPath: *geoCity, GeoIPASNPath: *geoASN})
	if err != nil {
		fatal(err)
	}
	defer s.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *dnsListen != "" && *zone != "" {
		go func() {
			if err := s.RunDNS(ctx, *dnsListen); err != nil {
				fmt.Fprintln(os.Stderr, "DNS:", err)
				stop()
			}
		}()
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fatal(err)
	}
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, ConnContext: s.ConnContext}
	go func() {
		var e error
		if *cert != "" && *key != "" {
			e = srv.ServeTLS(probe.SniffListener(ln), *cert, *key)
		} else {
			fmt.Fprintln(os.Stderr, "warning: serving plain HTTP; use --cert and --key in production")
			e = srv.Serve(ln)
		}
		if e != nil && e != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, e)
			stop()
		}
	}()
	fmt.Printf("probe listening on %s (DNS zone %q)\n", *listen, strings.TrimSpace(*zone))
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
