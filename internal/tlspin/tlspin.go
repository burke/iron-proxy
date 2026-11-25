// Package tlspin lets chosen upstream hosts be trusted by the SHA-256 of
// their certificate's public key instead of by a CA chain: for appliances
// with self-signed certificates (a router's admin API, say) that would
// otherwise need certificate checks turned off. Every other host is verified
// against the roots exactly as crypto/tls does by default.
package tlspin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Pin trusts Host's certificate when its SubjectPublicKeyInfo hashes to SHA256.
type Pin struct {
	Host   string `yaml:"host"`
	SHA256 string `yaml:"sha256"` // standard base64 of sha256(SPKI DER)
}

// Pins maps a lower-case host (name or IP, no port) to its SPKI hash.
type Pins map[string][]byte

// Parse checks pins from config.
func Parse(in []Pin) (Pins, error) {
	out := Pins{}
	for _, p := range in {
		h := strings.ToLower(strings.TrimSpace(p.Host))
		if h == "" || strings.ContainsAny(h, "*:/") {
			return nil, fmt.Errorf("tls.upstream_pins: bad host %q (a host name or IP, no port or wildcard)", p.Host)
		}
		sum, err := base64.StdEncoding.DecodeString(p.SHA256)
		if err != nil || len(sum) != sha256.Size {
			return nil, fmt.Errorf("tls.upstream_pins: %s: sha256 must be base64 of 32 bytes", h)
		}
		out[h] = sum
	}
	return out, nil
}

// Dialer is a context dialer for the raw TCP connection.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// DialTLS returns a TLS dialer over dial. A pinned host is trusted by its key
// alone; every other host is verified against base.RootCAs (nil = the system
// roots) for its name, as crypto/tls does by default. With no NextProtos in
// base it offers h2 and http/1.1.
func DialTLS(dial Dialer, base *tls.Config, pins Pins) Dialer {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		cfg := base.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		if len(cfg.NextProtos) == 0 {
			cfg.NextProtos = []string{"h2", "http/1.1"}
		}
		if want, ok := pins[strings.ToLower(strings.Trim(host, "[]"))]; ok {
			cfg.InsecureSkipVerify = true //nolint:gosec // the key is checked against its pin below
			cfg.VerifyConnection = func(cs tls.ConnectionState) error { return checkPin(host, cs, want) }
		}
		raw, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, cfg)
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return conn, nil
	}
}

func checkPin(host string, cs tls.ConnectionState, want []byte) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("tlspin: no peer certificate")
	}
	got := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return fmt.Errorf("tlspin: %s: certificate key does not match its pin", host)
	}
	return nil
}
