package tlspin

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func client(pins Pins, _ string) *http.Client {
	var d net.Dialer
	dial := DialTLS(d.DialContext, &tls.Config{MinVersion: tls.VersionTLS12}, pins)
	return &http.Client{Transport: &http.Transport{DialTLSContext: dial, ForceAttemptHTTP2: true}}
}

func TestPinnedSelfSignedHostIsTrusted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	host, _ := url.Parse(srv.URL)
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	pins, err := Parse([]Pin{{Host: host.Hostname(), SHA256: base64.StdEncoding.EncodeToString(sum[:])}})
	require.NoError(t, err)

	resp, err := client(pins, "").Get(srv.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)
}

func TestWrongPinIsRefused(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	host, _ := url.Parse(srv.URL)
	pins, err := Parse([]Pin{{Host: host.Hostname(), SHA256: base64.StdEncoding.EncodeToString(make([]byte, 32))}})
	require.NoError(t, err)
	_, err = client(pins, "").Get(srv.URL)
	require.ErrorContains(t, err, "does not match its pin")
}

func TestUnpinnedHostStillNeedsAChain(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	pins, err := Parse([]Pin{{Host: "other.example", SHA256: base64.StdEncoding.EncodeToString(make([]byte, 32))}})
	require.NoError(t, err)
	_, err = client(pins, "").Get(srv.URL)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "pin")
}

func TestParseRejectsBadPins(t *testing.T) {
	for _, p := range []Pin{{Host: "*.x", SHA256: "AA=="}, {Host: "h:443", SHA256: "AA=="}, {Host: "h", SHA256: "AA=="}, {Host: "", SHA256: ""}} {
		_, err := Parse([]Pin{p})
		require.Error(t, err, "%+v", p)
	}
}
