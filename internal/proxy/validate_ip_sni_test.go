package proxy

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// A client that CONNECTs to an IP address sends no SNI, so an empty SNI beside
// an IP Host is accepted; a present SNI must still match, and a hostname Host
// still needs its SNI.
func TestValidateRequestIPHostWithoutSNI(t *testing.T) {
	p := &Proxy{logger: slog.Default()}

	req := httptest.NewRequest(http.MethodGet, "https://192.168.1.1/x", nil)
	req.TLS = &tls.ConnectionState{ServerName: ""}
	reason, _ := p.validateRequest(req)
	require.Equal(t, "", reason)

	req.TLS = &tls.ConnectionState{ServerName: "other.example"}
	reason, _ = p.validateRequest(req)
	require.Equal(t, "sni_host_mismatch", reason)

	req = httptest.NewRequest(http.MethodGet, "https://example.com/x", nil)
	req.TLS = &tls.ConnectionState{ServerName: ""}
	reason, _ = p.validateRequest(req)
	require.Equal(t, "sni_host_mismatch", reason)
}
