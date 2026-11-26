package proxy

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/stretchr/testify/require"
)

// A client that CONNECTs to an IP address sends no SNI; the tunnel's leaf is
// then issued for the CONNECT target's host (as an IP SAN), not refused.
func TestTunnelCertificateFallsBackToTarget(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 10, time.Hour)
	require.NoError(t, err)
	p := &Proxy{certCache: cache}

	get := p.tunnelCertificate("192.168.1.1:443")

	cert, err := get(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.Empty(t, cert.Leaf.DNSNames)
	require.Equal(t, []net.IP{net.ParseIP("192.168.1.1").To4()}, []net.IP{cert.Leaf.IPAddresses[0].To4()})

	// SNI, when sent, still wins.
	cert, err = get(&tls.ClientHelloInfo{ServerName: "example.com"})
	require.NoError(t, err)
	require.Equal(t, []string{"example.com"}, cert.Leaf.DNSNames)

	// Without a tunnel target there is still nothing to issue for.
	_, err = p.getCertificate(&tls.ClientHelloInfo{})
	require.ErrorContains(t, err, "no SNI")
}
