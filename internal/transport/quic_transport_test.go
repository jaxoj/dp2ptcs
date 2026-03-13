package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"dp2ptcs/internal/transport"
	"math/big"
	"testing"
	"time"
)

// generateTestTLSConfig creates an ephemeral Ed25519-backed mTLS configuration.
// In a zero-trust architecture, both client and server mandate these certificates.
func generateTestTLSConfig() *tls.Config {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Tactical Node"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		NextProtos:         []string{"tactical-comms-v1"},
		InsecureSkipVerify: true, // For localized testing only
	}
}

func TestQUICTransport_DialAndListen_Success(t *testing.T) {
	tlsConf := generateTestTLSConfig()
	quicTransport := transport.NewQUICTransport(tlsConf)

	listener, err := quicTransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	// Dial the listener we just created
	// We run the Accept() in a goroutine so it doesn't block Dial()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			conn.Close()
		}
	}()

	// We need the dynamically assigned port from the listener to dial it
	add := listener.Addr().String()
	conn, err := quicTransport.Dial(add)

	if err != nil {
		t.Fatalf("expected successful dial, got %v", err)
	}
	if conn == nil {
		t.Fatal("expected a valid connection object")
	}

	conn.Close()
}
