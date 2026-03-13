package transport_test

import (
	"context"
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

func TestQUICTransport_StreamMultiplexing(t *testing.T) {
	tlsCon := generateTestTLSConfig()
	quicTransport := transport.NewQUICTransport(tlsCon)

	listener, err := quicTransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()

	payload := []byte("TACTICAL-ECHO-PAYLOAD")
	errChan := make(chan error, 1)

	// Recieve Goroutine
	go func() {
		// Accept the incoming QUIC connection
		serverConn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		defer serverConn.Close()

		// Accept multiplexer stream
		stream, err := serverConn.AcceptStream(context.Background())
		if err != nil {
			errChan <- err
			return
		}
		defer stream.Close()

		// Read the payload
		buff := make([]byte, 1024)
		n, err := stream.Read(buff)
		if err != nil {
			errChan <- err
			return
		}

		if string(buff[:n]) != string(payload) {
			errChan <- err // Payload mismatch
			return
		}
		errChan <- nil
	}()

	// Sender (Dialer)
	addr := listener.Addr().String()
	clientConn, err := quicTransport.Dial(addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	// Open the bidirectional stream over the established connection
	clientStream, err := clientConn.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	defer clientStream.Close()

	// Write the payload
	_, err = clientStream.Write(payload)
	if err != nil {
		t.Fatalf("failed to write the payload into the stream: %v", err)
	}

	if receiverErr := <-errChan; receiverErr != nil {
		t.Fatalf("receiver encountered an error: %v", receiverErr)
	}
}
