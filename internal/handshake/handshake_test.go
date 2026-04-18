package handshake_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"dp2ptcs/internal/handshake"
	"io"
	"net"
	"testing"
	"time"
)

func genIdentKey() (ed25519.PrivateKey, ed25519.PublicKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv, pub
}

func TestHandshakeProtocol_EstablishSecureSession(t *testing.T) {
	// Create Long-Term Identity Keys for Node A and Node B
	alicePriv, alicePub := genIdentKey()
	bobPriv, bobPub := genIdentKey()

	// net.Pipe creates a synchronous, in-memory full duplex network connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	aliceHandshake := handshake.NewHandshakeProtocol(alicePriv, alicePub)
	bobHandshake := handshake.NewHandshakeProtocol(bobPriv, bobPub)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var aliceSession, bobSession crypto.SecureSession
	var errA, errB error

	// Run the Responder (Bob) in a goroutine
	done := make(chan struct{})
	go func() {
		bobSession, _, errB = bobHandshake.Respond(ctx, serverConn)
		close(done)
	}()

	// Run the Initiator (Alice) on the main thread
	aliceSession, errA = aliceHandshake.Initiate(ctx, clientConn)

	<-done

	if errA != nil {
		t.Fatalf("Alice failed handshake: %v", errA)
	}
	if errB != nil {
		t.Fatalf("Bob failed handshake: %v", errB)
	}
	if aliceSession == nil || bobSession == nil {
		t.Fatal("Handshake did not return valid sessions")
	}

	// Final verification: Ensure the sessions can actually talk to each other
	msg := []byte("HANDSHAKE_SUCCESS")
	ciphertext, dhHeader, msgNum, prevLen, _ := aliceSession.Encrypt(msg)
	decrypted, err := bobSession.Decrypt(ciphertext, dhHeader, msgNum, prevLen)

	if err != nil || !bytes.Equal(msg, decrypted) {
		t.Fatalf("Post-handshake encryption failed. The root keys must have mismatched.")
	}
}

type partialHandshakeReader struct {
	data []byte
	sent bool
}

func (p *partialHandshakeReader) Read(b []byte) (int, error) {
	if p.sent {
		return 0, io.EOF
	}
	n := copy(b, p.data)
	p.data = p.data[n:]
	if len(p.data) == 0 {
		p.sent = true
		return n, io.EOF
	}
	return n, nil
}

func (p *partialHandshakeReader) Write(b []byte) (int, error) {
	return len(b), nil
}

func TestHandshakeProtocol_ReadFromPartialStreamFails(t *testing.T) {
	_, alicePub := genIdentKey()
	bobPriv, bobPub := genIdentKey()

	stream := &partialHandshakeReader{data: alicePub}
	bobHandshake := handshake.NewHandshakeProtocol(bobPriv, bobPub)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err := bobHandshake.Respond(ctx, stream)
	if err == nil {
		t.Fatal("expected error when peer closes stream during handshake")
	}
}
