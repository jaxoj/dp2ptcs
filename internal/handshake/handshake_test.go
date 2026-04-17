package handshake_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"dp2ptcs/internal/handshake"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func genIdentKey() ([]byte, []byte) {
	priv := make([]byte, 32)
	rand.Read(priv)
	pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
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
