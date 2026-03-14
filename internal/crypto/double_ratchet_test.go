package crypto_test

import (
	"bytes"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func generateKeyPair() (priv []byte, pub []byte) {
	priv = make([]byte, 32)
	rand.Read(priv)
	pub, _ = curve25519.X25519(priv, curve25519.Basepoint)
	return priv, pub
}

func TestDoubleRatchetSession_RatchetStepAndDecrypt(t *testing.T) {
	// Simulate the output of an X3DH Handshake
	initialRootKey := bytes.Repeat([]byte{0x99}, 32)

	// Generate initial keypairs
	alicePriv, alicePub := generateKeyPair()
	bobPriv, bobPub := generateKeyPair()

	// Alice initiates. She knows Bob's public key (DHr) and has her own (DHs)
	aliceSession := crypto.NewDoubleRatchetSession(initialRootKey, alicePriv, alicePub, bobPub)

	// Bob receives. He knows Alice's public key (DHr) and has his own (DHs)
	bobSession := crypto.NewDoubleRatchetSession(initialRootKey, bobPriv, bobPub, alicePub)

	originalMsg := []byte("MOVE_TO_WAYPOINT_ALPHA")

	// Alice encrypts. This will use her current DHs key.
	ciphertext, attachedPubKey, err := aliceSession.Encrypt(originalMsg)
	if err != nil {
		t.Fatalf("Alice failed to encrypt: %v", err)
	}

	// Bob receives the message over the network and decrypts it.
	// He passes the ciphertext AND Alice's attached public key.
	decryptedMsg, err := bobSession.Decrypt(ciphertext, attachedPubKey)
	if err != nil {
		t.Fatalf("Bob failed to decrypt: %v", err)
	}

	// Bob successfully derived the keys and decrypted the message
	if !bytes.Equal(originalMsg, decryptedMsg) {
		t.Errorf("expected %s, got %s", originalMsg, decryptedMsg)
	}
}
