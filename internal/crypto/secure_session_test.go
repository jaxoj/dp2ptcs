package crypto_test

import (
	"bytes"
	"dp2ptcs/internal/crypto"
	"testing"
)

func TestSummetricSession_EncryptDecrypt(t *testing.T) {
	// Create identical root keys for the simulation
	rootKeyAtoB := bytes.Repeat([]byte{0xAA}, 32)
	rootKeyBtoA := bytes.Repeat([]byte{0xBB}, 32)

	// Alice's session: Sends with A->B, Receives with B->A
	aliceSession := crypto.NewSymmetricSession(rootKeyAtoB, rootKeyBtoA)

	// Bob's session: Sends with B->A, Receives with A->B (mirrored)
	bobSession := crypto.NewSymmetricSession(rootKeyBtoA, rootKeyAtoB)

	originalPlaintext := []byte("TARGET_COORDINATES_LOCKED")

	// Alice encrypts
	ciphertext, _, _, _, err := aliceSession.Encrypt(originalPlaintext)
	if err != nil {
		t.Fatalf("Alice failed to encrypt: %v", err)
	}

	// Ensure encryption actually altered the data
	if bytes.Equal(ciphertext, originalPlaintext) {
		t.Fatal("encryption failed: ciphertext matches plaintext")
	}

	// Bob decrypts
	decryptedPlaintext, err := bobSession.Decrypt(ciphertext, nil, 0, 0)
	if err != nil {
		t.Fatalf("Bob failed to decrypt: %v", err)
	}

	// Bob's decrypted text must match Alice's original text
	if !bytes.Equal(originalPlaintext, decryptedPlaintext) {
		t.Errorf("expected %s, got %s", originalPlaintext, decryptedPlaintext)
	}
}
