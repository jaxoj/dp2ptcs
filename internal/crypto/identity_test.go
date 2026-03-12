package crypto_test

import (
	"bytes"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"testing"
)

func TestGenerateIdentity_Sucess(t *testing.T) {
	// Arrange: Injecting standard crypto read for the actual test
	entropy := rand.Reader

	// Act: Generate identity
	identity, err := crypto.GenerateIdentity(entropy)
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	if identity == nil {
		t.Fatal("Generated identity is nil")
	}

	if len(identity.PrivateKey) == 0 {
		t.Fatal("Generated identity has an empty private key")
	}

	if len(identity.NodeID) != 32 { // SHA-256 produces a 32-byte hash
		t.Fatalf("Generated identity has an invalid NodeID length: expected 32 bytes, got %d bytes", len(identity.NodeID))
	}
}

func TestGenerateIdentity_FailingEntropy(t *testing.T) {
	// Arrange: Injecting a reader that returns EOF immediatly
	badEntropy := bytes.NewReader([]byte{})

	// Act
	_, err := crypto.GenerateIdentity(badEntropy)
	if err == nil {
		t.Fatal("Expected error when generating identity with bad entropy, but got nil")
	}
}
