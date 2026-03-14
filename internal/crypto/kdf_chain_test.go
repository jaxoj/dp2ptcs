package crypto_test

import (
	"bytes"
	"dp2ptcs/internal/crypto"
	"testing"
)

func TestKDFChain_Ratchet_ForwardSecrecy(t *testing.T) {
	// Arrange
	// A 32-byte initial root key (simulating the output of an initial Diffie-Hellman exchange)
	initialKey := bytes.Repeat([]byte{0x01}, 32)
	chain := crypto.NewKDFChain(initialKey)

	// Act: Step the ratchet forward twice
	msgKey1, err1 := chain.Ratchet()
	if err1 != nil {
		t.Fatalf("first ratchet failed: %v", err1)
	}

	msgKey2, err2 := chain.Ratchet()
	if err2 != nil {
		t.Fatalf("second ratchet failed: %v", err2)
	}

	// Assert
	// 1. Keys must be exactly 32 bytes for AES-256 / ChaCha20
	if len(msgKey1) != 32 || len(msgKey2) != 32 {
		t.Errorf("expected message keys to be exactly 32 bytes")
	}

	// 2. Forward Secrecy Check: Keys must NEVER repeat
	if bytes.Equal(msgKey1, msgKey2) {
		t.Fatal("CRITICAL SECURITY FAILURE: Ratchet failed to rotate keys; msgKey1 and msgKey2 are identical")
	}

	// 3. Independence Check: The output message keys must not expose the initial chain key
	if bytes.Equal(initialKey, msgKey1) || bytes.Equal(initialKey, msgKey2) {
		t.Fatal("CRITICAL SECURITY FAILURE: Ratchet leaked the internal chain key directly into the message key")
	}
}
