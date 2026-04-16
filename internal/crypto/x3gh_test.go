package crypto_test

import (
	"bytes"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// helper to generate X25519 keypairs
func genKey() ([]byte, []byte) {
	priv := make([]byte, 32)
	rand.Read(priv)
	pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
	return priv, pub
}

func TestX3DH_ComputeSharedSecret_Matches(t *testing.T) {
	// Generate Identity Keys (Long-term)
	aliceIdentPriv, aliceIdentPub := genKey()
	bobIdentPriv, bobIdentPub := genKey()

	// Generate Ephemeral Keys (Short-term / Prekeys)
	aliceEphemPriv, aliceEphemPub := genKey()
	bobEphemPriv, bobEphemPub := genKey()

	// Alice computes X3DH as the INITIATOR
	// She uses her private keys and Bob's public keys
	aliceRootKey, err := crypto.InitiateX3DH(
		aliceIdentPriv, aliceEphemPriv,
		bobIdentPub, bobEphemPub,
	)
	if err != nil {
		t.Fatalf("Alice failed to compute X3DH: %v", err)
	}

	// Bob computes X3DH as the RESPONDER
	// He uses his private keys and Alice's public keys
	bobRootKey, err := crypto.RespondX3DH(
		bobIdentPriv, bobEphemPriv,
		aliceIdentPub, aliceEphemPub,
	)
	if err != nil {
		t.Fatalf("Bob failed to compute X3DH: %v", err)
	}

	// The resulting initial Root Keys must be identical
	if !bytes.Equal(aliceRootKey, bobRootKey) {
		t.Fatal("X3DH computation failed: Initiator and Responder derived different root keys")
	}

	if len(aliceRootKey) != 32 {
		t.Errorf("expected 32-byte root key, got %d bytes", len(aliceRootKey))
	}
}
