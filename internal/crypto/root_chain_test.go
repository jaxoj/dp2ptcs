package crypto_test

import (
	"bytes"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestRootChain_DHRatchet_HealsConnection(t *testing.T) {
	// Alice and Bob start with the exact same Root Key
	initialRootKey := bytes.Repeat([]byte{0x55}, 32)
	aliceRoot := crypto.NewRootChain(initialRootKey)
	bobRoot := crypto.NewRootChain(initialRootKey)

	// Generate Alice's new ephermal DH keypair
	alicePriv := make([]byte, 32)
	rand.Read(alicePriv)
	alicePub, _ := curve25519.X25519(alicePriv, curve25519.Basepoint)

	// Generate Bob's new ephermal DH keypair
	bobPriv := make([]byte, 32)
	rand.Read(bobPriv)
	bobPub, _ := curve25519.X25519(bobPriv, curve25519.Basepoint)

	// Alice computes the shared secret using her Private and Bob's Public
	aliceSecret, _ := curve25519.X25519(alicePriv, bobPub)

	// Bob computes the shared secret using his Private and Alice's Public
	bobSecret, _ := curve25519.X25519(bobPriv, alicePub)

	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Fatal("DH math failed: shared secrets do not match")
	}

	// Step both root chains forward using the new shared secret
	aliceNewChainKey, errA := aliceRoot.Step(aliceSecret)
	bobNewChainKey, errB := bobRoot.Step(bobSecret)

	if errA != nil || errB != nil {
		t.Fatalf("failed to step root chain")
	}

	// The output Chain Keys must perfectly match, allowing symmetric communication to resume
	if !bytes.Equal(aliceNewChainKey, bobNewChainKey) {
		t.Errorf("expected Root Chains to produce identical Chain Keys, got distinct outputs")
	}

	// The new Chain Key must not equal the initial Root Key (proving state rotation)
	if bytes.Equal(aliceNewChainKey, initialRootKey) {
		t.Fatal("CRITICAL: Root chain failed to rotate; output key matches input key")
	}
}
