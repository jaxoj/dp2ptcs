package crypto_test

import (
	"bytes"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"fmt"
	"sync"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func generateKeyPair(t *testing.T) (priv []byte, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	pub, _ = curve25519.X25519(priv, curve25519.Basepoint)
	return priv, pub
}

func TestDoubleRatchetSession_RatchetStepAndDecrypt(t *testing.T) {
	// Simulate the output of an X3DH Handshake
	initialRootKey := bytes.Repeat([]byte{0x99}, 32)

	// Generate initial keypairs
	alicePriv, alicePub := generateKeyPair(t)
	bobPriv, bobPub := generateKeyPair(t)

	// Alice initiates. She knows Bob's public key (DHr) and has her own (DHs)
	aliceSession := crypto.NewDoubleRatchetSession(initialRootKey, alicePriv, alicePub, bobPub)

	// Bob receives. He knows Alice's public key (DHr) and has his own (DHs)
	bobSession := crypto.NewDoubleRatchetSession(initialRootKey, bobPriv, bobPub, alicePub)

	originalMsg := []byte("MOVE_TO_WAYPOINT_ALPHA")

	// Alice encrypts. This will use her current DHs key.
	ciphertext, attachedPubKey, msgNum, prevLen, err := aliceSession.Encrypt(originalMsg)
	if err != nil {
		t.Fatalf("Alice failed to encrypt: %v", err)
	}

	// Bob receives the message over the network and decrypts it.
	// He passes the ciphertext AND Alice's attached public key.
	decryptedMsg, err := bobSession.Decrypt(ciphertext, attachedPubKey, msgNum, prevLen)
	if err != nil {
		t.Fatalf("Bob failed to decrypt: %v", err)
	}

	// Bob successfully derived the keys and decrypted the message
	if !bytes.Equal(originalMsg, decryptedMsg) {
		t.Errorf("expected %s, got %s", originalMsg, decryptedMsg)
	}
}

func TestDoubleRatchetSession_ConcurrentEncryptDecrypt(t *testing.T) {
	initialRootKey := bytes.Repeat([]byte{0x42}, 32)
	alicePriv, alicePub := generateKeyPair(t)
	bobPriv, bobPub := generateKeyPair(t)

	alice := crypto.NewDoubleRatchetSession(initialRootKey, alicePriv, alicePub, bobPub)
	bob := crypto.NewDoubleRatchetSession(initialRootKey, bobPriv, bobPub, alicePub)

	const goroutines = 8
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Producer goroutines: Alice encrypts repeatedly
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				msg := []byte(fmt.Sprintf("msg-%d-%d", id, i))
				ct, pub, msgNum, prevLen, err := alice.Encrypt(msg)
				if err != nil {
					t.Errorf("alice encrypt error: %v", err)
					return
				}
				// Simulate network delivery to Bob
				if _, err := bob.Decrypt(ct, pub, msgNum, prevLen); err != nil {
					t.Errorf("bob decrypt error: %v", err)
					return
				}
			}
		}(g)
	}

	// Producer goroutines: Bob encrypts repeatedly and Alice decrypts
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				msg := []byte(fmt.Sprintf("bmsg-%d-%d", id, i))
				ct, pub, msgNum, prevLen, err := bob.Encrypt(msg)
				if err != nil {
					t.Errorf("bob encrypt error: %v", err)
					return
				}
				if _, err := alice.Decrypt(ct, pub, msgNum, prevLen); err != nil {
					t.Errorf("alice decrypt error: %v", err)
					return
				}
			}
		}(g)
	}

	wg.Wait()
}
