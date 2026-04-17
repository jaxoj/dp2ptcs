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

	type networkPayload struct {
		ciphertext []byte
		pubKey     []byte
		msgNum     uint32
		prevLen    uint32
		original   []byte
	}

	// Use channels to decouple the sender and receiver, simulating an asynchronous network.
	aliceToBob := make(chan networkPayload, goroutines*iterations)
	bobToAlice := make(chan networkPayload, goroutines*iterations)

	var wgProduce sync.WaitGroup
	wgProduce.Add(goroutines * 2)

	// Producer: Alice encrypts concurrently
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wgProduce.Done()
			for i := 0; i < iterations; i++ {
				msg := []byte(fmt.Sprintf("msg-a2b-%d-%d", id, i))
				ct, pub, msgNum, prevLen, err := alice.Encrypt(msg)
				if err != nil {
					t.Errorf("alice encrypt error: %v", err)
					return
				}
				aliceToBob <- networkPayload{ct, pub, msgNum, prevLen, msg}
			}
		}(g)
	}

	// Producer: Bob encrypts concurrently
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wgProduce.Done()
			for i := 0; i < iterations; i++ {
				msg := []byte(fmt.Sprintf("msg-b2a-%d-%d", id, i))
				ct, pub, msgNum, prevLen, err := bob.Encrypt(msg)
				if err != nil {
					t.Errorf("bob encrypt error: %v", err)
					return
				}
				bobToAlice <- networkPayload{ct, pub, msgNum, prevLen, msg}
			}
		}(g)
	}

	// Block until all network traffic is generated, then seal the queues.
	wgProduce.Wait()
	close(aliceToBob)
	close(bobToAlice)

	var wgConsume sync.WaitGroup
	wgConsume.Add(2)

	// Consumer: Bob decrypts Alice's messages
	go func() {
		defer wgConsume.Done()
		for payload := range aliceToBob {
			decrypted, err := bob.Decrypt(payload.ciphertext, payload.pubKey, payload.msgNum, payload.prevLen)
			if err != nil {
				t.Errorf("bob decrypt error: %v", err)
				return
			}
			if !bytes.Equal(decrypted, payload.original) {
				t.Errorf("bob payload mismatch: got %s, want %s", decrypted, payload.original)
			}
		}
	}()

	// Consumer: Alice decrypts Bob's messages
	go func() {
		defer wgConsume.Done()
		for payload := range bobToAlice {
			decrypted, err := alice.Decrypt(payload.ciphertext, payload.pubKey, payload.msgNum, payload.prevLen)
			if err != nil {
				t.Errorf("alice decrypt error: %v", err)
				return
			}
			if !bytes.Equal(decrypted, payload.original) {
				t.Errorf("alice payload mismatch: got %s, want %s", decrypted, payload.original)
			}
		}
	}()

	wgConsume.Wait()
}
