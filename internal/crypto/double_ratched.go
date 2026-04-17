package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// DoubleRatchetSession manages the full Post-Compromise and Forward Secrecy state.
type DoubleRatchetSession struct {
	mu sync.Mutex

	rootChain *RootChain
	sendChain *KDFChain
	recvChain *KDFChain

	dhSendPriv, dhSendPub, dhRecvPub []byte // The remote peer's last known ephemeral public key

	sendMessageNumber uint32
	recvMessageNumber uint32
	skippedKeys       map[uint32][]byte // Skipped message keys for out-of-order delivery
}

// NewDoubleRatchetSession initializes the state machine.
// In a real flow, this is called immediately after the X3DH handshake completes.
func NewDoubleRatchetSession(rootKey, localPriv, localPub, remotePub []byte) *DoubleRatchetSession {
	// For simplicity in initialization, we start with empty KDF chains.
	// The first Encrypt/Decrypt call will immediately trigger a Root step to populate them.
	return &DoubleRatchetSession{
		rootChain:         NewRootChain(rootKey),
		sendChain:         &KDFChain{}, // Will be populated on next step
		recvChain:         &KDFChain{}, // Will be populated on next step
		dhSendPriv:        localPriv,
		dhSendPub:         localPub,
		dhRecvPub:         remotePub,
		sendMessageNumber: 0,
		recvMessageNumber: 1, // First expected message is 1
		skippedKeys:       make(map[uint32][]byte),
	}
}

// Encrypt ratchets the symmetric send chain and locks the payload.
// It returns the ciphertext and our current DH public key to be attached to the header.
func (s *DoubleRatchetSession) Encrypt(plaintext []byte) ([]byte, []byte, uint32, uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If our send chain is empty, we must establish it by mixing our current DH keys.
	if len(s.sendChain.chainKey) == 0 {
		if err := s.stepRootChain(); err != nil {
			return nil, nil, 0, 0, err
		}
	}

	// We use the same SymmetricSession logic we built previously
	symSession := &SymmetricSession{
		sendChain: s.sendChain,
		recvChain: s.recvChain,
	}

	ciphertext, _, _, _, err := symSession.Encrypt(plaintext)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	// Increment message number
	s.sendMessageNumber++

	// For this simplified implementation, previous chain length is always 0
	// In a full implementation, it would be the number of messages sent with the previous key
	previousChainLength := uint32(0)

	// Return the locked payload AND our public key for the message header
	return ciphertext, s.dhSendPub, s.sendMessageNumber, previousChainLength, nil
}

// Decrypt checks the header for a new DH public key, steps the root chain if needed,
// and decrypts the payload.
func (s *DoubleRatchetSession) Decrypt(ciphertext []byte, remoteDHPubKey []byte, messageNumber uint32, previousChainLength uint32) ([]byte, error) {
	if len(remoteDHPubKey) != 32 {
		return nil, errors.New("invalid remote DH public key length")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// The Golden Rule: If the remote key changed, a DH step has occurred.
	if len(s.recvChain.chainKey) == 0 || !bytes.Equal(s.dhRecvPub, remoteDHPubKey) {
		s.dhRecvPub = remoteDHPubKey // Update our knowledge of their key

		// Step the root chain using their new public key and our current private key
		if err := s.stepRootChain(); err != nil {
			return nil, err
		}

		// Because we received a new key, we must immediately rotate our own ephemeral keypair
		// so our NEXT outbound message will force them to step their root chain.
		newPriv := make([]byte, 32)
		rand.Read(newPriv)
		newPub, _ := curve25519.X25519(newPriv, curve25519.Basepoint)

		s.dhSendPriv = newPriv
		s.dhSendPub = newPub

		// Reset message numbers when DH ratchets
		s.recvMessageNumber = 1
		s.sendMessageNumber = 0
	}

	// Handle out-of-order messages
	var msgKey []byte
	var err error
	if messageNumber < s.recvMessageNumber {
		// Old message, use stored key
		var exists bool
		msgKey, exists = s.skippedKeys[messageNumber]
		if !exists {
			return nil, errors.New("message key not found for out-of-order message")
		}
		delete(s.skippedKeys, messageNumber)
	} else {
		// Message is at or ahead of expected
		numRatchets := int(messageNumber - s.recvMessageNumber + 1)
		for i := 0; i < numRatchets-1; i++ {
			skippedKey, err := s.recvChain.Ratchet()
			if err != nil {
				return nil, err
			}
			s.skippedKeys[s.recvMessageNumber+uint32(i)] = skippedKey
		}
		// Ratchet for this message
		msgKey, err = s.recvChain.Ratchet()
		if err != nil {
			return nil, err
		}
		s.recvMessageNumber = messageNumber + 1
	}

	// Decrypt with the key
	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encryptedData := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, errors.New("message authentication failed")
	}

	return plaintext, nil
}

// stepRootChain computes the DH shared secret and rotates all symmetric keys.
// NOTE: stepRootChain assumes the caller holds s.mu.
func (s *DoubleRatchetSession) stepRootChain() error {
	// Compute DH shared secret: Our Private + Their Public
	sharedSecret, err := curve25519.X25519(s.dhSendPriv, s.dhRecvPub)
	if err != nil {
		return err
	}

	// Mix the secret into the Root Chain to get a brand new symmetric key
	newSymmetricKey, err := s.rootChain.Step(sharedSecret)
	if err != nil {
		return err
	}

	// Reset both the send and receive KDF chains with this fresh entropy
	s.sendChain = NewKDFChain(newSymmetricKey)

	// In a full implementation, Send/Recv keys are usually separated by an additional KDF step,
	// but for this phase, initializing both off the new symmetric key fulfills the rotation requirement.
	s.recvChain = NewKDFChain(newSymmetricKey)

	return nil
}
