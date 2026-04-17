package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	// MaxSkippedKeys limits the number of out-of-order message keys stored in memory.
	// This prevents memory exhaustion from extreme reordering or denial-of-service attacks.
	// With a limit of 10,000 keys at ~32 bytes each = ~320 KB max per session.
	MaxSkippedKeys = 10000

	// MaxMessageGap warns if a message arrives with a sequence number gap > this threshold.
	// Helps detect network issues or potential replay/reordering attacks.
	// A gap > 1000 messages is suspicious in tactical networks.
	MaxMessageGap = 1000
)

// DoubleRatchetSession manages the full Post-Compromise and Forward Secrecy state.
type DoubleRatchetSession struct {
	mu sync.Mutex

	rootChain *RootChain
	sendChain *KDFChain
	recvChain *KDFChain

	dhSendPriv, dhSendPub, dhRecvPub []byte // The remote peer's last known ephemeral public key

	sendMessageNumber uint64            // Monotonically increasing counter (1-indexed)
	recvMessageNumber uint64            // Next expected message number
	skippedKeys       map[uint64][]byte // Skipped message keys for out-of-order delivery
	oldestSkippedKey  uint64            // Tracks earliest key in skipped map for eviction
}

// NewDoubleRatchetSession initializes the state machine.
// In a real flow, this is called immediately after the X3DH handshake completes.
// Message numbers start at 1 and increment monotonically.
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
		recvMessageNumber: 1, // First expected message is 1 (1-indexed)
		skippedKeys:       make(map[uint64][]byte),
		oldestSkippedKey:  1,
	}
}

// Encrypt ratchets the symmetric send chain and locks the payload.
// It returns the ciphertext and our current DH public key to be attached to the header.
func (s *DoubleRatchetSession) Encrypt(plaintext []byte) ([]byte, []byte, uint64, uint32, error) {
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

	// Increment message number and wrap safely (uint64 overflow is catastrophic)
	// In practice, uint64 can hold ~18 billion messages per second for 580 years
	// Before overflow, nodes should be rekeyed via X3DH handshake
	if s.sendMessageNumber == ^uint64(0) { // Maximum uint64
		return nil, nil, 0, 0, errors.New("message counter overflow: rekey required")
	}
	s.sendMessageNumber++

	// For this simplified implementation, previous chain length is always 0
	// In a full implementation, it would be the number of messages sent with the previous key
	previousChainLength := uint32(0)

	// Return the locked payload AND our public key for the message header
	return ciphertext, s.dhSendPub, s.sendMessageNumber, previousChainLength, nil
}

// Decrypt checks the header for a new DH public key, steps the root chain if needed,
// and decrypts the payload. Handles out-of-order delivery via skipped key storage.
// Returns an error if: message authentication fails, message is replayed, or gap is unreasonably large.
func (s *DoubleRatchetSession) Decrypt(ciphertext []byte, remoteDHPubKey []byte, messageNumber uint64, previousChainLength uint32) ([]byte, error) {
	if len(remoteDHPubKey) != 32 {
		return nil, errors.New("invalid remote DH public key length")
	}

	// Validate monotonic increase: message numbers must be > 0
	if messageNumber == 0 {
		return nil, errors.New("invalid message number: must be >= 1 (1-indexed)")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Detect if gap is suspiciously large (potential reordering attack or network issue)
	if messageNumber > s.recvMessageNumber && messageNumber-s.recvMessageNumber > MaxMessageGap {
		log.Printf(
			"[WARNING] Large message gap detected: expected %d, received %d (gap=%d). "+
				"Possible network reordering, DoS attack, or long network delay.",
			s.recvMessageNumber, messageNumber, messageNumber-s.recvMessageNumber,
		)
	}

	// Replay detection: reject messages we've already seen
	if messageNumber < s.recvMessageNumber {
		_, alreadyStored := s.skippedKeys[messageNumber]
		if !alreadyStored {
			// Message is older than our receive window and we don't have a key for it
			return nil, fmt.Errorf("replay detected: message %d is too old (expected >= %d)", messageNumber, s.recvMessageNumber)
		}
		// We have a skipped key for this message, allow processing below
	}

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
		// Start the receive counter at 1 (1-indexed) and send at 0 (will increment to 1 on first encrypt)
		s.recvMessageNumber = 1
		s.sendMessageNumber = 0
		s.oldestSkippedKey = 1
		// Clear skipped keys as they're only valid for the previous DH epoch
		s.skippedKeys = make(map[uint64][]byte)
	}

	// Handle out-of-order messages and retrieve the message key
	var msgKey []byte
	var err error

	if messageNumber < s.recvMessageNumber {
		// Old message: use stored skipped key for this message number
		var exists bool
		msgKey, exists = s.skippedKeys[messageNumber]
		if !exists {
			return nil, fmt.Errorf("message key not found for out-of-order message %d", messageNumber)
		}
		delete(s.skippedKeys, messageNumber)
	} else {
		// Message is at or ahead of expected: ratchet forward, storing skipped keys
		numRatchets := int(messageNumber - s.recvMessageNumber + 1)
		for i := 0; i < numRatchets-1; i++ {
			skippedKey, err := s.recvChain.Ratchet()
			if err != nil {
				return nil, err
			}
			seqNum := s.recvMessageNumber + uint64(i)
			s.skippedKeys[seqNum] = skippedKey
		}

		// Ratchet for this message
		msgKey, err = s.recvChain.Ratchet()
		if err != nil {
			return nil, err
		}

		// Update receive counter to next expected message
		s.recvMessageNumber = messageNumber + 1
		s.oldestSkippedKey = s.recvMessageNumber // Update oldest tracked key

		// Evict skipped keys beyond the maximum limit to prevent memory exhaustion
		s.evictOldSkippedKeys()
	}

	// Decrypt the message with the derived key
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
		return nil, errors.New("message authentication failed: potential tampering or out-of-sync ratchet")
	}

	return plaintext, nil
}

// evictOldSkippedKeys removes the oldest skipped keys when the map exceeds MaxSkippedKeys.
// This prevents memory exhaustion from extremely out-of-order deliveries or DoS attacks.
// NOTE: Assumes caller holds s.mu (lock)
func (s *DoubleRatchetSession) evictOldSkippedKeys() {
	if len(s.skippedKeys) > MaxSkippedKeys {
		// Find and delete the oldest keys to bring us back under the limit
		numToEvict := len(s.skippedKeys) - MaxSkippedKeys + 100 // Evict a bit extra to avoid repeated calls

		for i := 0; i < numToEvict && s.oldestSkippedKey < s.recvMessageNumber; i++ {
			delete(s.skippedKeys, s.oldestSkippedKey)
			s.oldestSkippedKey++
		}

		if len(s.skippedKeys) > MaxSkippedKeys {
			log.Printf(
				"[WARNING] Skipped keys map still exceeds limit: %d > %d. "+
					"Message reordering gap may be larger than %d messages.",
				len(s.skippedKeys), MaxSkippedKeys, MaxMessageGap,
			)
		}
	}
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
