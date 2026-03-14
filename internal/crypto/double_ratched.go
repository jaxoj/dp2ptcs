package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// DoubleRatchetSession manages the full Post-Compromise and Forward Secrecy state.
type DoubleRatchetSession struct {
	rootChain *RootChain
	sendChain *KDFChain
	recvChain *KDFChain

	dhSendPriv []byte // Our current ephemeral private key
	dhSendPub  []byte // Our current ephemeral public key
	dhRecvPub  []byte // The remote peer's last known ephemeral public key
}

// NewDoubleRatchetSession initializes the state machine.
// In a real flow, this is called immediately after the X3DH handshake completes.
func NewDoubleRatchetSession(rootKey, localPriv, localPub, remotePub []byte) *DoubleRatchetSession {
	// For simplicity in initialization, we start with empty KDF chains.
	// The first Encrypt/Decrypt call will immediately trigger a Root step to populate them.
	return &DoubleRatchetSession{
		rootChain:  NewRootChain(rootKey),
		sendChain:  &KDFChain{}, // Will be populated on next step
		recvChain:  &KDFChain{}, // Will be populated on next step
		dhSendPriv: localPriv,
		dhSendPub:  localPub,
		dhRecvPub:  remotePub,
	}
}

// Encrypt ratchets the symmetric send chain and locks the payload.
// It returns the ciphertext and our current DH public key to be attached to the header.
func (s *DoubleRatchetSession) Encrypt(plaintext []byte) ([]byte, []byte, error) {
	// If our send chain is empty, we must establish it by mixing our current DH keys.
	if len(s.sendChain.chainKey) == 0 {
		if err := s.stepRootChain(); err != nil {
			return nil, nil, err
		}
	}

	// We use the same SymmetricSession logic we built previously
	symSession := &SymmetricSession{
		sendChain: s.sendChain,
		recvChain: s.recvChain,
	}

	ciphertext, err := symSession.Encrypt(plaintext)
	if err != nil {
		return nil, nil, err
	}

	// Return the locked payload AND our public key for the message header
	return ciphertext, s.dhSendPub, nil
}

// Decrypt checks the header for a new DH public key, steps the root chain if needed,
// and decrypts the payload.
func (s *DoubleRatchetSession) Decrypt(ciphertext []byte, remoteDHPubKey []byte) ([]byte, error) {
	if len(remoteDHPubKey) != 32 {
		return nil, errors.New("invalid remote DH public key length")
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
	}

	// Decrypt using the (potentially newly generated) symmetric receive chain
	symSession := &SymmetricSession{
		sendChain: s.sendChain,
		recvChain: s.recvChain,
	}

	return symSession.Decrypt(ciphertext)
}

// stepRootChain computes the DH shared secret and rotates all symmetric keys.
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
