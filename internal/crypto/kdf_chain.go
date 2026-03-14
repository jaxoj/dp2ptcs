package crypto

import (
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// Keys are standard 32-byte (256-bit) lengths for high-security environments.
	KeyLength = 32
)

// KDFChain represents one half of the symmetric ratchet (either sending or receiving).
type KDFChain struct {
	chainKey []byte
}

// NewKDFChain initializes a chain with a highly secure root key established via Diffie-Hellman.
func NewKDFChain(initialChainKey []byte) *KDFChain {
	return &KDFChain{
		chainKey: initialChainKey,
	}
}

// Ratchet steps the KDF chain forward.
// It mathematically destroys the old chain key, returning a one-time message key
// and updating internal state so past keys cannot be derived.
func (c *KDFChain) Ratchet() (messageKey []byte, err error) {
	if len(c.chainKey) == 0 {
		return nil, errors.New("chain key is empty")
	}

	// HKDF-Extract and Expand using SHA-256
	// We use the current chainKey as the secret, and specific tactical info constants
	hash := sha256.New

	// We need 64 bytes total: 32 for the next Chain Key, 32 for the Message Key
	kdf := hkdf.New(hash, c.chainKey, nil, []byte("Tactical-Ratchet-v1"))

	output := make([]byte, KeyLength*2)
	if _, err := io.ReadFull(kdf, output); err != nil {
		return nil, err
	}

	// Split the 64-byte output
	c.chainKey = output[:KeyLength] // The new state (keeps the chain moving)
	messageKey = output[KeyLength:] // The output key (used for AES/ChaCha)

	return messageKey, nil
}
