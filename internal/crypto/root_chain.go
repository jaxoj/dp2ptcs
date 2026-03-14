package crypto

import (
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// RootChain manages the Post-Compromise Security (PCS) state.
// It mixes Diffie-Hellman shared secrets to continuously rotate the symmetric chains.
type RootChain struct {
	rootKey []byte
}

func NewRootChain(initialRootKey []byte) *RootChain {
	return &RootChain{
		rootKey: initialRootKey,
	}
}

// Step advances the Root Chain using a newly calculated DH shared secret.
// It returns a brand new Symmetric Chain Key to be used for payload encryption.
func (c *RootChain) Step(dhSharedSecret []byte) (newSymmetricChainKey []byte, err error) {
	if len(c.rootKey) == 0 {
		return nil, errors.New("root key is empty")
	}
	if len(dhSharedSecret) == 0 {
		return nil, errors.New("dh shared secret is empty")
	}

	// HKDF-Extract and Expand using SHA-256
	// The current rootKey acts as the HKDF "salt", and the dhSharedSecret acts as the "secret"
	hash := sha256.New
	kdf := hkdf.New(hash, dhSharedSecret, c.rootKey, []byte("Tactical-Root-Ratchet-v1"))

	// We need 64 bytes total: 32 for the next Root Key, 32 for the new Symmetric Chain Key
	output := make([]byte, KeyLength*2)
	if _, err := io.ReadFull(kdf, output); err != nil {
		return nil, err
	}

	// Update the internal state with the new Root Key
	c.rootKey = output[:KeyLength]

	// Output the new Chain Key to reset the symmetric ratchet
	newSymmetricChainKey = output[KeyLength:]

	return newSymmetricChainKey, nil
}
