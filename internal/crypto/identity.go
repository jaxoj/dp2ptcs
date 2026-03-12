package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"io"
)

// Identity represents a cryptographic identity code of a peer node.
type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	NodeID     []byte
}

// GenerateIdentity creates a new self-soverign identity
func GenerateIdentity(entropy io.Reader) (*Identity, error) {
	pub, pri, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return nil, err
	}

	// Calculate SHA-256 hash of the public key to generate the NodeID
	hash := sha256.Sum256(pub)

	return &Identity{
		PrivateKey: pri,
		PublicKey:  pub,
		NodeID:     hash[:],
	}, nil
}
