package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
)

// ErrNoIdentityFound is returned when no cryptographic identity can be found at the specified path.
var ErrNoIdentityFound = errors.New("no cryptographic identity found at specific path")

// IdentityStore defines the interface for storing and retrieving cryptographic identities.
type IdentityStore interface {
	Save(id *Identity) error
	Load() (*Identity, error)
}

// FileIdentityStore implements IdentityStore using the filesystem for persistence.
type FileIdentityStore struct {
	filePath string
}

// NewFileIdentityStore creates a new FileIdentityStore with the given file path for storing the identity.
func NewFileIdentityStore(filePath string) *FileIdentityStore {
	return &FileIdentityStore{filePath: filePath}
}

// Save writes the private key of the identity to the specified file path with strict permissions.
func (s *FileIdentityStore) Save(id *Identity) error {
	// Delegate to the OS-specific implementation
	return saveFileSecure(s.filePath, id.PrivateKey)
}

func (s *FileIdentityStore) Load() (*Identity, error) {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoIdentityFound
		}
		return nil, err
	}

	priv := ed25519.PrivateKey(data)

	// Reconstruct the public key from the private key
	// In Go, ed25519.PrivateKey is 64 bytes; the last 32 bytes are the public key.
	pub := priv.Public().(ed25519.PublicKey)

	// Calculate SHA-256 hash of the public key to generate the NodeID
	hash := sha256.Sum256(pub)

	return &Identity{
		PrivateKey: priv,
		PublicKey:  pub,
		NodeID:     hash[:],
	}, nil
}
