package crypto

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// SymmetricSession implements SecureSession using independent send and receive KDF chains.
type SymmetricSession struct {
	sendChain *KDFChain
	recvChain *KDFChain
}

// NewSymmetricSession initializes a session with distinct keys for each direction.
func NewSymmetricSession(sendRootKey, recvRootKey []byte) *SymmetricSession {
	return &SymmetricSession{sendChain: NewKDFChain(sendRootKey), recvChain: NewKDFChain(recvRootKey)}
}

func (s *SymmetricSession) Encrypt(plaintext []byte) ([]byte, error) {
	// Ratchet the send chain forward to get a one-time message key
	msgKey, err := s.sendChain.Ratchet()
	if err != nil {
		return nil, err
	}

	// Initialize the AEAD cipher
	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		return nil, err
	}

	// Generate a random 12-byte nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and authenticate the payload.
	// Seal appends the ciphertext and MAC to the provided prefix (our nonce).
	// The output format is: [12-byte Nonce] + [Ciphertext] + [16-byte Poly1305 MAC]
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

func (s *SymmetricSession) Decrypt(ciphertext []byte) ([]byte, error) {
	// Ratchet the receive chain forward to get the matching one-time message key
	msgKey, err := s.recvChain.Ratchet()
	if err != nil {
		return nil, err
	}

	// Initialize the AEAD cipher
	aead, err := chacha20poly1305.New(msgKey)
	if err != nil {
		return nil, err
	}

	// Ensure the ciphertext is at least as long as the nonce
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short to contain nonce")
	}

	// Split the nonce and the actual encrypted data
	nonce, encryptedData := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, errors.New("message authentication failed: potential tampering or out-of-sync ratchet")
	}

	return plaintext, nil
}
