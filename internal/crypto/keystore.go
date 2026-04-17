package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize = 16
	keySize  = 32 // 256 bits for AES-256
	// Argon2id recommended parameters (adjust based on target hardware capabilities)
	timeCost   = 1
	memoryCost = 64 * 1024 // 64 MB
	threads    = 4
)

// EncryptedKeyStore represents the payload written to disk
type EncryptedKeyStore struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// EncryptKey derives a key from the passphrase and encrypts the private key
func EncryptKey(privateKey []byte, passphrase string) ([]byte, error) {
	// Generate a random salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// Derive the AES key using Argon2id
	aesKey := argon2.IDKey([]byte(passphrase), salt, timeCost, memoryCost, threads, keySize)

	// Setup AES-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and authenticate the private key
	ciphertext := aesGCM.Seal(nil, nonce, privateKey, nil)

	store := EncryptedKeyStore{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}

	return json.Marshal(store)
}

// DecryptKey extracts the private key using the provided passphrase
func DecryptKey(data []byte, passphrase string) ([]byte, error) {
	var store EncryptedKeyStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, errors.New("failed to parse keystore format")
	}

	// Derive the AES key using the stored salt
	aesKey := argon2.IDKey([]byte(passphrase), store.Salt, timeCost, memoryCost, threads, keySize)

	// Set up AES-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt and verify authenticity
	plaintext, err := aesGCM.Open(nil, store.Nonce, store.Ciphertext, nil)
	if err != nil {
		return nil, errors.New("invalid passphrase or corrupted key file")
	}

	return plaintext, nil
}
