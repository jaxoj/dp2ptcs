package crypto_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"strings"
	"testing"
)

func TestEncryptDecryptKey_Success(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ed25519 key: %v", err)
	}

	passphrase := "tactical-secure-passphrase-2026"

	// 1. Encrypt the key
	encryptedData, err := crypto.EncryptKey(privKey, passphrase)
	if err != nil {
		t.Fatalf("EncryptKey failed: %v", err)
	}

	if len(encryptedData) == 0 {
		t.Fatal("EncryptKey returned empty byte slice")
	}

	// 2. Decrypt the key
	decryptedKey, err := crypto.DecryptKey(encryptedData, passphrase)
	if err != nil {
		t.Fatalf("DecryptKey failed: %v", err)
	}

	// 3. Verify integrity
	if !bytes.Equal(privKey, decryptedKey) {
		t.Errorf("Decrypted private key does not match the original")
	}
}

func TestDecryptKey_WrongPassphrase(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	encryptedData, _ := crypto.EncryptKey(privKey, "correct-passphrase")

	_, err := crypto.DecryptKey(encryptedData, "wrong-passphrase")
	if err == nil {
		t.Fatal("Expected an error when decrypting with the wrong passphrase, but got nil")
	}

	if !strings.Contains(err.Error(), "invalid passphrase") {
		t.Errorf("Expected invalid passphrase error, got: %v", err)
	}
}

func TestDecryptKey_MalformedJSON(t *testing.T) {
	malformedData := []byte(`{"salt": "invalid-base64", "nonce": 123}`)

	_, err := crypto.DecryptKey(malformedData, "any-passphrase")
	if err == nil {
		t.Fatal("Expected error when parsing malformed keystore format, but got nil")
	}

	if !strings.Contains(err.Error(), "failed to parse") {
		t.Errorf("Expected parsing error, got: %v", err)
	}
}
