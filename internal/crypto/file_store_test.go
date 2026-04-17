package crypto_test

import (
	"bytes"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"path/filepath"
	"testing"
)

func TestFileIdentityStore_SaveAndLoad_Success(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "node.key")
	store := crypto.NewFileIdentityStore(keyPath)

	originalIdentity, err := crypto.GenerateIdentity(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	passphrase := "operation-alpha-key"

	err = store.Save(originalIdentity, passphrase)
	if err != nil {
		t.Fatalf("Failed to save encrypted identity: %v", err)
	}

	// Ensure OS-level permissions are still enforced as a defense-in-depth measure
	if err := VerifyOnlyCurrentUserHasAccess(keyPath); err != nil {
		t.Errorf("Permission check failed: %v", err)
	}

	loadedIdentity, err := store.Load(passphrase)
	if err != nil {
		t.Fatalf("Failed to load and decrypt identity: %v", err)
	}

	// Verify cryptographic integrity of loaded identity
	if !bytes.Equal(originalIdentity.PrivateKey, loadedIdentity.PrivateKey) {
		t.Fatalf("Loaded private key does not match original")
	}
	if !bytes.Equal(originalIdentity.PublicKey, loadedIdentity.PublicKey) {
		t.Fatalf("Loaded public key does not match original")
	}
	if !bytes.Equal(originalIdentity.NodeID, loadedIdentity.NodeID) {
		t.Fatalf("Loaded NodeID does not match original")
	}
}

func TestFileIdentityStore_Load_WrongPassphrase(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "node.key")
	store := crypto.NewFileIdentityStore(keyPath)

	originalIdentity, _ := crypto.GenerateIdentity(rand.Reader)
	err := store.Save(originalIdentity, "correct-passphrase")
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	_, err = store.Load("wrong-passphrase")
	if err == nil {
		t.Fatal("Expected error when loading with wrong passphrase, but got nil")
	}
}

func TestFileIdentityStore_LoadNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "nonexistent.key")
	store := crypto.NewFileIdentityStore(keyPath)

	_, err := store.Load("any-passphrase")
	if err == nil {
		t.Fatal("Expected error when loading non-existent identity, but got nil")
	}

	// Ensure it returns the specific sentinel error so the use case can handle initialization properly
	if err != crypto.ErrNoIdentityFound {
		t.Fatalf("Expected ErrNoIdentityFound, got: %v", err)
	}
}
