package crypto_test

import (
	"bytes"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"path/filepath"
	"testing"
)

func TestFileIdentityStore_SaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "node.key")
	store := crypto.NewFileIdentityStore(keyPath)

	originalIdentity, err := crypto.GenerateIdentity(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate identity: %v", err)
	}

	err = store.Save(originalIdentity)
	if err != nil {
		t.Fatalf("Failed to save identity: %v", err)
	}

	if err := VerifyOnlyCurrentUserHasAccess(keyPath); err != nil {
		t.Errorf("Permission check failed: %v", err)
	}

	loadedIdentity, err := store.Load()
	if err != nil {
		t.Fatalf("Failed to load identity: %v", err)
	}

	// Verify integrity of loaded identity
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

func TestFileIdentityStore_LoadNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "nonexistent.key")
	store := crypto.NewFileIdentityStore(keyPath)

	_, err := store.Load()
	if err == nil {
		t.Fatal("Expected error when loading non-existent identity, but got nil")
	}
}
