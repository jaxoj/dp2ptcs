package usecase_test

import (
	"bytes"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"dp2ptcs/internal/usecase"
	"testing"
)

// MockStore implements crypto.IdentityStore for isolated unit testing.
type MockStore struct {
	id  *crypto.Identity
	err error
}

func (m *MockStore) Save(id *crypto.Identity, passphrase string) error {
	m.id = id
	return m.err
}

func (m *MockStore) Load(passphrase string) (*crypto.Identity, error) {
	if m.id == nil {
		return nil, crypto.ErrNoIdentityFound
	}
	return m.id, m.err
}

const passphrase = "operation-alpha-key"

func TestIdentityManager_LoadOrCreate_CreatesNew(t *testing.T) {
	mockStore := &MockStore{}
	manager := usecase.NewIdentityManager(mockStore, rand.Reader)

	id, err := manager.LoadOrCreate(passphrase)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if id == nil {
		t.Fatal("Expected identity to be created, got nil")
	}
	if mockStore.id == nil {
		t.Fatal("Expected identity to be saved in store, but it was not")
	}
}

func TestIdentityManager_LoadOrCreate_LoadsExisting(t *testing.T) {
	existingId, _ := crypto.GenerateIdentity(rand.Reader)
	mockStore := &MockStore{id: existingId}
	manager := usecase.NewIdentityManager(mockStore, rand.Reader)

	id, err := manager.LoadOrCreate(passphrase)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !bytes.Equal(id.NodeID, existingId.NodeID) {
		t.Fatal("Expected exisiting identity to be loaded, got deffirent one")
	}
}
