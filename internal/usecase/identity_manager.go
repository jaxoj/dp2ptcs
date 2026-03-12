package usecase

import (
	"dp2ptcs/internal/crypto"
	"io"
)

// IdentityManager orchestrate the loading and creation of node identities, abstracting away the underlying storage mechanism.
type IdentityManager struct {
	store   crypto.IdentityStore
	entropy io.Reader
}

func NewIdentityManager(store crypto.IdentityStore, entropy io.Reader) *IdentityManager {
	return &IdentityManager{
		store:   store,
		entropy: entropy,
	}
}

func (m *IdentityManager) LoadOrCreate() (*crypto.Identity, error) {
	id, err := m.store.Load()
	if err == nil {
		return id, nil // Successfully loaded existing identity
	}

	if err != crypto.ErrNoIdentityFound {
		return nil, err // Return unexpected storage error (e.g permission issues)
	}

	id, err = crypto.GenerateIdentity(m.entropy)
	if err != nil {
		return nil, err
	}

	// Presist the newly generated identity
	err = m.store.Save(id)
	if err != nil {
		return nil, err
	}

	return id, nil
}
