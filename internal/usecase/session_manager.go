package usecase

import (
	"dp2ptcs/internal/crypto"
	"encoding/hex"
	"errors"
	"sync"
)

// InMemorySessionManager securely holds active Double Ratchet sessions in memory.
type InMemorySessionManager struct {
	mu       sync.RWMutex
	sessions map[string]crypto.SecureSession
}

func NewInMemorySessionManager() *InMemorySessionManager {
	return &InMemorySessionManager{
		sessions: make(map[string]crypto.SecureSession),
	}
}

func (m *InMemorySessionManager) GetSession(peerID []byte) (crypto.SecureSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := hex.EncodeToString(peerID)
	session, exists := m.sessions[key]
	if !exists {
		return nil, errors.New("session not found")
	}
	return session, nil
}

func (m *InMemorySessionManager) SetSession(peerID []byte, session crypto.SecureSession) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := hex.EncodeToString(peerID)
	m.sessions[key] = session
}
