package usecase

import (
	"context"
	"dp2ptcs/internal/crypto"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const (
	// SessionTTL is the maximum time a session can remain in memory without activity.
	// After this duration, the session is automatically evicted.
	SessionTTL = 1 * time.Hour

	// CleanupInterval is how frequently the manager scans for expired sessions.
	CleanupInterval = 15 * time.Minute
)

// sessionMetadata tracks when a session was last accessed for TTL management.
type sessionMetadata struct {
	session   crypto.SecureSession
	lastSeen  time.Time
	createdAt time.Time
}

// InMemorySessionManager securely holds active Double Ratchet sessions in memory
// with automatic TTL-based eviction to prevent memory exhaustion.
type InMemorySessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*sessionMetadata

	// stopCleanup signals the cleanup goroutine to terminate.
	stopCleanup context.CancelFunc
}

// NewInMemorySessionManager creates and initializes a session manager with cleanup.
func NewInMemorySessionManager() *InMemorySessionManager {
	ctx, cancel := context.WithCancel(context.Background())

	m := &InMemorySessionManager{
		sessions:    make(map[string]*sessionMetadata),
		stopCleanup: cancel,
	}

	// Start the background cleanup goroutine.
	go m.cleanupExpiredSessions(ctx)

	return m
}

// GetSession retrieves a session and updates its last-seen timestamp.
func (m *InMemorySessionManager) GetSession(peerID []byte) (crypto.SecureSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := hex.EncodeToString(peerID)
	meta, exists := m.sessions[key]
	if !exists {
		return nil, errors.New("session not found")
	}

	// Update last-seen timestamp to prevent eviction due to activity.
	meta.lastSeen = time.Now()

	return meta.session, nil
}

// SetSession stores a session with the current timestamp.
func (m *InMemorySessionManager) SetSession(peerID []byte, session crypto.SecureSession) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := hex.EncodeToString(peerID)
	now := time.Now()
	m.sessions[key] = &sessionMetadata{
		session:   session,
		lastSeen:  now,
		createdAt: now,
	}
}

// DeleteSession explicitly removes a session from the manager.
// This is called when a peer disconnects or a stream error occurs.
func (m *InMemorySessionManager) DeleteSession(peerID []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := hex.EncodeToString(peerID)
	if _, exists := m.sessions[key]; !exists {
		return errors.New("session not found")
	}

	delete(m.sessions, key)
	return nil
}

// cleanupExpiredSessions runs in a background goroutine and removes sessions
// that have exceeded their TTL without activity.
func (m *InMemorySessionManager) cleanupExpiredSessions(ctx context.Context) {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Manager is shutting down.
			return
		case <-ticker.C:
			m.evictExpiredSessions()
		}
	}
}

// evictExpiredSessions scans the session map and removes expired entries.
func (m *InMemorySessionManager) evictExpiredSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, meta := range m.sessions {
		if now.Sub(meta.lastSeen) > SessionTTL {
			delete(m.sessions, key)
		}
	}
}

// Shutdown gracefully stops the cleanup goroutine. Call this during node shutdown.
func (m *InMemorySessionManager) Shutdown() {
	if m.stopCleanup != nil {
		m.stopCleanup()
	}
}
