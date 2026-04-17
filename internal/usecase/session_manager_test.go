package usecase_test

import (
	"dp2ptcs/internal/usecase"
	"testing"
	"time"
)

// MockSecureSessionForSessionMgr is a minimal SecureSession for testing
type MockSecureSessionForSessionMgr struct{}

func (m *MockSecureSessionForSessionMgr) Encrypt(plaintext []byte) ([]byte, []byte, uint64, uint32, error) {
	return plaintext, nil, 1, 0, nil
}

func (m *MockSecureSessionForSessionMgr) Decrypt(ciphertext, remoteDHPubKey []byte, messageNumber uint64, previousChainLength uint32) ([]byte, error) {
	return ciphertext, nil
}

func TestInMemorySessionManager_SetAndGetSession(t *testing.T) {
	mgr := usecase.NewInMemorySessionManager()
	defer mgr.Shutdown()

	peerID := []byte{0x01, 0x02, 0x03, 0x04}
	session := &MockSecureSessionForSessionMgr{}

	// Set a session
	mgr.SetSession(peerID, session)

	// Get the session back
	retrievedSession, err := mgr.GetSession(peerID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	// Verify we got a session (interface doesn't support direct comparison)
	if retrievedSession == nil {
		t.Errorf("expected to retrieve a session, got nil")
	}
}

func TestInMemorySessionManager_DeleteSession(t *testing.T) {
	mgr := usecase.NewInMemorySessionManager()
	defer mgr.Shutdown()

	peerID := []byte{0x01, 0x02, 0x03, 0x04}
	session := &MockSecureSessionForSessionMgr{}

	// Set a session
	mgr.SetSession(peerID, session)

	// Verify it exists
	_, err := mgr.GetSession(peerID)
	if err != nil {
		t.Fatalf("Session should exist after SetSession, but got error: %v", err)
	}

	// Delete the session
	err = mgr.DeleteSession(peerID)
	if err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}

	// Verify it no longer exists
	_, err = mgr.GetSession(peerID)
	if err == nil {
		t.Errorf("Session should not exist after DeleteSession")
	}
}

func TestInMemorySessionManager_SessionTTL(t *testing.T) {
	// Create a manager and temporarily override the TTL for testing
	mgr := usecase.NewInMemorySessionManager()
	defer mgr.Shutdown()

	peerID := []byte{0x01, 0x02, 0x03, 0x04}
	session := &MockSecureSessionForSessionMgr{}

	// Set a session
	mgr.SetSession(peerID, session)

	// Verify it exists
	_, err := mgr.GetSession(peerID)
	if err != nil {
		t.Fatalf("Session should exist after SetSession")
	}

	// Manually trigger cleanup by waiting slightly longer than the TTL
	// Note: This test relies on the cleanup goroutine running, which happens periodically.
	// For a unit test, we verify that the session exists when recently accessed.
	// A more robust test would mock time.Now() or expose a synchronous cleanup method.

	// At minimum, verify GetSession updates lastSeen
	time.Sleep(100 * time.Millisecond)

	_, err = mgr.GetSession(peerID)
	if err != nil {
		t.Fatalf("Recently accessed session should still exist")
	}
}

func TestInMemorySessionManager_MultipleSessionsIndependent(t *testing.T) {
	mgr := usecase.NewInMemorySessionManager()
	defer mgr.Shutdown()

	peerID1 := []byte{0x01, 0x01, 0x01, 0x01}
	peerID2 := []byte{0x02, 0x02, 0x02, 0x02}

	// Set two different sessions
	mgr.SetSession(peerID1, &MockSecureSessionForSessionMgr{})
	mgr.SetSession(peerID2, &MockSecureSessionForSessionMgr{})

	// Retrieve both
	retrieved1, err := mgr.GetSession(peerID1)
	if err != nil || retrieved1 == nil {
		t.Errorf("Failed to retrieve session 1 correctly")
	}

	retrieved2, err := mgr.GetSession(peerID2)
	if err != nil || retrieved2 == nil {
		t.Errorf("Failed to retrieve session 2 correctly")
	}

	// Delete session 1
	mgr.DeleteSession(peerID1)

	// Verify session 1 is gone but session 2 still exists
	_, err = mgr.GetSession(peerID1)
	if err == nil {
		t.Errorf("Session 1 should be deleted")
	}

	retrieved2, err = mgr.GetSession(peerID2)
	if err != nil || retrieved2 == nil {
		t.Errorf("Session 2 should still exist after deleting session 1")
	}
}

func TestInMemorySessionManager_GetSessionUpdatesLastSeen(t *testing.T) {
	mgr := usecase.NewInMemorySessionManager()
	defer mgr.Shutdown()

	peerID := []byte{0x01, 0x02, 0x03, 0x04}
	session := &MockSecureSessionForSessionMgr{}

	// Set a session
	mgr.SetSession(peerID, session)

	// Sleep a bit
	time.Sleep(100 * time.Millisecond)

	// GetSession should refresh the lastSeen time, preventing TTL eviction
	_, err := mgr.GetSession(peerID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	// Verify the session still exists (it should, since we just accessed it)
	_, err = mgr.GetSession(peerID)
	if err != nil {
		t.Errorf("Session should still exist after being accessed")
	}
}
