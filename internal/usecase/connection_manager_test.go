package usecase_test

import (
	"bytes"
	"dp2ptcs/internal/dht"
	"dp2ptcs/internal/usecase"
	"testing"
)

// MockDiscoverer implements dht.Discoverer for isolated unit testing.
type MockDiscoverer struct {
	peer *dht.Peer
	err  error
}

func (m *MockDiscoverer) FindPeer(targetID []byte) (*dht.Peer, error) {
	return m.peer, m.err
}

func TestConnectionManager_ResolvePeer_Success(t *testing.T) {
	// Create a mock peer with a valid ID and addresses
	targetID := bytes.Repeat([]byte{0x01}, 32)
	expectedPeer, _ := dht.NewPeer(targetID, []string{"127.0.0.1:8080"})
	mockDiscoverer := &MockDiscoverer{peer: expectedPeer}
	connManager := usecase.NewConnectionManager(mockDiscoverer)

	resolvedPeer, err := connManager.ResolvePeer(targetID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(resolvedPeer.ID, targetID) {
		t.Errorf("expected ID %v, got %v", targetID, resolvedPeer.ID)
	}

	if len(resolvedPeer.Addresses) == 0 {
		t.Errorf("expected resolved peer to have at least one address, got none")
	}
}

func TestConnectionManager_ResolvePeer_NotFound(t *testing.T) {
	targetID := bytes.Repeat([]byte{0x01}, 32)
	mockDiscoverer := &MockDiscoverer{peer: nil, err: dht.ErrPeerNotFound}
	connManager := usecase.NewConnectionManager(mockDiscoverer)

	_, err := connManager.ResolvePeer(targetID)
	if err != dht.ErrPeerNotFound {
		t.Fatalf("expected error %v, got %v", dht.ErrPeerNotFound, err)
	}
}

func TestConnectionManager_InvalidIDLength(t *testing.T) {
	targetID := []byte{0x01, 0x02} // Invalid length
	manager := usecase.NewConnectionManager(&MockDiscoverer{})

	_, err := manager.ResolvePeer(targetID)
	if err != dht.ErrInvalidNodeID {
		t.Fatalf("expected error %v, got %v", dht.ErrInvalidNodeID, err)
	}
}
