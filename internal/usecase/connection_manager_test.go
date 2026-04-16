package usecase_test

import (
	"bytes"
	"context"
	"dp2ptcs/internal/domain"
	"dp2ptcs/internal/transport"
	"dp2ptcs/internal/usecase"
	"errors"
	"testing"
)

// MockConnection implements transport.Connection for testing.
type MockConnection struct{}

func (m *MockConnection) OpenStream(ctx context.Context) (transport.Stream, error)   { return nil, nil }
func (m *MockConnection) AcceptStream(ctx context.Context) (transport.Stream, error) { return nil, nil }
func (m *MockConnection) Close() error                                               { return nil }

// MockTransport implements transport.Transport for testing.
type MockTransport struct {
	FailAddresses map[string]bool
}

func (m *MockTransport) Dial(address string) (transport.Connection, error) {
	if m.FailAddresses[address] {
		return nil, errors.New("simulated network timeout")
	}
	return &MockConnection{}, nil
}

func (m *MockTransport) Listen(address string) (transport.Listener, error) { return nil, nil }

// MockDiscoverer implements domain.Discoverer for isolated unit testing.
type MockDiscoverer struct {
	peer *domain.Peer
	err  error
}

func (m *MockDiscoverer) FindPeer(targetID []byte) (*domain.Peer, error) {
	return m.peer, m.err
}

func TestConnectionManager_ResolvePeer_Success(t *testing.T) {
	// Create a mock peer with a valid ID and addresses
	targetID := bytes.Repeat([]byte{0x01}, 32)
	expectedPeer, _ := domain.NewPeer(targetID, []string{"127.0.0.1:8080"})
	mockDiscoverer := &MockDiscoverer{peer: expectedPeer}
	connManager := usecase.NewConnectionManager(mockDiscoverer, nil)

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
	mockDiscoverer := &MockDiscoverer{peer: nil, err: domain.ErrPeerNotFound}
	connManager := usecase.NewConnectionManager(mockDiscoverer, nil)

	_, err := connManager.ResolvePeer(targetID)
	if err != domain.ErrPeerNotFound {
		t.Fatalf("expected error %v, got %v", domain.ErrPeerNotFound, err)
	}
}

func TestConnectionManager_InvalidIDLength(t *testing.T) {
	targetID := []byte{0x01, 0x02} // Invalid length
	manager := usecase.NewConnectionManager(&MockDiscoverer{}, nil)

	_, err := manager.ResolvePeer(targetID)
	if err != domain.ErrInvalidNodeID {
		t.Fatalf("expected error %v, got %v", domain.ErrInvalidNodeID, err)
	}
}

func TestConnectionManager_ConnectToPeer_SuccessWithFallback(t *testing.T) {
	targetID := bytes.Repeat([]byte{0x04}, 32)

	// The peer has two addresses. The first is dead (e.g., out of radio range), the second is alive.
	addresses := []string{"10.0.0.99:9000", "192.168.1.5:9000"}
	expectedPeer, _ := domain.NewPeer(targetID, addresses)

	mockDiscoverer := &MockDiscoverer{peer: expectedPeer, err: nil}

	mockTransport := &MockTransport{
		FailAddresses: map[string]bool{
			addresses[0]: true, // Force the first address to fail
		},
	}

	// Inject both dependencies
	manager := usecase.NewConnectionManager(mockDiscoverer, mockTransport)

	conn, err := manager.ConnectToPeer(targetID)

	if err != nil {
		t.Fatalf("expected successful connection on the second address, got error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected a valid connection object to be returned")
	}
}

func TestConnectionManager_ConnectToPeer_AllAddressesFail(t *testing.T) {
	targetID := bytes.Repeat([]byte{0x05}, 32)
	addresses := []string{"10.0.0.99:9000"}
	expectedPeer, _ := domain.NewPeer(targetID, addresses)

	mockDiscoverer := &MockDiscoverer{peer: expectedPeer, err: nil}
	mockTransport := &MockTransport{
		FailAddresses: map[string]bool{addresses[0]: true}, // All known addresses fail
	}

	manager := usecase.NewConnectionManager(mockDiscoverer, mockTransport)

	_, err := manager.ConnectToPeer(targetID)

	if err == nil {
		t.Fatal("expected error when all addresses fail, got nil")
	}
	if err != usecase.ErrConnectionFailed {
		t.Errorf("expected ErrConnectionFailed, got %v", err)
	}
}
