package usecase_test

import (
	"bytes"
	"context"
	"dp2ptcs/internal/domain"
	"dp2ptcs/internal/transport"
	"dp2ptcs/internal/usecase"
	"errors"
	"testing"
	"time"
)

// MockConnection implements transport.Connection for testing.
type MockConnection struct{}

func (m *MockConnection) OpenStreamSync(ctx context.Context) (transport.Stream, error) {
	return nil, nil
}
func (m *MockConnection) AcceptStream(ctx context.Context) (transport.Stream, error) { return nil, nil }
func (m *MockConnection) OpenStream(ctx context.Context) (transport.Stream, error)   { return nil, nil }
func (m *MockConnection) Close() error                                               { return nil }

// MockTransport implements transport.Transport for testing.
type MockTransport struct {
	FailAddresses map[string]bool
	DialDelay     map[string]time.Duration // To test "Happy Eyeballs" concurrency
}

// Updated Dial to match transport.Transport interface with context and addr
func (m *MockTransport) Dial(address string) (transport.Connection, error) {
	// Respect simulated delay
	if delay, ok := m.DialDelay[address]; ok {
		time.After(delay)
	}

	if m.FailAddresses[address] {
		return nil, errors.New("simulated network timeout")
	}
	return &MockConnection{}, nil
}

func (m *MockTransport) Listen(address string) (transport.Listener, error) {
	return nil, nil
}

// MockDiscoverer implements domain.Discoverer
type MockDiscoverer struct {
	peer *domain.Peer
	err  error
}

func (m *MockDiscoverer) FindPeer(targetID []byte) (*domain.Peer, error) {
	if m.err != nil {
		return &domain.Peer{}, m.err
	}
	return m.peer, nil
}
func TestConnectionManager_ResolvePeer_Success(t *testing.T) {
	targetID := bytes.Repeat([]byte{0x01}, 32)
	expectedPeer := domain.Peer{ID: targetID, Addresses: []string{"127.0.0.1:8080"}}
	mockDiscoverer := &MockDiscoverer{peer: &expectedPeer}
	connManager := usecase.NewConnectionManager(mockDiscoverer, nil)

	resolvedPeer, err := connManager.ResolvePeer(targetID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(resolvedPeer.ID, targetID) {
		t.Errorf("expected ID %x, got %x", targetID, resolvedPeer.ID)
	}
}

func TestConnectionManager_ResolvePeer_NotFound(t *testing.T) {
	targetID := bytes.Repeat([]byte{0x01}, 32)
	mockDiscoverer := &MockDiscoverer{err: domain.ErrPeerNotFound}
	connManager := usecase.NewConnectionManager(mockDiscoverer, nil)

	_, err := connManager.ResolvePeer(targetID)
	if !errors.Is(err, domain.ErrPeerNotFound) {
		t.Fatalf("expected error %v, got %v", domain.ErrPeerNotFound, err)
	}
}

func TestConnectionManager_ConnectToPeer_SuccessWithFallback(t *testing.T) {
	targetID := bytes.Repeat([]byte{0x04}, 32)
	addresses := []string{"10.0.0.99:9000", "192.168.1.5:9000"}
	targetPeer := domain.Peer{ID: targetID, Addresses: addresses}

	mockTransport := &MockTransport{
		FailAddresses: map[string]bool{
			addresses[0]: true, // First address fails
		},
		DialDelay: map[string]time.Duration{
			addresses[0]: 10 * time.Millisecond,
			addresses[1]: 50 * time.Millisecond,
		},
	}

	manager := usecase.NewConnectionManager(nil, mockTransport)

	// Context for the dial operation
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Now passing the Peer object directly as per your recent implementation
	conn, err := manager.ConnectToPeer(ctx, targetPeer)

	if err != nil {
		t.Fatalf("expected successful connection on second address, got: %v", err)
	}
	if conn == nil {
		t.Fatal("expected valid connection object")
	}
}

func TestConnectionManager_ConnectToPeer_ConcurrencyCheck(t *testing.T) {
	targetID := bytes.Repeat([]byte{0x06}, 32)
	// Even if the first address is "first" in the list, if it's slow, the second should win.
	addresses := []string{"10.0.0.1:9000", "192.168.1.1:9000"}
	targetPeer := domain.Peer{ID: targetID, Addresses: addresses}

	mockTransport := &MockTransport{
		DialDelay: map[string]time.Duration{
			addresses[0]: 200 * time.Millisecond, // Slow
			addresses[1]: 10 * time.Millisecond,  // Fast
		},
	}

	manager := usecase.NewConnectionManager(nil, mockTransport)

	start := time.Now()
	conn, err := manager.ConnectToPeer(context.Background(), targetPeer)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("connection failed: %v", err)
	}
	if conn == nil {
		t.Fatal("connection is nil")
	}

	// If concurrent dialing works, we should finish in ~10ms, not ~200ms.
	if duration > 100*time.Millisecond {
		t.Errorf("Happy Eyeballs failed: took %v, expected ~10ms", duration)
	}
}

func TestConnectionManager_ConnectToPeer_AllAddressesFail(t *testing.T) {
	targetID := bytes.Repeat([]byte{0x05}, 32)
	addresses := []string{"10.0.0.99:9000"}
	targetPeer := domain.Peer{ID: targetID, Addresses: addresses}

	mockTransport := &MockTransport{
		FailAddresses: map[string]bool{addresses[0]: true},
	}

	manager := usecase.NewConnectionManager(nil, mockTransport)

	_, err := manager.ConnectToPeer(context.Background(), targetPeer)

	if err == nil {
		t.Fatal("expected error when all addresses fail")
	}
}
