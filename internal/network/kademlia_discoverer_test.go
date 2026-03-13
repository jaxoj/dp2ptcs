package network_test

import (
	"bytes"
	"dp2ptcs/internal/dht"
	"dp2ptcs/internal/network"
	"testing"
)

// MockRPCClient simulates network I/O for tactical node simulation
type MockRPCClient struct {
	ReturnedPeers []*dht.Peer
	Err           error
}

func (m *MockRPCClient) FindNode(targetID []byte, remote *dht.Peer) ([]*dht.Peer, error) {
	return m.ReturnedPeers, m.Err
}

func TestKademliaDiscoverer_FindPeer_Success(t *testing.T) {
	targetID := bytes.Repeat([]byte{0xBB}, 32)
	targetPeer, _ := dht.NewPeer(targetID, []string{"10.77.0.5:9000"})

	// Simulates the remote node returning a list that includes our target
	mockRPC := &MockRPCClient{
		ReturnedPeers: []*dht.Peer{targetPeer},
		Err:           nil,
	}

	// We need a known peer to ask. In a real scenario, this comes from our routing table.
	knownPeer, _ := dht.NewPeer(bytes.Repeat([]byte{0xAA}, 32), []string{"10.55.0.1:9000"})

	discoverer := network.NewKademliaDiscoverer(mockRPC, knownPeer)

	foundPeer, err := discoverer.FindPeer(targetID)

	if err != nil {
		t.Fatalf("expected no error, go %v", err)
	}
	if !bytes.Equal(foundPeer.ID, targetID) {
		t.Error("expected to find the target peer")
	}
	if foundPeer.Addresses[0] != "10.77.0.5:9000" {
		t.Errorf("expected address 10.77.0.5:9000, got %s", foundPeer.Addresses[0])
	}
}

func TestKademliaDiscoverer_FindPeer_NotFound(t *testing.T) {
	// Arrange
	targetID := bytes.Repeat([]byte{0xCC}, 32)

	// Simulate the remote node returning peers, but NOT our target
	otherPeer, _ := dht.NewPeer(bytes.Repeat([]byte{0xDD}, 32), []string{"10.77.0.6:9000"})
	mockRPC := &MockRPCClient{
		ReturnedPeers: []*dht.Peer{otherPeer},
		Err:           nil,
	}

	knownPeer, _ := dht.NewPeer(bytes.Repeat([]byte{0xAA}, 32), []string{"10.55.0.1:9000"})
	discoverer := network.NewKademliaDiscoverer(mockRPC, knownPeer)

	// Act
	_, err := discoverer.FindPeer(targetID)

	// Assert
	if err != dht.ErrPeerNotFound {
		t.Errorf("expected ErrPeerNotFound, got %v", err)
	}
}
