package network_test

import (
	"bytes"
	"dp2ptcs/internal/domain"
	"dp2ptcs/internal/network"
	"testing"
)

func TestStaticDiscoverer_FindPeer_Sucess(t *testing.T) {
	targetID := bytes.Repeat([]byte{0x0A}, 32)
	bootstrapPeer, _ := domain.NewPeer(targetID, []string{"192.168.1.10:9000"}, nil)

	// Create the discoverer with our known inviter peer
	discoverer := network.NewStaticDiscoverer([]*domain.Peer{bootstrapPeer})

	peer, err := discoverer.FindPeer(targetID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(peer.ID, targetID) {
		t.Errorf("expected ID %v, got %v", targetID, peer.ID)
	}

	if len(peer.Addresses) == 0 {
		t.Errorf("expected peer to have at least one address, got none")
	}

	if peer.Addresses[0] != "192.168.1.10:9000" {
		t.Errorf("expected address %v, got %v", "192.168.1.10:9000", peer.Addresses[0])
	}
}

func TestStaticDiscoverer_FindPeer_NotFound(t *testing.T) {
	targetID := bytes.Repeat([]byte{0x0B}, 32)
	bootstrapPeer, _ := domain.NewPeer(bytes.Repeat([]byte{0x0A}, 32), []string{"192.168.1.10:9000"}, nil)

	discoverer := network.NewStaticDiscoverer([]*domain.Peer{bootstrapPeer})

	_, err := discoverer.FindPeer(targetID)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}
