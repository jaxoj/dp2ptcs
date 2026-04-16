package domain_test

import (
	"bytes"
	"dp2ptcs/internal/domain"
	"testing"
)

func TestNewPeer_Success(t *testing.T) {
	validID := bytes.Repeat([]byte{0x01}, 32) // 32-bytes valid ID
	addresses := []string{"192.168.1.100:9000", "10.0.0.5:9000"}

	peer, err := domain.NewPeer(validID, addresses)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(peer.ID, validID) {
		t.Errorf("expected ID %v, got %v", validID, peer.ID)
	}

	if len(peer.Addresses) != len(addresses) {
		t.Errorf("expected %d addresses, got %d", len(addresses), len(peer.Addresses))
	}
}

func TestNewPeer_InvalidIDLength(t *testing.T) {
	invalidID := bytes.Repeat([]byte{0x01}, 16) // 16-bytes invalid ID
	addresses := []string{"192.168.1.100:9000", "10.0.0.5:9000"}

	_, err := domain.NewPeer(invalidID, addresses)
	if err != domain.ErrInvalidNodeID {
		t.Fatalf("expected error %v, got %v", domain.ErrInvalidNodeID, err)
	}
}
