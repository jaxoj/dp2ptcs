package network

import (
	"dp2ptcs/internal/domain"
)

// StaticDiscoverer is an Interface Adapter that implements domain.Discoverer.
// It uses a hardcoded, in-memory list of peers (e.g., bootstrap nodes).
type StaticDiscoverer struct {
	// We use a string representation of the byte slice as the map key
	// for O(1) lookups.
	directory map[string]*domain.Peer
}

func NewStaticDiscoverer(peers []*domain.Peer) *StaticDiscoverer {
	dir := make(map[string]*domain.Peer)
	for _, peer := range peers {
		dir[string(peer.ID)] = peer
	}
	return &StaticDiscoverer{directory: dir}
}

func (sd *StaticDiscoverer) FindPeer(targetID []byte) (*domain.Peer, error) {
	peer, exists := sd.directory[string(targetID)]
	if !exists {
		return nil, domain.ErrPeerNotFound
	}
	return peer, nil
}
