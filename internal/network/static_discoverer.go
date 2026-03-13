package network

import "dp2ptcs/internal/dht"

// StaticDiscoverer is an Interface Adapter that implements dht.Discoverer.
// It uses a hardcoded, in-memory list of peers (e.g., bootstrap nodes).
type StaticDiscoverer struct {
	// We use a string representation of the byte slice as the map key
	// for O(1) lookups.
	directory map[string]*dht.Peer
}

func NewStaticDiscoverer(peers []*dht.Peer) *StaticDiscoverer {
	dir := make(map[string]*dht.Peer)
	for _, peer := range peers {
		dir[string(peer.ID)] = peer
	}
	return &StaticDiscoverer{directory: dir}
}

func (sd *StaticDiscoverer) FindPeer(targetID []byte) (*dht.Peer, error) {
	peer, exists := sd.directory[string(targetID)]
	if !exists {
		return nil, dht.ErrPeerNotFound
	}
	return peer, nil
}
