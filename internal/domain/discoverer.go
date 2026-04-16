package domain

// Discoverer defines the interface for finding peers in the network.
// This allows us to abstract away the underlying discovery mechanism (e.g., mDNS, Kademlia DHT).
type Discoverer interface {
	// FindPeer attempts to locate a peer by its Node ID.
	// It returns the Peer if found, or an error if not found or if discovery fails.
	FindPeer(id []byte) (*Peer, error)
}
