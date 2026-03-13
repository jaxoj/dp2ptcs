package dht

import "errors"

// ErrInvalidNodeID is returned when a Node ID is not exactly 32 bytes (256 bits).
var ErrInvalidNodeID = errors.New("Node ID must be 32 bytes long")

// ErrPeerNotFound is returned by a Discoverer when the requested peer cannot be located.
var ErrPeerNotFound = errors.New("Peer not found in the network")

// Peer represents a remote node in the tactical network.
// It resides in the Entity layer of Clean Architecture.
type Peer struct {
	ID        []byte   // 32-byte unique identifier for the peer
	Addresses []string // List of network addresses (e.g., "
}

func NewPeer(id []byte, addresses []string) (*Peer, error) {
	if len(id) != 32 {
		return nil, ErrInvalidNodeID
	}

	return &Peer{
		ID:        id,
		Addresses: addresses,
	}, nil
}

// Discoverer defines the interface for finding peers in the network.
// This allows us to abstract away the underlying discovery mechanism (e.g., mDNS, Kademlia DHT).
type Discoverer interface {
	// FindPeer attempts to locate a peer by its Node ID.
	// It returns the Peer if found, or an error if not found or if discovery fails.
	FindPeer(id []byte) (*Peer, error)
}
