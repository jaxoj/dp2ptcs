package domain

import "errors"

// ErrInvalidNodeID is returned when a Node ID is not exactly 32 bytes (256 bits).
var ErrInvalidNodeID = errors.New("Node ID must be 32 bytes long")

// ErrPeerNotFound is returned by a Discoverer when the requested peer cannot be located.
var ErrPeerNotFound = errors.New("Peer not found in the network")

// Peer represents a remote node in the tactical network.
// It resides in the Entity layer of Clean Architecture.
type Peer struct {
	ID        []byte   // 32-byte unique identifier for the peer
	Addresses []string // List of network addresses"
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
