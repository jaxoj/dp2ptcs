package usecase

import "dp2ptcs/internal/dht"

// ConnectionManager orchestrates the resolution and connection to remote peers.
type ConnectionManager struct {
	discoverer dht.Discoverer
}

func NewConnectionManager(discoverer dht.Discoverer) *ConnectionManager {
	return &ConnectionManager{discoverer: discoverer}
}

func (cm *ConnectionManager) ResolvePeer(targetID []byte) (*dht.Peer, error) {
	if len(targetID) != 32 {
		return nil, dht.ErrInvalidNodeID
	}

	peer, err := cm.discoverer.FindPeer(targetID)
	if err != nil {
		return nil, err
	}

	return peer, nil
}
