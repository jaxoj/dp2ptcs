package usecase

import (
	"dp2ptcs/internal/domain"
	"dp2ptcs/internal/transport"
	"errors"
)

// ErrConnectionFailed is returned when a peer is resolved, but none of its physical addresses are reachable.
var ErrConnectionFailed = errors.New("failed to connect to any known addresses for peer")

// ConnectionManager orchestrates the resolution and connection to remote peers.
type ConnectionManager struct {
	discoverer domain.Discoverer
	transport  transport.Transport
}

func NewConnectionManager(discoverer domain.Discoverer, tr transport.Transport) *ConnectionManager {
	return &ConnectionManager{discoverer: discoverer, transport: tr}
}

// ResolvePeer queries the discovery mechanism to find the physical network addresses.
func (cm *ConnectionManager) ResolvePeer(targetID []byte) (*domain.Peer, error) {
	if len(targetID) != 32 {
		return nil, domain.ErrInvalidNodeID
	}

	peer, err := cm.discoverer.FindPeer(targetID)
	if err != nil {
		return nil, err
	}

	return peer, nil
}

// ConnectToPeer resolves the peer's logical ID to physical addresses,
// then attempts to establish a secure transport connection.
func (cm *ConnectionManager) ConnectToPeer(targetID []byte) (transport.Connection, error) {
	// Resolve the peer
	peer, err := cm.discoverer.FindPeer(targetID)
	if err != nil {
		return nil, err
	}

	// Iterate through all known addresses and attempt to dial.
	// In a tactical environment, the first successful connection wins.
	for _, address := range peer.Addresses {
		conn, err := cm.transport.Dial(address)
		if err == nil {
			// Connection established
			return conn, nil
		}
		// If dial fails, we simply log it (omitted for brevity) and try the next address
	}
	// If we exhaust all addresses without success, the peer is physically unreachable.
	return nil, ErrConnectionFailed
}
