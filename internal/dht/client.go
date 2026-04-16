package dht

import (
	"context"
	"dp2ptcs/internal/domain"
)

// RPCClient defines the outbound network operations for the DHT.
type RPCClient interface {
	// FindNode requests the k closest peers to the targetID from the specified peer.
	FindNode(ctx context.Context, peer *domain.Peer, targetID []byte) ([]*domain.Peer, error)
}
