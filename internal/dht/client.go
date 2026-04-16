package dht

import "context"

// RPCClient defines the outbound network operations for the DHT.
type RPCClient interface {
	// FindNode requests the k closest peers to the targetID from the specified peer.
	FindNode(ctx context.Context, peer *Peer, targetID []byte) ([]*Peer, error)
}
