package network

import (
	"bytes"
	"dp2ptcs/internal/domain"
)

// RPCClient defines the network capabilities required by the Kademlia protocol.
// It abstracts the underlying transport (UDP/QUIC) away from the discoverer.
type RPCClient interface {
	// FindNode sends a FIND_NODE RPC to a specific remote peer.
	// It returns a list of peers that the remote node thinks are closest to the target.
	FindNode(targetID []byte, remote *domain.Peer) ([]*domain.Peer, error)
}

// KademliaDiscoverer implements domain.Discoverer using the Kademlia protocol.
type KademliaDiscoverer struct {
	rpc RPCClient
	// For this initial minimal implementation, we hardcode a single entry point.
	// TODO: Later, this will be replaced by pulling the closest peers from our dht.RoutingTable.
	entryPeer *domain.Peer
}

// NewKademliaDiscoverer creates a new network adapter for DHT discovery.
func NewKademliaDiscoverer(rpc RPCClient, entryPeer *domain.Peer) *KademliaDiscoverer {
	return &KademliaDiscoverer{
		rpc:       rpc,
		entryPeer: entryPeer,
	}
}

// FindPeer queries the network for a specific Node ID
func (k *KademliaDiscoverer) FindPeer(targetID []byte) (*domain.Peer, error) {
	// Send the FIND_NODE RPC to our known entry peer
	returnedPeers, err := k.rpc.FindNode(targetID, k.entryPeer)
	if err != nil {
		// If the network call fails, we haven't found the peer
		return nil, domain.ErrPeerNotFound
	}

	// Parse the response. Did the remote node give us the exact peer we want?
	for _, peer := range returnedPeers {
		if bytes.Equal(peer.ID, targetID) {
			return peer, nil
		}
	}

	// In a full recursive Kademlia lookup, if we didn't find the target here,
	// TODO: we would add these returnedPeers to a shortlist and query the closest ones.
	// For now, if it's not in the immediate response, we return not found.
	return nil, domain.ErrPeerNotFound
}
