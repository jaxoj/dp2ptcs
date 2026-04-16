package usecase

import (
	"bytes"
	"context"
	"dp2ptcs/internal/dht"
	"errors"
	"sync"
	"time"
)

type DiscoveryManager struct {
	dhtService *dht.DHTService
	rpcClient  dht.RPCClient // New dependency for outbound calls
	localID    []byte        // Our own NodeID
}

func NewDiscoveryManager(service *dht.DHTService, client dht.RPCClient, localID []byte) *DiscoveryManager {
	return &DiscoveryManager{
		dhtService: service,
		rpcClient:  client,
		localID:    localID,
	}
}

// Bootstrap connects to a known entry-point node to join the network.
func (m *DiscoveryManager) Bootstrap(ctx context.Context, bootstrapPeer *dht.Peer) error {
	// Manually add the bootstrap node to our own routing table
	// (Assuming you add an AddPeer method to DHTService or expose the table)
	m.dhtService.Table.AddPeer(bootstrapPeer)

	// Send a FIND_NODE request for our OWN ID
	// Set a strict timeout so a dead bootstrap node doesn't hang the startup
	rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	closestPeers, err := m.rpcClient.FindNode(rpcCtx, bootstrapPeer, m.localID)
	if err != nil {
		return err // Failed to contact the bootstrap node
	}

	// Populate our routing table with the results
	for _, p := range closestPeers {
		m.dhtService.Table.AddPeer(p)
	}

	return nil
}

// FindPeer attempts to resolve a NodeID into a list of IP addresses.
func (m *DiscoveryManager) FindPeer(ctx context.Context, targetID []byte) ([]string, error) {
	initialPeers := m.dhtService.Table.ClosestPeers(targetID, m.dhtService.Table.K())
	if len(initialPeers) == 0 {
		return nil, errors.New("routing table empty, cannot route")
	}

	// Initialize the state machine
	task := dht.NewLookupTask(targetID, m.dhtService.Table.K(), initialPeers)

	// The iterative loop
	for {
		toQuery := task.GetNextToQuery()
		if len(toQuery) == 0 {
			break // No more unvisited peers, lookup converged
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		var newlyDiscovered []*dht.Peer

		// Execute concurrent RPCs
		for _, p := range toQuery {
			wg.Add(1)
			go func(peer *dht.Peer) {
				defer wg.Done()

				// Short timeout for individual hops in a tactical environment
				hopCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()

				foundPeers, err := m.rpcClient.FindNode(hopCtx, peer, targetID)
				if err != nil {
					mu.Lock()
					newlyDiscovered = append(newlyDiscovered, foundPeers...)
					mu.Unlock()

					// As we traverse the network, add responsive nodes to our local table!
					m.dhtService.Table.AddPeer(peer)
				}
			}(p)
		}

		// Wait for this alpha-batch to finish
		wg.Wait()

		// Feed the new peers back into the state machine
		task.AddPeers(newlyDiscovered)
	}

	// Did we find the target?
	closest := task.GetClosest()
	for _, p := range closest {
		if bytes.Equal(p.ID, targetID) {
			return p.Addresses, nil
		}
	}
	return nil, errors.New("peer not found in network")
}
