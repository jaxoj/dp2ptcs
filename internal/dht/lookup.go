package dht

import (
	"bytes"
	"dp2ptcs/internal/domain"
	"sort"
	"sync"
)

// LookupTask manages the state of an iterative search for a target NodeID.
type LookupTask struct {
	targetID []byte
	k        int

	shortlist []*domain.Peer
	visited   map[string]bool
	mu        sync.Mutex
}

func NewLookupTask(target []byte, k int, initialPeers []*domain.Peer) *LookupTask {
	return &LookupTask{targetID: target, k: k, shortlist: initialPeers, visited: make(map[string]bool)}
}

// Run executes the iterative lookup logic.
// TODO: In a real implementation, this would involve concurrent RPC calls to peers.
func (t *LookupTask) GetNextToQuery() []*domain.Peer {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Sort shortlist by distance to target
	sort.Slice(t.shortlist, func(i, j int) bool {
		distI, _ := XORDistance(t.shortlist[i].ID, t.targetID)
		distJ, _ := XORDistance(t.shortlist[j].ID, t.targetID)
		return bytes.Compare(distI, distJ) < 0
	})

	var toQuery []*domain.Peer
	for _, p := range t.shortlist {
		idStr := string(p.ID)
		if !t.visited[idStr] {
			toQuery = append(toQuery, p)
			t.visited[idStr] = true
			if len(toQuery) == 3 { // Alpha parameter: query 3 peers in parallel
				break
			}
		}
	}
	return toQuery
}

// AddPeers ingests newly discovered peers into the shortlist, ensuring no duplicates.
func (t *LookupTask) AddPeers(peers []*domain.Peer) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Use the visited map's keys (or a separate map) to track uniqueness
	existing := make(map[string]bool)
	for _, p := range t.shortlist {
		existing[string(p.ID)] = true
	}

	for _, p := range peers {
		if !existing[string(p.ID)] {
			t.shortlist = append(t.shortlist, p)
			existing[string(p.ID)] = true
		}
	}
}

// GetClosest returns the top k closest peers from the current shortlist.
func (t *LookupTask) GetClosest() []*domain.Peer {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Ensure they are strictly sorted before returning
	sort.Slice(t.shortlist, func(i, j int) bool {
		distI, _ := XORDistance(t.shortlist[i].ID, t.targetID)
		distJ, _ := XORDistance(t.shortlist[j].ID, t.targetID)
		return bytes.Compare(distI, distJ) < 0
	})

	if len(t.shortlist) > t.k {
		return t.shortlist[:t.k]
	}
	return t.shortlist
}
