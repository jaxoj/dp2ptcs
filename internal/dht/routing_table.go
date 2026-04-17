package dht

import (
	"bytes"
	"dp2ptcs/internal/domain"
	"math/bits"
	"sort"
	"sync"
)

// RoutingTable manages the k-buckets for a local Kademlia node.
// It is thread-safe to handle concurrent discovery events.
type RoutingTable struct {
	localID []byte
	k       int
	// 256 buckets for a 256-bit ID space
	buckets [256][]*domain.Peer
	mu      sync.RWMutex
}

func NewRoutingTable(localID []byte, bucketSize int) *RoutingTable {
	return &RoutingTable{
		localID: localID,
		k:       bucketSize,
	}
}

func (rt *RoutingTable) K() int {
	return rt.k
}

// AddPeer attempts to insert a peer into the appropriate k-bucket.
// Returns true if added, false if the bucket is full or the peer is ourselves.
func (rt *RoutingTable) AddPeer(peer *domain.Peer) bool {
	if bytes.Equal(rt.localID, peer.ID) {
		return false // cannot add ourselves
	}

	distance, err := XORDistance(rt.localID, peer.ID)
	if err != nil {
		return false
	}

	bucketIndex := bucketIndex(distance)

	rt.mu.Lock()
	defer rt.mu.Unlock()

	bucket := rt.buckets[bucketIndex]

	// Check if peer already exists in the bucket
	for i, p := range bucket {
		if bytes.Equal(peer.ID, p.ID) {
			// Move the peer to the tail (to be the most recently seen)
			bucket = append(bucket[:i], bucket[i+1:]...)
			bucket = append(bucket, p)
			return true
		}
	}

	// Check if bucket is full
	if len(bucket) >= rt.k {
		// In a full implementation, we'd ping the oldest node before dropping this one.
		// TODO: if the oldest node is not responding (drop it and add this one)
		return false
	}

	rt.buckets[bucketIndex] = append(rt.buckets[bucketIndex], peer)
	return true
}

// TotalPeers returns the total number of peers stored across all buckets.
func (rt *RoutingTable) TotalPeers() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	count := 0
	for _, bucket := range rt.buckets {
		count += len(bucket)
	}
	return count
}

// ClosestPeers returns the 'count' number of peers from the routing table
// that are mathematically closest to the provided targetID.
func (rt *RoutingTable) ClosestPeers(targeID []byte, count int) []*domain.Peer {
	rt.mu.RLock()

	// Gather all peers from all buckets
	// TODO: In a heavily optimized implementation, we would only search the target's bucket
	// and fan out to adjacent buckets. For tactical constraints (max 5120 nodes),
	// sorting the whole slice is highly performant and extremely robust.
	var allPeers []*domain.Peer
	for _, bucket := range rt.buckets {
		allPeers = append(allPeers, bucket...)
	}
	rt.mu.RUnlock()

	// Sort the slice mathematically using XOR distance
	sort.Slice(allPeers, func(i, j int) bool {
		distI, _ := XORDistance(allPeers[i].ID, targeID)
		distJ, _ := XORDistance(allPeers[j].ID, targeID)

		// bytes.Compare returns -1 if distI is lexicographically (mathematically) smaller than distJ
		return bytes.Compare(distI, distJ) < 0
	})

	// Prevent out-of-bounds panics if we have fewer peers than requested
	// and return up to count peers
	if len(allPeers) < count {
		count = len(allPeers)
	}
	return allPeers[:count]
}

// bucketIndex calculates the bucket index based on the number of leading zeros
// in the XOR distance. Index ranges from 0 to 255.
func bucketIndex(distance []byte) int {
	leadingZeros := 0
	for _, b := range distance {
		if b == 0 {
			leadingZeros += 8
		} else {
			leadingZeros += bits.LeadingZeros8(b)
			break
		}
	}

	// If distance is all zeros (same ID), it goes to bucket 0.
	// Otherwise, we group them such that distance 1 is index 0, distance 2 is index 1, etc.
	// For 256 bits, the index is 256 - leadingZeros - 1.
	if leadingZeros == 256 {
		return 0
	}
	return 256 - leadingZeros - 1
}
