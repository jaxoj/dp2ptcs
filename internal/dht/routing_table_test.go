package dht_test

import (
	"bytes"
	"dp2ptcs/internal/dht"
	"testing"
)

func TestRoutingTable_AddPeer_Success(t *testing.T) {
	localID := bytes.Repeat([]byte{0x00}, 32)
	table := dht.NewRoutingTable(localID, 2) // k=2 for testing

	// Create a peer that is exactly one but different (should go to bucket 255)
	remoteID := bytes.Repeat([]byte{0x00}, 32)
	remoteID[31] = 0x01
	peer, _ := dht.NewPeer(remoteID, []string{"10.0.0.2:9000"})

	added := table.AddPeer(peer)

	if !added {
		t.Fatal("Expected peer to be added to the routing table")
	}
	if table.TotalPeers() != 1 {
		t.Errorf("expected 1 peer in table, got %d", table.TotalPeers())
	}
}

func TestRoutingTable_AddPeer_RejectSelf(t *testing.T) {
	localID := bytes.Repeat([]byte{0x00}, 32)
	table := dht.NewRoutingTable(localID, 2)
	selfPeer, _ := dht.NewPeer(localID, []string{"10.0.0.1:9000"})

	added := table.AddPeer(selfPeer)

	if added {
		t.Error("Routing table should not add the local node to its own buckets")
	}
}

func TestRoutingTable_BucketFull(t *testing.T) {
	localID := bytes.Repeat([]byte{0x00}, 32)
	table := dht.NewRoutingTable(localID, 2) // bucket limit is 2

	// Create 3 peers that will all fall into the same bucket
	for i := 1; i <= 3; i++ {
		remoteID := bytes.Repeat([]byte{0x00}, 32)
		remoteID[31] = 0x80 + byte(i) // 0x01, 0x02, 0x03 will all have similar distances
		peer, _ := dht.NewPeer(remoteID, []string{"10.0.0.x:9000"})

		added := table.AddPeer(peer)

		// Assert
		if i <= 2 && !added {
			t.Errorf("Expected peer %d to be added", i)
		}
		if i == 3 && added {
			t.Error("Expected 3rd peer to be rejected because the bucket is full")
		}
	}
}

func TestRoutingTable_ClosestPeers(t *testing.T) {
	localID := bytes.Repeat([]byte{0xFF}, 32)
	table := dht.NewRoutingTable(localID, 20)

	targetID := bytes.Repeat([]byte{0x00}, 32)

	// Create IDs with specific differences at the last byte
	p1ID := bytes.Repeat([]byte{0x00}, 32)
	p1ID[31] = 0x04 // Distance: 4
	p2ID := bytes.Repeat([]byte{0x00}, 32)
	p2ID[31] = 0x01 // Distance: 1
	p3ID := bytes.Repeat([]byte{0x00}, 32)
	p3ID[31] = 0x02 // Distance: 2

	p1, _ := dht.NewPeer(p1ID, []string{"10.0.0.1:9000"})
	p2, _ := dht.NewPeer(p2ID, []string{"10.0.0.2:9000"})
	p3, _ := dht.NewPeer(p3ID, []string{"10.0.0.3:9000"})

	// Add them out of order
	table.AddPeer(p1)
	table.AddPeer(p2)
	table.AddPeer(p3)

	// Request the 2 closest peers to the target
	closest := table.ClosestPeers(targetID, 2)

	if len(closest) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(closest))
	}

	// p2 is distance 1 (Closest)
	if !bytes.Equal(closest[0].ID, p2ID) {
		t.Errorf("expected closest peer to be p2 (distance 1)")
	}

	// p3 is distance 2 (Second Closest)
	if !bytes.Equal(closest[1].ID, p3ID) {
		t.Errorf("expected second closest peer to be p3 (distance 2)")
	}
}
