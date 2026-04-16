package dht

// DHTService handles the control-plane logic for decentralized discovery.
type DHTService struct {
	Table *RoutingTable
}

func NewDHTService(table *RoutingTable) *DHTService {
	return &DHTService{Table: table}
}

func (s *DHTService) HandleFindNode(targetID []byte) []*Peer {
	// We use the k value defined when the routing table was initialized
	return s.Table.ClosestPeers(targetID, s.Table.k)
}
