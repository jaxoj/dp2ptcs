package main

import (
	"dp2ptcs/internal/dht"
	"dp2ptcs/internal/messaging"
	"dp2ptcs/internal/messaging/pb"
	"log"

	"google.golang.org/protobuf/proto"
)

// AppRouter connects incoming network messages to the correct internal services.
type AppRouter struct {
	dhtService *dht.DHTService
	localID    []byte
}

func NewAppRouter(dhtSvc *dht.DHTService, localID []byte) *AppRouter {
	return &AppRouter{
		dhtService: dhtSvc,
		localID:    localID,
	}
}

// HandleMessage is the concrete implementation of usecase.MessageHandler.
func (r *AppRouter) HandleMessage(msg messaging.Message) *messaging.Message {
	switch msg.Type {

	case messaging.TypeCommand:
		log.Printf("Received Command Payload: %s", string(msg.Payload))
		// Route to Command/Control execution logic
		return nil // Commands might be one-way, so no immediate stream reply

	case messaging.TypeTelemetry:
		log.Printf("Received Telemetry Data: %s", string(msg.Payload))
		// Route to health monitoring service
		return nil

	case messaging.TypeDHT:
		// Unmarshal the incoming request
		var req pb.FindNodeRequest
		if err := proto.Unmarshal(msg.Payload, &req); err != nil {
			log.Printf("Failed to unmarshal DHT request: %v", err)
			return nil
		}

		// Query our local Routing Table via the DHT Service
		closestPeers := r.dhtService.HandleFindNode(req.TargetId)

		// Map the domain Peers to Protobuf PeerInfos
		var pbPeers []*pb.PeerInfo
		for _, p := range closestPeers {
			pbPeers = append(pbPeers, &pb.PeerInfo{
				Id:        p.ID,
				Addresses: p.Addresses,
			})
		}

		// Construct the Protobuf Response
		resp := &pb.FindNodeResponse{
			ClosestPeers: pbPeers,
		}
		respBytes, err := proto.Marshal(resp)
		if err != nil {
			log.Printf("Failed to marshal DHT response: %v", err)
			return nil
		}

		// Return the plaintext response message.
		// The NodeServer will intercept this, Double-Ratchet encrypt it, and send it.
		return &messaging.Message{
			SenderID: r.localID,
			Type:     messaging.TypeDHT,
			Payload:  respBytes,
		}

	default:
		log.Printf("Unknown message type received: %d", msg.Type)
		return nil
	}
}
