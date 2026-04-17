package dht

import (
	"context"
	"dp2ptcs/internal/domain"
	"dp2ptcs/internal/handshake"
	"dp2ptcs/internal/messaging"
	"dp2ptcs/internal/messaging/pb"
	"dp2ptcs/internal/transport"
	"errors"
	"log"

	"google.golang.org/protobuf/proto"
)

type NetworkRPCClient struct {
	dialer     transport.MultiDialer
	serializer messaging.Serializer
	handshake  *handshake.HandshakeProtocol
	localID    []byte
}

func NewNetworkRPCClient(dialer transport.MultiDialer, ser messaging.Serializer, hs *handshake.HandshakeProtocol, localID []byte) *NetworkRPCClient {
	return &NetworkRPCClient{
		dialer:     dialer,
		serializer: ser,
		handshake:  hs,
		localID:    localID,
	}
}

// FindNode dials a peer, secures the stream, and executes the FIND_NODE RPC.
func (c *NetworkRPCClient) FindNode(ctx context.Context, peer *domain.Peer, targetID []byte) ([]*domain.Peer, error) {
	if len(peer.Addresses) == 0 {
		return nil, errors.New("peer has no known addresses")
	}

	// Dial the peer's known addresses using Happy Eyeballs style fallback.
	conn, err := c.dialer.DialAddresses(ctx, peer.Addresses)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Open a fresh multiplexed stream
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	// Execute the X3DH Handshake as the Initiator
	session, err := c.handshake.Initiate(ctx, stream)
	if err != nil {
		return nil, errors.New("failed to establish secure session with peer")
	}

	// Construct the Protobuf payload
	req := &pb.FindNodeRequest{
		TargetId: targetID,
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}

	// Encrypt the payload using the Double Ratchet
	ciphertext, dhPubKey, msgNum, prevLen, err := session.Encrypt(reqBytes)
	if err != nil {
		return nil, err
	}

	// Frame the message
	msg := messaging.Message{
		SenderID:            c.localID,
		Type:                messaging.TypeDHT,
		DHPublicKey:         dhPubKey,
		Payload:             ciphertext,
		MessageNumber:       msgNum,
		PreviousChainLength: prevLen,
	}

	// Send the request over the wire
	if err := c.serializer.Encode(stream, msg); err != nil {
		return nil, err
	}

	// Wait for and decode the response frame
	respMsg, err := c.serializer.Decode(stream)
	if err != nil {
		return nil, err
	}

	// Decrypt the response
	plaintext, err := session.Decrypt(respMsg.Payload, respMsg.DHPublicKey, respMsg.MessageNumber, respMsg.PreviousChainLength)
	if err != nil {
		return nil, errors.New("failed to authenticate DHT response")
	}

	// Unmarshal the Protobuf response
	var resp pb.FindNodeResponse
	if err := proto.Unmarshal(plaintext, &resp); err != nil {
		return nil, err
	}

	// Map the Protobuf DTOs back to our Domain Entities
	var closestPeers []*domain.Peer
	for _, pInfo := range resp.ClosestPeers {
		peerObj, err := domain.NewPeer(pInfo.Id, pInfo.Addresses)
		if err != nil {
			log.Printf("Received invalid peer ID in DHT response: %v", err)
			continue // Skip malformed peers, don't crash the routing lookup
		}
		closestPeers = append(closestPeers, peerObj)
	}

	return closestPeers, nil
}
