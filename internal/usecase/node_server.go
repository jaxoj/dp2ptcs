package usecase

import (
	"context"
	"dp2ptcs/internal/crypto"
	"dp2ptcs/internal/messaging"
	"dp2ptcs/internal/transport"
	"log"
)

// MessageHandler is a callback function defined by the higher-level application
// to dictate what happens when a valid message arrives.
type MessageHandler func(msg messaging.Message)

type NodeServer struct {
	transport  transport.Transport
	serializer messaging.Serializer
	sessionMgr crypto.SessionManager
}

func NewNodeServer(tr transport.Transport, ser messaging.Serializer, sm crypto.SessionManager) *NodeServer {
	return &NodeServer{transport: tr, serializer: ser, sessionMgr: sm}
}

// Start binds to the given address and begins blocking to accept connections.
// It uses the provided context for graceful shutdown.
func (s *NodeServer) Start(ctx context.Context, address string, handler MessageHandler) error {
	listener, err := s.transport.Listen(address)
	if err != nil {
		return err
	}
	defer listener.Close()

	// Ensure the listener closes when the context is cancelled
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		// Accept a new physical QUIC Connection
		conn, err := listener.Accept()
		if err != nil {
			// If context is cancelled, exit gracefully
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		// Handle the connection concurrently so we don't block other peers
		go s.handleConnection(ctx, conn, handler)
	}
}

func (s *NodeServer) handleConnection(ctx context.Context, conn transport.Connection, handler MessageHandler) {
	defer conn.Close()

	for {
		// Accept a new multiplexed Stream on this connection
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return // Connection closed or context cancelled
		}

		// Handle the stream concurrently. If a peer opens 5 streams, they process in parallel.
		go s.handleStream(stream, handler)
	}
}

func (s *NodeServer) handleStream(stream transport.Stream, handler MessageHandler) {
	defer stream.Close()

	// Decode the stream into an encrypted Message struct using our abstraction
	msg, err := s.serializer.Decode(stream)
	if err != nil {
		log.Printf("Failed to decode incoming stream: %v", err)
		return
	}

	// Fetch the stateful cryptographic session for this specific sender
	session, err := s.sessionMgr.GetSession(msg.SenderID)
	if err != nil {
		log.Printf("Failed to retrieve secure session for peer %x: %v", msg.SenderID, err)
		return
	}

	// Ratchet the keys and decrypt the payload
	decryptedPayload, err := session.Decrypt(msg.Payload)
	if err != nil {
		log.Printf("Failed to decrypt payload from peer %x: %v", msg.SenderID, err)
		// Drop the message. Do not pass unauthenticated/undecryptable data to the application.
		return
	}

	// Overwrite the ciphertext with the plaintext and pass to the application
	msg.Payload = decryptedPayload
	handler(msg)
}
