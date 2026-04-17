package usecase

import (
	"context"
	"dp2ptcs/internal/crypto"
	"dp2ptcs/internal/messaging"
	"dp2ptcs/internal/transport"
	"io"
	"log"
)

// MessageHandler is a callback function defined by the higher-level application
// to dictate what happens when a valid message arrives.
type MessageHandler func(msg messaging.Message) *messaging.Message

// Handshaker defines the interface for intercepting a stream and establishing a secure session.
type Handshaker interface {
	Respond(ctx context.Context, stream io.ReadWriter) (crypto.SecureSession, []byte, error)
}

type NodeServer struct {
	transport  transport.Transport
	serializer messaging.Serializer
	sessionMgr crypto.SessionManager
	handshaker Handshaker // Decoupled interface
}

func NewNodeServer(tr transport.Transport, ser messaging.Serializer, sm crypto.SessionManager, hs Handshaker) *NodeServer {
	return &NodeServer{transport: tr, serializer: ser, sessionMgr: sm, handshaker: hs}
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

		// Perform handshake on this stream and store the resulting session
		session, remoteIdentPub, err := s.handshaker.Respond(ctx, stream)
		if err != nil {
			log.Printf("Handshake failed: %v", err)
			stream.Close()
			continue
		}
		s.sessionMgr.SetSession(remoteIdentPub, session)

		// Handle the stream concurrently. If a peer opens 5 streams, they process in parallel.
		go s.handleStream(stream, handler, session, remoteIdentPub)
	}
}

// handleSecureStream enforces the X3DH Handshake before allowing Protobuf parsing.
func (s *NodeServer) handleStream(stream transport.Stream, handler MessageHandler, session crypto.SecureSession, remoteIdentPub []byte) {
	defer stream.Close()

	for {

		// Decode the stream into an encrypted Message struct using our abstraction
		msg, err := s.serializer.Decode(stream)
		if err != nil {
			if err == io.EOF {
				log.Printf("Peer %x closed the stream cleanly.", remoteIdentPub[:8])
				return
			}
			log.Printf("Framing error or stream drop: %v", err)
			return
		}

		// Ratchet the keys (if necessary) and decrypt the payload
		// Notice we are now passing the msg.DHPublicKey from the header into the Decrypt method
		decryptedPayload, err := session.Decrypt(msg.Payload, msg.DHPublicKey, msg.MessageNumber, msg.PreviousChainLength)
		if err != nil {
			log.Printf("Decryption MAC failure from peer %x: tampering detected, dropping frame.", remoteIdentPub[:8]) // Drop the message. Do not pass unauthenticated/undecryptable data to the application.
			continue
		}

		// Overwrite the ciphertext with the plaintext and pass to the application
		msg.Payload = decryptedPayload

		// Execute the handler

		responseMsg := handler(msg)

		// If the application provided a response (e.g., a DHT reply), encrypt and send it back
		if responseMsg != nil {
			cipherResp, dhPubResp, msgNum, prevLen, err := session.Encrypt(responseMsg.Payload)
			if err != nil {
				log.Printf("Failed to encrypt response for peer %x: %v", remoteIdentPub[:8], err)
				continue
			}

			responseMsg.Payload = cipherResp
			responseMsg.DHPublicKey = dhPubResp
			responseMsg.MessageNumber = msgNum
			responseMsg.PreviousChainLength = prevLen

			if err := s.serializer.Encode(stream, *responseMsg); err != nil {
				log.Printf("Failed to write response to peer %x: %v", remoteIdentPub[:8], err)
				return
			}
		}
	}

}
