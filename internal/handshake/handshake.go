package handshake

import (
	"context"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"dp2ptcs/internal/messaging"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

// HandshakeProtocol manages the transition of a raw stream into an End-to-End Encrypted stream.
type HandshakeProtocol struct {
	localIdentPriv []byte
	localIdentPub  []byte
}

func NewHandshakeProtocol(identPriv, identPub []byte) *HandshakeProtocol {
	return &HandshakeProtocol{localIdentPriv: identPriv, localIdentPub: identPub}
}

// Initiate is called by the node dialing outbound to a peer.
func (h *HandshakeProtocol) Initiate(ctx context.Context, stream io.ReadWriter) (crypto.SecureSession, error) {
	// Generate local Ephemeral key pair for this specific connection
	ephemPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ephemPriv); err != nil {
		return nil, err
	}
	ephemPub, _ := curve25519.X25519(ephemPriv, curve25519.Basepoint)

	// Send our public keys to the responder
	outboundMsg := messaging.HandshakeExchange{
		IdentityPub:  h.localIdentPub,
		EphemeralPub: ephemPub,
	}
	if err := outboundMsg.WriteTo(stream); err != nil {
		return nil, err
	}

	// Read the responder's public keys
	var inboundMsg messaging.HandshakeExchange
	if err := inboundMsg.ReadFrom(stream); err != nil {
		return nil, errors.New("failed to read responder handshake")
	}

	// Compute the X3DH Root Key
	rootKey, err := crypto.InitiateX3DH(
		h.localIdentPriv, ephemPriv,
		inboundMsg.IdentityPub, inboundMsg.EphemeralPub,
	)
	if err != nil {
		return nil, err
	}

	// Initialize and return the state machine
	session := crypto.NewDoubleRatchetSession(rootKey, ephemPriv, ephemPub, inboundMsg.EphemeralPub)
	return session, nil
}

// Respond is called by the NodeServer when a new inbound connection is accepted.
func (h *HandshakeProtocol) Respond(ctx context.Context, stream io.ReadWriter) (crypto.SecureSession, []byte, error) {
	// Read the initiator's public keys FIRST
	var inboundMsg messaging.HandshakeExchange
	if err := inboundMsg.ReadFrom(stream); err != nil {
		return nil, nil, errors.New("failed to read initiator handshake")
	}

	// Generate local Ephemeral key pair for this specific connection
	ephemPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ephemPriv); err != nil {
		return nil, nil, err
	}
	ephemPub, _ := curve25519.X25519(ephemPriv, curve25519.Basepoint)

	// Send our public keys back to the initiator
	outboundMsg := messaging.HandshakeExchange{
		IdentityPub:  h.localIdentPub,
		EphemeralPub: ephemPub,
	}
	if err := outboundMsg.WriteTo(stream); err != nil {
		return nil, nil, errors.New("failed to write responder handshake")
	}

	// Compute the X3DH Root key (Using Respond Math)
	rootKey, err := crypto.RespondX3DH(h.localIdentPriv, ephemPriv, inboundMsg.IdentityPub, inboundMsg.EphemeralPub)
	if err != nil {
		return nil, nil, err
	}

	// Initialize and return the state machine
	session := crypto.NewDoubleRatchetSession(rootKey, ephemPriv, ephemPub, inboundMsg.EphemeralPub)
	return session, inboundMsg.IdentityPub, nil
}
