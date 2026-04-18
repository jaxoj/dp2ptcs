package handshake

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"dp2ptcs/internal/messaging"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
)

// HandshakeProtocol manages the transition of a raw stream into an End-to-End Encrypted stream.
type HandshakeProtocol struct {
	localIdentPriv  ed25519.PrivateKey // ed25519 for identity verification
	localIdentPub   ed25519.PublicKey  // ed25519 for identity verification
	localPrekeyPriv []byte             // X25519 prekey for X3DH
	localPrekeyPub  []byte             // X25519 prekey for X3DH
}

func NewHandshakeProtocol(identPriv ed25519.PrivateKey, identPub ed25519.PublicKey) *HandshakeProtocol {
	// Derive X25519 key from ed25519 seed (first 32 bytes of private key)
	x25519Priv := identPriv.Seed()
	x25519Pub, _ := curve25519.X25519(x25519Priv, curve25519.Basepoint)

	return &HandshakeProtocol{
		localIdentPriv:  identPriv,
		localIdentPub:   identPub,
		localPrekeyPriv: x25519Priv,
		localPrekeyPub:  x25519Pub,
	}
}

// Initiate is called by the node dialing outbound to a peer.
func (h *HandshakeProtocol) Initiate(ctx context.Context, stream io.ReadWriter) (crypto.SecureSession, error) {
	// Generate local Ephemeral key pair for this specific connection
	ephemPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ephemPriv); err != nil {
		return nil, err
	}
	ephemPub, _ := curve25519.X25519(ephemPriv, curve25519.Basepoint)

	// Create message to sign: IdentityPub + PrekeyPub + EphemeralPub
	message := make([]byte, 0, 96)
	message = append(message, h.localIdentPub...)
	message = append(message, h.localPrekeyPub...)
	message = append(message, ephemPub...)

	// Sign the combined public keys
	signature := ed25519.Sign(h.localIdentPriv, message)

	// Send our signed public keys to the responder
	outboundMsg := messaging.HandshakeExchange{
		IdentityPub:  h.localIdentPub,
		PrekeyPub:    h.localPrekeyPub,
		EphemeralPub: ephemPub,
		Signature:    signature,
		Expiry:       time.Now().Add(5 * time.Minute), // 5 minute handshake timeout
	}
	if err := outboundMsg.WriteTo(stream); err != nil {
		return nil, err
	}

	// Read the responder's signed public keys
	var inboundMsg messaging.HandshakeExchange
	if err := inboundMsg.ReadFrom(stream); err != nil {
		return nil, errors.New("failed to read responder handshake")
	}

	// Verify responder's signature and expiry
	if err := h.verifyHandshakeExchange(&inboundMsg); err != nil {
		return nil, err
	}

	// Compute the X3DH Root Key
	rootKey, err := crypto.InitiateX3DH(
		h.localPrekeyPriv, ephemPriv,
		inboundMsg.PrekeyPub, inboundMsg.EphemeralPub,
	)
	if err != nil {
		return nil, err
	}

	// Initialize and return the state machine
	session := crypto.NewDoubleRatchetSession(rootKey, ephemPriv, ephemPub, inboundMsg.EphemeralPub)
	return session, nil
}

// verifyHandshakeExchange verifies the signature and expiry of a handshake exchange.
func (h *HandshakeProtocol) verifyHandshakeExchange(exchange *messaging.HandshakeExchange) error {
	// Check expiry
	if time.Now().After(exchange.Expiry) {
		return errors.New("handshake exchange has expired")
	}

	// Recreate the signed message
	message := make([]byte, 0, 96)
	message = append(message, exchange.IdentityPub...)
	message = append(message, exchange.PrekeyPub...)
	message = append(message, exchange.EphemeralPub...)

	// Verify signature
	if !ed25519.Verify(exchange.IdentityPub, message, exchange.Signature) {
		return errors.New("handshake exchange signature verification failed")
	}

	return nil
}

// Respond is called by the NodeServer when a new inbound connection is accepted.
func (h *HandshakeProtocol) Respond(ctx context.Context, stream io.ReadWriter) (crypto.SecureSession, []byte, error) {
	// Read the initiator's signed public keys FIRST
	var inboundMsg messaging.HandshakeExchange
	if err := inboundMsg.ReadFrom(stream); err != nil {
		return nil, nil, errors.New("failed to read initiator handshake")
	}

	// Verify initiator's signature and expiry
	if err := h.verifyHandshakeExchange(&inboundMsg); err != nil {
		return nil, nil, err
	}

	// Generate local Ephemeral key pair for this specific connection
	ephemPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ephemPriv); err != nil {
		return nil, nil, err
	}
	ephemPub, _ := curve25519.X25519(ephemPriv, curve25519.Basepoint)

	// Create message to sign: IdentityPub + PrekeyPub + EphemeralPub
	message := make([]byte, 0, 96)
	message = append(message, h.localIdentPub...)
	message = append(message, h.localPrekeyPub...)
	message = append(message, ephemPub...)

	// Sign the combined public keys
	signature := ed25519.Sign(h.localIdentPriv, message)

	// Send our signed public keys back to the initiator
	outboundMsg := messaging.HandshakeExchange{
		IdentityPub:  h.localIdentPub,
		PrekeyPub:    h.localPrekeyPub,
		EphemeralPub: ephemPub,
		Signature:    signature,
		Expiry:       time.Now().Add(5 * time.Minute), // 5 minute handshake timeout
	}
	if err := outboundMsg.WriteTo(stream); err != nil {
		return nil, nil, errors.New("failed to write responder handshake")
	}

	// Compute the X3DH Root key (Using Respond Math)
	rootKey, err := crypto.RespondX3DH(h.localPrekeyPriv, ephemPriv, inboundMsg.PrekeyPub, inboundMsg.EphemeralPub)
	if err != nil {
		return nil, nil, err
	}

	// Initialize and return the state machine
	session := crypto.NewDoubleRatchetSession(rootKey, ephemPriv, ephemPub, inboundMsg.EphemeralPub)
	return session, inboundMsg.IdentityPub, nil
}
