package messaging

import (
	"io"
	"time"
)

// In highly-security environments, X25519 public keys are always exactly 32-bytes.
const KeySize = 32
const SignatureSize = 64                           // ed25519 signature size
const HandshakePayloadSize = 32 + 32 + 32 + 64 + 8 // IdentityPub (32) + PrekeyPub (32) + EphemeralPub (32) + Signature (64) + Expiry (8)

// HandshakeExchange represents the signed public keys sent during connection setup.
type HandshakeExchange struct {
	IdentityPub  []byte    // ed25519 public key for identity verification
	PrekeyPub    []byte    // X25519 prekey for X3DH
	EphemeralPub []byte    // X25519 ephemeral key for X3DH
	Signature    []byte    // ed25519 signature of IdentityPub + PrekeyPub + EphemeralPub
	Expiry       time.Time // When this handshake expires
}

func (h *HandshakeExchange) WriteTo(w io.Writer) error {
	if _, err := w.Write(h.IdentityPub); err != nil {
		return err
	}
	if _, err := w.Write(h.PrekeyPub); err != nil {
		return err
	}
	if _, err := w.Write(h.EphemeralPub); err != nil {
		return err
	}
	if _, err := w.Write(h.Signature); err != nil {
		return err
	}

	// Write expiry as Unix timestamp (int64, 8 bytes)
	expiryBytes := make([]byte, 8)
	expiryUnix := h.Expiry.Unix()
	for i := 0; i < 8; i++ {
		expiryBytes[i] = byte(expiryUnix >> (i * 8))
	}
	_, err := w.Write(expiryBytes)
	return err
}

// ReadFrom reads exactly 168-bytes from the stream to construct the keys and signature
func (h *HandshakeExchange) ReadFrom(r io.Reader) error {
	h.IdentityPub = make([]byte, KeySize)
	h.PrekeyPub = make([]byte, KeySize)
	h.EphemeralPub = make([]byte, KeySize)
	h.Signature = make([]byte, SignatureSize)

	if _, err := io.ReadFull(r, h.IdentityPub); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, h.PrekeyPub); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, h.EphemeralPub); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, h.Signature); err != nil {
		return err
	}

	// Read expiry timestamp (8 bytes)
	expiryBytes := make([]byte, 8)
	if _, err := io.ReadFull(r, expiryBytes); err != nil {
		return err
	}

	var expiryUnix int64
	for i := 0; i < 8; i++ {
		expiryUnix |= int64(expiryBytes[i]) << (i * 8)
	}
	h.Expiry = time.Unix(expiryUnix, 0)

	return nil
}
