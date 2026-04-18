package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// PrekeyBundle contains the signed prekey material for X3DH handshake.
// This prevents MITM attacks by allowing identity verification.
type PrekeyBundle struct {
	IdentityPub []byte    // ed25519 public key for identity verification
	PrekeyPub   []byte    // X25519 prekey for X3DH
	Signature   []byte    // ed25519 signature of IdentityPub + PrekeyPub
	Expiry      time.Time // When this prekey expires
}

// GeneratePrekeyBundle creates a new signed prekey bundle.
func GeneratePrekeyBundle(identityPriv ed25519.PrivateKey, identityPub ed25519.PublicKey) (*PrekeyBundle, error) {
	// Generate X25519 prekey pair
	prekeyPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, prekeyPriv); err != nil {
		return nil, err
	}
	prekeyPub, err := curve25519.X25519(prekeyPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	// Create message to sign: IdentityPub + PrekeyPub
	message := make([]byte, 0, 64)
	message = append(message, identityPub...)
	message = append(message, prekeyPub...)

	// Sign the combined public keys
	signature := ed25519.Sign(identityPriv, message)

	return &PrekeyBundle{
		IdentityPub: identityPub,
		PrekeyPub:   prekeyPub,
		Signature:   signature,
		Expiry:      time.Now().Add(24 * time.Hour), // 24 hour TTL
	}, nil
}

// VerifyPrekeyBundle verifies the signature and expiry of a prekey bundle.
func VerifyPrekeyBundle(bundle *PrekeyBundle) error {
	// Check expiry
	if time.Now().After(bundle.Expiry) {
		return errors.New("prekey bundle has expired")
	}

	// Recreate the signed message
	message := make([]byte, 0, 64)
	message = append(message, bundle.IdentityPub...)
	message = append(message, bundle.PrekeyPub...)

	// Verify signature
	if !ed25519.Verify(bundle.IdentityPub, message, bundle.Signature) {
		return errors.New("prekey bundle signature verification failed")
	}

	return nil
}

// InitiateX3DH performs the Triple Diffie-Hellman calculation from the perspective
// of the node initiating the connection.
func InitiateX3DH(localIdentPriv, localEphemPriv, remoteIdentPub, remoteEphemPub []byte) ([]byte, error) {
	// DH1: Local Identity + Remote Ephemeral
	dh1, err := curve25519.X25519(localIdentPriv, remoteEphemPub)
	if err != nil {
		return nil, errors.New("failed to compute DH1")
	}

	// DH2: Local Ephemeral + Remote Identity
	dh2, err := curve25519.X25519(localEphemPriv, remoteIdentPub)
	if err != nil {
		return nil, errors.New("failed to compute DH2")
	}

	// DH3: Local Ephemeral + Remote Ephemeral
	dh3, err := curve25519.X25519(localEphemPriv, remoteEphemPub)
	if err != nil {
		return nil, errors.New("failed to compute DH3")
	}

	return mixDHSecrets(dh1, dh2, dh3)
}

// RespondX3DH performs the calculation from the perspective of the receiving node.
// Notice that the inputs to DH1 and DH2 are physically swapped compared to the initiator,
// guaranteeing that the mathematical result is identical on both sides.
func RespondX3DH(localIdentPriv, localEphemPriv, remoteIdentPub, remoteEphemPub []byte) ([]byte, error) {
	// DH1: Local Ephemeral + Remote Identity (mirrors Initiator's DH1)
	dh1, err := curve25519.X25519(localEphemPriv, remoteIdentPub)
	if err != nil {
		return nil, errors.New("failed to compute DH1")
	}

	// DH2: Local Identity + Remote Ephemeral (mirrors Initiator's DH2)
	dh2, err := curve25519.X25519(localIdentPriv, remoteEphemPub)
	if err != nil {
		return nil, errors.New("failed to compute DH2")
	}

	// DH3: Local Ephemeral + Remote Ephemeral
	dh3, err := curve25519.X25519(localEphemPriv, remoteEphemPub)
	if err != nil {
		return nil, errors.New("failed to compute DH3")
	}

	return mixDHSecrets(dh1, dh2, dh3)
}

// mixDHSecrets concatenates the Diffie-Hellman outputs and passes them through an HKDF
// to produce a cryptographically strong, uniform 32-byte initial Root Key.
func mixDHSecrets(dh1, dh2, dh3 []byte) ([]byte, error) {
	var combinedMaterial []byte

	// The X3DH specification strictly dictates concatenating DH1 || DH2 || DH3
	// We prefix it with an all-xFF byte sequence as a standard KDF initialization padding.
	combinedMaterial = append(combinedMaterial, bytes.Repeat([]byte{0xFF}, 32)...)
	combinedMaterial = append(combinedMaterial, dh1...)
	combinedMaterial = append(combinedMaterial, dh2...)
	combinedMaterial = append(combinedMaterial, dh3...)

	// Pass through HKDF with SHA-256
	hash := sha256.New
	kdf := hkdf.New(hash, combinedMaterial, nil, []byte("Tactical-X3DH-Root-v1"))

	rootKey := make([]byte, KeyLength)
	if _, err := io.ReadFull(kdf, rootKey); err != nil {
		return nil, err
	}

	return rootKey, nil
}
