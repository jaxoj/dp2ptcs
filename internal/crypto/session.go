package crypto

// SecureSession represents the stateful End-to-End Encryption context between two peers.
// In a Double Ratchet implementation, the keys rotate forward with every Encrypt/Decrypt call.
type SecureSession interface {
	// Encrypt locks the plaintext and returns the ciphertext along with the
	// current ephemeral DH public key that must be attached to the message header.
	Encrypt(plainText []byte) (cipherText, dhPulicKey []byte, err error)

	// Decrypt takes the ciphertext and the remote peer's ephemeral DH public key.
	// If the remote key has changed, the session will automatically step the Root Chain.
	Decrypt(cipherText, remoteDHPubKey []byte) (plainText []byte, err error)
}

// SessionManager retrieves the correct cryptographic state for a specific remote peer.
type SessionManager interface {
	GetSession(remoteNodeID []byte) (SecureSession, error)
}
