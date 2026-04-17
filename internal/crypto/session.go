package crypto

// SecureSession represents the stateful End-to-End Encryption context between two peers.
// In a Double Ratchet implementation, the keys rotate forward with every Encrypt/Decrypt call.
type SecureSession interface {
	// Encrypt locks the plaintext and returns the ciphertext along with the
	// current ephemeral DH public key, message number, and previous chain length that must be attached to the message header.
	Encrypt(plainText []byte) (cipherText, dhPublicKey []byte, messageNumber uint32, previousChainLength uint32, err error)

	// Decrypt takes the ciphertext, remote DH public key, message number, and previous chain length.
	// If the remote key has changed, the session will automatically step the Root Chain.
	Decrypt(cipherText, remoteDHPubKey []byte, messageNumber uint32, previousChainLength uint32) (plainText []byte, err error)
}

// SessionManager stores and retrieves the correct cryptographic state for a specific remote peer.
type SessionManager interface {
	GetSession(remoteNodeID []byte) (SecureSession, error)
	SetSession(remoteNodeID []byte, session SecureSession)
}
