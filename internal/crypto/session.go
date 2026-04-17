package crypto

// SecureSession represents the stateful End-to-End Encryption context between two peers.
// In a Double Ratchet implementation, the keys rotate forward with every Encrypt/Decrypt call.
type SecureSession interface {
	// Encrypt locks the plaintext and returns the ciphertext along with the
	// current ephemeral DH public key, message number (uint64 for large address space), and previous chain length that must be attached to the message header.
	Encrypt(plainText []byte) (cipherText, dhPublicKey []byte, messageNumber uint64, previousChainLength uint32, err error)

	// Decrypt takes the ciphertext, remote DH public key, message number (uint64 for replay detection), and previous chain length.
	// If the remote key has changed, the session will automatically step the Root Chain.
	// Returns error if message is replayed, authentication fails, or gap is suspiciously large.
	Decrypt(cipherText, remoteDHPubKey []byte, messageNumber uint64, previousChainLength uint32) (plainText []byte, err error)
}

// SessionManager stores and retrieves the correct cryptographic state for a specific remote peer.
type SessionManager interface {
	GetSession(remoteNodeID []byte) (SecureSession, error)
	SetSession(remoteNodeID []byte, session SecureSession)
	DeleteSession(remoteNodeID []byte) error
}
