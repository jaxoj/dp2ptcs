package crypto

// SecureSession represents the stateful End-to-End Encryption context between two peers.
// In a Double Ratchet implementation, the keys rotate forward with every Encrypt/Decrypt call.
type SecureSession interface {
	Encrypt(plainText []byte) (cipherText []byte, err error)
	Decrypt(cipherText []byte) (plainText []byte, err error)
}

// SessionManager retrieves the correct cryptographic state for a specific remote peer.
type SessionManager interface {
	GetSession(remoteNodeID []byte) (SecureSession, error)
}
