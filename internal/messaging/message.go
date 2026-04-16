package messaging

type MessageType uint8

const (
	TypeChat MessageType = iota
	TypeCommand
	TypeTelemetry // For automated device posture and health reports
	TypeDHT       // Defines control-plane routing messages
)

// Message is the core domain entity for data in transit.
type Message struct {
	SenderID    []byte
	Type        MessageType
	DHPublicKey []byte // Ephemeral public key for Post-Compromise Security
	Payload     []byte // This will hold the Double Ratchet encrypted ciphertext later
}
