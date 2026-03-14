package messaging

type MessageType uint8

const (
	TypeChat MessageType = iota
	TypeCommand
	TypeTelementary // For automated device posture and health reports
)

// Message is the core domain entity for data in transit.
type Message struct {
	SenderID []byte
	Type     MessageType
	Payload  []byte // This will hold the Double Ratchet encrypted ciphertext later
}
