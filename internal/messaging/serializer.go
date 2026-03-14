package messaging

import "io"

// Serializer dictates how a Message is encoded onto and decoded from a raw byte stream.
// This abstraction allows us to swap JSON for Protobuf without touching the core logic.
type Serializer interface {
	Encode(w io.Writer, msg Message) error
	Decode(r io.Reader) (Message, error)
}
