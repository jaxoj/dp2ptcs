package transport

import (
	"context"
	"io"
)

// Stream represents a single, independent byte channel within a multiplexed Connection.
// It inherently fulfills the standard io.Reader, io.Writer, and io.Closer interfaces.
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
}

// Connection represents a secure multiplexire between two links
type Connection interface {
	// OpenStream initiates a new bidirectional stream to the remote peer.
	OpenStream(ctx context.Context) (Stream, error)
	// AcceptStream waits for and accepts an incoming stream from the remote peer.
	AcceptStream(ctx context.Context) (Stream, error)

	Close() error
}

// Listener represents a socket listening for incoming tactical connections.
type Listener interface {
	Accept() (Connection, error)
	Close() error
}

// Transport abstracts the underlying network dialing and listening mechanics.
type Transport interface {
	Dial(address string) (Connection, error)
	Listen(address string) (Listener, error)
}
