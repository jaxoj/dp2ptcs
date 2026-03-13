package transport

// Connection represents a secure multiplexire between two links
type Connection interface {
	Close() error
	// TODO: In the future we will add OpenStream() and AcceptStream()
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
