package transport

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/quic-go/quic-go"
)

// quicConnection wraps a quic.Connection to implement our domain Connection interface.
type quicConnection struct {
	conn *quic.Conn
}

func (q *quicConnection) Close() error {
	// 0x00 is the application error code for a normal closure
	return q.conn.CloseWithError(0x00, "connection closed by tactical node")
}

type quicListener struct {
	listener *quic.Listener
}

func (q *quicListener) Accept() (Connection, error) {
	conn, err := q.listener.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	return &quicConnection{conn: conn}, nil
}

func (q *quicListener) Close() error {
	return q.listener.Close()
}

// Addr allows us to retrieve the actual bound address (useful for port 0 testing).
func (q *quicListener) Addr() net.Addr {
	return q.listener.Addr()
}

// QUICTransport implements the Transport interface using quic-go.
type QUICTransport struct {
	tlsConf *tls.Config
}

// NewQUICTransport initializes a new QUIC adapter with the mandatory mTLS configuration.
func NewQUICTransport(tlsConf *tls.Config) *QUICTransport {
	return &QUICTransport{
		tlsConf: tlsConf,
	}
}

// Dial establishes a secure QUIC connection to the target address.
func (qt *QUICTransport) Dial(address string) (Connection, error) {
	conn, err := quic.DialAddr(context.Background(), address, qt.tlsConf, nil)
	if err != nil {
		return nil, err
	}
	return &quicConnection{conn: conn}, nil
}

func (qt *QUICTransport) Listen(address string) (*quicListener, error) {
	listener, err := quic.ListenAddr(address, qt.tlsConf, nil)
	if err != nil {
		return nil, err
	}
	return &quicListener{listener: listener}, nil
}
