package usecase

import (
	"context"
	"dp2ptcs/internal/domain"
	"dp2ptcs/internal/transport"
	"errors"
	"fmt"
)

// ErrConnectionFailed is returned when a peer is resolved, but none of its physical addresses are reachable.
var ErrConnectionFailed = errors.New("failed to connect to any known addresses for peer")

// ConnectionManager orchestrates the resolution and connection to remote peers.
type ConnectionManager struct {
	discoverer domain.Discoverer
	transport  transport.Transport
}

func NewConnectionManager(discoverer domain.Discoverer, tr transport.Transport) *ConnectionManager {
	return &ConnectionManager{discoverer: discoverer, transport: tr}
}

// ResolvePeer queries the discovery mechanism to find the physical network addresses.
func (cm *ConnectionManager) ResolvePeer(targetID []byte) (*domain.Peer, error) {
	if len(targetID) != 32 {
		return nil, domain.ErrInvalidNodeID
	}

	peer, err := cm.discoverer.FindPeer(targetID)
	if err != nil {
		return nil, err
	}

	return peer, nil
}

// ConnectToPeer resolves the peer's logical ID to physical addresses,
// then attempts to establish a secure transport connection.
func (cm *ConnectionManager) ConnectToPeer(ctx context.Context, peer domain.Peer) (transport.Connection, error) {
	if len(peer.Addresses) == 0 {
		return nil, fmt.Errorf("no routable addresses for peer '%x'", peer.ID)
	}
	return cm.DialAddresses(ctx, peer.Addresses)
}

// DialAddresses attempts concurrent dialing to all provided addresses and returns the first successful connection.
func (cm *ConnectionManager) DialAddresses(ctx context.Context, addresses []string) (transport.Connection, error) {
	if len(addresses) == 0 {
		return nil, errors.New("no addresses provided for dialing")
	}

	// Create a derived context to cancel pending dials once we have a winner.
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resCh := make(chan transport.Connection)
	errCh := make(chan error, len(addresses))

	for _, add := range addresses {
		go func(targetAddr string) {
			conn, err := cm.transport.Dial(targetAddr)
			if err != nil {
				errCh <- err
				return
			}

			select {
			case resCh <- conn:
			case <-dialCtx.Done():
				conn.Close()
			}
		}(add)
	}

	var lastErr error
	for i := 0; i < len(addresses); i++ {
		select {
		case conn := <-resCh:
			cancel()
			return conn, nil
		case err := <-errCh:
			lastErr = err
		case <-dialCtx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("all %d concurrent connection attempts failed, last error: %w", len(addresses), lastErr)
}
