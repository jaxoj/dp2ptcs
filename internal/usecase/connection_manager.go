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

	// Create a derived context to cancel pending dials once we have a winner
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Unbuffered channel for the winning connection
	resCh := make(chan transport.Connection)

	// Buffered error channel to prevent failing goroutines from blocking
	errCh := make(chan error, len(peer.Addresses))

	// Launch a concurrent dial for every known connection
	for _, add := range peer.Addresses {
		go func(targetAddr string) {
			conn, err := cm.transport.Dial(targetAddr)
			if err != nil {
				errCh <- err
				return
			}

			// If dial succeeds, try to pass it to the result channel
			select {
			case resCh <- conn:
				// We are the first to succeed! The main loop will catch this.
			case <-dialCtx.Done():
				// We succeeded, but another goroutine beat us to it and cancelled the context.
				// We MUST close this redundant connection to prevent resource leaks (zombie connections).
				conn.Close()

			}
		}(add)
	}

	var lastErr error

	// Wait for exactly len(p.Addresses) events (either a success or an error)
	for i := 0; i < len(peer.Addresses); i++ {
		select {
		case conn := <-resCh:
			// The first successful connection arrived.
			// Calling cancel() instantly aborts the other in-flight transport.Dial() calls.
			cancel()
			return conn, nil
		case err := <-errCh:
			// Capture the error but keep waiting for other goroutines to finish
			lastErr = err
		case <-dialCtx.Done():
			// The parent context (e.g., a global 5-second timeout) expired before any dial succeeded
			return nil, ctx.Err()
		}
	}

	// If the loop finishes, it means we received len(p.Addresses) errors and 0 successes.
	return nil, fmt.Errorf("all %d concurrent connection attempts failed, last error: %w", len(peer.Addresses), lastErr)
}
