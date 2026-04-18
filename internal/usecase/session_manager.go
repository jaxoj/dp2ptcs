package usecase

import (
	"context"
	"dp2ptcs/internal/crypto"
	"encoding/hex"
	"errors"
	"time"
)

const (
	// SessionTTL is the maximum time a session can remain in memory without activity.
	SessionTTL = 1 * time.Hour

	// CleanupInterval is how frequently the manager scans for expired sessions.
	CleanupInterval = 15 * time.Minute
)

// sessionMetadata tracks when a session was last accessed for TTL management.
type sessionMetadata struct {
	session   crypto.SecureSession
	lastSeen  time.Time
	createdAt time.Time
}

// sessionOp represents different types of operations the dispatcher can perform.
type sessionOp int

const (
	opUse    sessionOp = iota // fn(session) - execute arbitrary function
	opGet                     // retrieve session
	opSet                     // store session
	opDelete                  // remove session
)

// sessionRequest encapsulates an operation on a session sent to the dispatcher.
type sessionRequest struct {
	op      sessionOp
	peerID  string
	session crypto.SecureSession             // for opSet
	fn      func(crypto.SecureSession) error // for opUse
	result  chan interface{}                 // chan error or chan (crypto.SecureSession, error)
}

// InMemorySessionManager securely holds active Double Ratchet sessions in memory
// with automatic TTL-based eviction. All access is serialized through a dispatcher goroutine.
type InMemorySessionManager struct {
	requests         chan sessionRequest
	dispatcherCtx    context.Context
	dispatcherCancel context.CancelFunc
}

// NewInMemorySessionManager creates and initializes a session manager with a dispatcher goroutine.
func NewInMemorySessionManager() *InMemorySessionManager {
	dispatcherCtx, cancel := context.WithCancel(context.Background())

	m := &InMemorySessionManager{
		requests:         make(chan sessionRequest, 100),
		dispatcherCtx:    dispatcherCtx,
		dispatcherCancel: cancel,
	}

	go m.dispatcher()
	return m
}

// dispatcher runs the session manager's main event loop.
func (m *InMemorySessionManager) dispatcher() {
	sessions := make(map[string]*sessionMetadata)
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.dispatcherCtx.Done():
			return
		case req := <-m.requests:
			m.handleRequest(sessions, req)
		case <-ticker.C:
			now := time.Now()
			for key, meta := range sessions {
				if now.Sub(meta.lastSeen) > SessionTTL {
					delete(sessions, key)
				}
			}
		}
	}
}

// handleRequest processes a session operation.
func (m *InMemorySessionManager) handleRequest(sessions map[string]*sessionMetadata, req sessionRequest) {
	switch req.op {
	case opUse:
		meta := sessions[req.peerID]
		if meta == nil {
			req.result <- errors.New("session not found")
		} else {
			meta.lastSeen = time.Now()
			req.result <- req.fn(meta.session)
		}

	case opGet:
		meta := sessions[req.peerID]
		if meta == nil {
			req.result <- struct {
				session crypto.SecureSession
				err     error
			}{nil, errors.New("session not found")}
		} else {
			meta.lastSeen = time.Now()
			req.result <- struct {
				session crypto.SecureSession
				err     error
			}{meta.session, nil}
		}

	case opSet:
		now := time.Now()
		sessions[req.peerID] = &sessionMetadata{
			session:   req.session,
			lastSeen:  now,
			createdAt: now,
		}
		req.result <- nil

	case opDelete:
		if _, exists := sessions[req.peerID]; !exists {
			req.result <- errors.New("session not found")
		} else {
			delete(sessions, req.peerID)
			req.result <- nil
		}
	}
}

// UseSession executes a function with a session, serialized through the dispatcher.
func (m *InMemorySessionManager) UseSession(peerID []byte, fn func(crypto.SecureSession) error) error {
	key := hex.EncodeToString(peerID)
	result := make(chan interface{}, 1)

	req := sessionRequest{
		op:     opUse,
		peerID: key,
		fn:     fn,
		result: result,
	}

	m.requests <- req
	err := <-result
	if e, ok := err.(error); ok {
		return e
	}
	return nil
}

// GetSession retrieves a session and updates its last-seen timestamp.
func (m *InMemorySessionManager) GetSession(peerID []byte) (crypto.SecureSession, error) {
	key := hex.EncodeToString(peerID)
	result := make(chan interface{}, 1)

	req := sessionRequest{
		op:     opGet,
		peerID: key,
		result: result,
	}

	m.requests <- req
	res := <-result
	if data, ok := res.(struct {
		session crypto.SecureSession
		err     error
	}); ok {
		return data.session, data.err
	}
	return nil, errors.New("unexpected response type")
}

// SetSession stores a session with the current timestamp.
func (m *InMemorySessionManager) SetSession(peerID []byte, session crypto.SecureSession) {
	key := hex.EncodeToString(peerID)
	result := make(chan interface{}, 1)

	req := sessionRequest{
		op:      opSet,
		peerID:  key,
		session: session,
		result:  result,
	}

	m.requests <- req
	<-result
}

// DeleteSession explicitly removes a session from the manager.
func (m *InMemorySessionManager) DeleteSession(peerID []byte) error {
	key := hex.EncodeToString(peerID)
	result := make(chan interface{}, 1)

	req := sessionRequest{
		op:     opDelete,
		peerID: key,
		result: result,
	}

	m.requests <- req
	err := <-result
	if e, ok := err.(error); ok {
		return e
	}
	return nil
}

// Shutdown gracefully stops the dispatcher goroutine.
func (m *InMemorySessionManager) Shutdown() {
	if m.dispatcherCancel != nil {
		m.dispatcherCancel()
	}
}
