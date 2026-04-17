package usecase_test

import (
	"bytes"
	"context"
	"dp2ptcs/internal/crypto"
	"dp2ptcs/internal/messaging"
	"dp2ptcs/internal/transport"
	"dp2ptcs/internal/usecase"
	"io"
	"net"
	"testing"
	"time"
)

// MockSerializer implements messaging.Serializer
type MockSerializer struct {
	MsgToReturn messaging.Message
}

func (m *MockSerializer) Encode(w io.Writer, msg messaging.Message) error { return nil }
func (m *MockSerializer) Decode(r io.Reader) (messaging.Message, error) {
	// Simulate reading from the stream
	b := make([]byte, 1)
	_, err := r.Read(b)
	if err == io.EOF {
		return messaging.Message{}, err
	}
	return m.MsgToReturn, nil
}

// MockSecureSession and MockSessionManager implement our crypto interfaces
type MockSecureSession struct{}

func (m *MockSecureSession) Encrypt(plaintext []byte) ([]byte, []byte, uint32, uint32, error) {
	return plaintext, nil, 1, 0, nil
}
func (m *MockSecureSession) Decrypt(ciphertext, remoteDHPubKey []byte, messageNumber uint32, previousChainLength uint32) ([]byte, error) {
	// Simulate decrypting the payload by appending a suffix
	return append(ciphertext, []byte("-DECRYPTED")...), nil
}

type MockSessionManager struct {
	// store sessions resulting from a successful handshake
	sessions map[string]crypto.SecureSession
}

func (m *MockSessionManager) GetSession(remoteNodeID []byte) (crypto.SecureSession, error) {
	return &MockSecureSession{}, nil
}

func (m *MockSessionManager) SetSession(remoteNodeID []byte, session crypto.SecureSession) {}

func (m *MockSessionManager) DeleteSession(remoteNodeID []byte) error {
	// Mock implementation - just succeed
	return nil
}

// MockServerStream simulates an incoming QUIC stream containing a serialized JSON message.
type MockServerStream struct {
	data *bytes.Buffer
}

func (m *MockServerStream) Read(p []byte) (n int, err error)  { return m.data.Read(p) }
func (m *MockServerStream) Write(p []byte) (n int, err error) { return 0, nil }
func (m *MockServerStream) Close() error                      { return nil }

// MockServerConnection simulates a QUIC connection that yields one stream then blocks.
type MockServerConnection struct {
	streamDelivered bool
	streamData      []byte
}

func (m *MockServerConnection) AcceptStream(ctx context.Context) (transport.Stream, error) {
	if !m.streamDelivered {
		m.streamDelivered = true
		return &MockServerStream{data: bytes.NewBuffer(m.streamData)}, nil
	}
	// Block forever after delivering the first stream to simulate a long-lived connection
	<-ctx.Done()
	return nil, ctx.Err()
}
func (m *MockServerConnection) OpenStream(ctx context.Context) (transport.Stream, error) {
	return nil, nil
}
func (m *MockServerConnection) Close() error { return nil }

// MockListener yields our mock connection.
type MockListener struct {
	connData []byte
}

func (m *MockListener) Accept() (transport.Connection, error) {
	return &MockServerConnection{streamData: m.connData}, nil
}
func (m *MockListener) Close() error   { return nil }
func (m *MockListener) Addr() net.Addr { return nil }

// MockServerTransport returns our MockListener
type MockServerTransport struct {
	connData []byte
}

func (m *MockServerTransport) Listen(address string) (transport.Listener, error) {
	return &MockListener{connData: m.connData}, nil
}
func (m *MockServerTransport) Dial(address string) (transport.Connection, error) { return nil, nil }

// MockHandshake bypasses cryptographic math and stream reading for testing NodeServer routing.
type MockHandshake struct{}

func (m *MockHandshake) Respond(ctx context.Context, stream io.ReadWriter) (crypto.SecureSession, []byte, error) {
	// Immediately return our MockSecureSession and a dummy 32-byte identity key
	return &MockSecureSession{}, bytes.Repeat([]byte{0xFF}, 32), nil
}

func TestNodeServer_AcceptsAndDecodesMessages(t *testing.T) {
	mockTransport := &MockServerTransport{connData: []byte{0x01}} // Dymmy byte to trigger read

	expectedMsg := messaging.Message{
		SenderID: []byte{0x01, 0x02, 0x03},
		Type:     messaging.TypeTelemetry,
		Payload:  []byte("cpu_temp:45C"),
	}
	mockSerializer := &MockSerializer{MsgToReturn: expectedMsg}
	mockSessionMgr := &MockSessionManager{}
	mockHandshake := &MockHandshake{}

	server := usecase.NewNodeServer(mockTransport, mockSerializer, mockSessionMgr, mockHandshake)

	// We use a channel to capture the message received by the handler callback
	receivedChan := make(chan messaging.Message, 1)
	handler := func(msg messaging.Message) *messaging.Message {
		receivedChan <- msg
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Start(ctx, "0.0.0.0:9000", handler)

	select {
	case msg := <-receivedChan:
		if !bytes.Equal(msg.SenderID, expectedMsg.SenderID) {
			t.Errorf("expected SenderID %v, got %v", expectedMsg.SenderID, msg.SenderID)
		}
		if msg.Type != expectedMsg.Type {
			t.Errorf("expected Type %v, got %v", expectedMsg.Type, msg.Type)
		}
		expectedPayload := "cpu_temp:45C-DECRYPTED"
		if string(msg.Payload) != expectedPayload {
			t.Errorf("expected Payload %s, got %s", expectedMsg.Payload, msg.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the server to process the message")
	}
}

func TestNodeServer_DecodesAndDecryptMessage(t *testing.T) {
	mockTransport := &MockServerTransport{connData: []byte{0x01}} // Dymmy byte to trigger read

	encryptMsg := messaging.Message{
		SenderID: []byte{0xAA, 0xBB},
		Type:     messaging.TypeCommand,
		Payload:  []byte("TACTICAL-ORDERS"), // Pretend this is ciphertext
	}

	mockSerializer := &MockSerializer{MsgToReturn: encryptMsg}
	mockSessionMgr := &MockSessionManager{}
	mockHandshake := &MockHandshake{}

	// Inject all three dependencies
	server := usecase.NewNodeServer(mockTransport, mockSerializer, mockSessionMgr, mockHandshake)

	receivedChan := make(chan messaging.Message, 1)
	handler := func(msg messaging.Message) *messaging.Message {
		receivedChan <- msg
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Start(ctx, "0.0.0.0:9000", handler)

	select {
	case msg := <-receivedChan:
		expectedPayload := "TACTICAL-ORDERS-DECRYPTED"
		if string(msg.Payload) != expectedPayload {
			t.Errorf("expected decrypted payload %s, got %s", expectedPayload, string(msg.Payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the server to process the message")
	}

}
