package messaging_test

import (
	"bytes"
	"dp2ptcs/internal/messaging"
	"testing"
)

func TestProtobufSerializer_EncodeDecode(t *testing.T) {
	serializer := &messaging.ProtobufSerializer{}

	originalMsg := messaging.Message{
		SenderID:            []byte{0xDE, 0xAD, 0xBE, 0xEF}, // Simulated 32-byte Ed25519 public key
		Type:                messaging.TypeCommand,
		DHPublicKey:         []byte{0x12, 0x34},
		Payload:             []byte("EXECUTE_ROTATION"),
		MessageNumber:       42,
		PreviousChainLength: 0,
	}

	// bytes.Buffer implements both io.Reader and io.Writer, perfectly simulating our Stream
	var streamBuffer bytes.Buffer

	// Encode the message
	if err := serializer.Encode(&streamBuffer, originalMsg); err != nil {
		t.Fatalf("failed to encode message: %v", err)
	}

	// Ensure the buffer actually contains framed data
	if streamBuffer.Len() == 0 {
		t.Fatal("expected buffer to contain data after encoding, but it is empty")
	}

	// Decode the message off the stream
	decodedMsg, err := serializer.Decode(&streamBuffer)
	if err != nil {
		t.Fatalf("failed to decode message: %v", err)
	}

	// The decoded domain entity must perfectly match the original
	if !bytes.Equal(decodedMsg.SenderID, originalMsg.SenderID) {
		t.Errorf("expected SenderID %x, got %x", originalMsg.SenderID, decodedMsg.SenderID)
	}
	if decodedMsg.Type != originalMsg.Type {
		t.Errorf("expected Type %v, got %v", originalMsg.Type, decodedMsg.Type)
	}
	if !bytes.Equal(decodedMsg.DHPublicKey, originalMsg.DHPublicKey) {
		t.Errorf("expected DHPublicKey %x, got %x", originalMsg.DHPublicKey, decodedMsg.DHPublicKey)
	}
	if !bytes.Equal(decodedMsg.Payload, originalMsg.Payload) {
		t.Errorf("expected Payload %s, got %s", originalMsg.Payload, decodedMsg.Payload)
	}
	if decodedMsg.MessageNumber != originalMsg.MessageNumber {
		t.Errorf("expected MessageNumber %d, got %d", originalMsg.MessageNumber, decodedMsg.MessageNumber)
	}
	if decodedMsg.PreviousChainLength != originalMsg.PreviousChainLength {
		t.Errorf("expected PreviousChainLength %d, got %d", originalMsg.PreviousChainLength, decodedMsg.PreviousChainLength)
	}
}
