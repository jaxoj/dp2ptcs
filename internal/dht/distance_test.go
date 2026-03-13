package dht_test

import (
	"bytes"
	"dp2ptcs/internal/dht"
	"testing"
)

func TestXORDistance_Sucess(t *testing.T) {
	// 0x01 XOR 0x01 = 0x00
	// 0x01 XOR 0x02 = 0x03
	// 0x01 XOR 0x04 = 0x05
	nodeA := []byte{0x01, 0x01, 0x01}
	nodeB := []byte{0x01, 0x02, 0x04}
	expectedDistance := []byte{0x00, 0x03, 0x05}

	distance, err := dht.XORDistance(nodeA, nodeB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(distance, expectedDistance) {
		t.Errorf("expected distance %v, got %v", expectedDistance, distance)
	}
}

func TestXORDistance_LengthMismatch(t *testing.T) {
	nodeA := []byte{0x01, 0x02}
	nodeB := []byte{0x01}

	_, err := dht.XORDistance(nodeA, nodeB)
	if err != dht.ErrLengthMismatch {
		t.Fatalf("expected error %v, got %v", dht.ErrLengthMismatch, err)
	}
}
