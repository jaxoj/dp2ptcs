package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_InitializesTacticalNodeAndOutputsID(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "test_node.key")
	var out bytes.Buffer // Captures standard output for verification

	err := run(&out, keyPath, "127.0.0.1:0", []string{})
	if err != nil {
		t.Fatalf("Expected app to run with no error, got %v", err)
	}

	output := out.String()

	if !strings.Contains(output, "Tactical Node Initialized") {
		t.Errorf("Expected output to contain 'Tactical Node Initialized', got %s", output)
	}

	if !strings.Contains(output, "Node ID:") {
		t.Error("Expected Node ID to be printed to output")
	}
}

func TestRun_ResolvesKnownPeer(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "test_node.key")
	var out bytes.Buffer // Captures standard output for verification

	targetHex := strings.Repeat("aa", 32)

	err := run(&out, keyPath, "127.0.0.1:0", []string{string(targetHex)})

	if err != nil {
		t.Fatalf("Expected app to run with no error, got %v", err)
	}

	output := out.String()

	if !strings.Contains(output, "resolved peer") {
		t.Error("Expected output to contain 'resolved peer', got " + output)
	}
	if !strings.Contains(output, "10.55.0.1:9000") {
		t.Error("Expected output to contain '10.55.0.1:9000', got " + output)
	}
}

func TestRun_FailsToResolveKnownPeer(t *testing.T) {
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "test_node.key")
	var out bytes.Buffer

	targetHex := strings.Repeat("bb", 32)

	err := run(&out, keyPath, "127.0.0.1:0", []string{targetHex})

	if err == nil {
		t.Fatal("expected error when resolving unknown peer, got nil")
	}
	if !strings.Contains(err.Error(), "Peer not found") {
		t.Errorf("expected peer not found error, got %v", err)
	}
}
