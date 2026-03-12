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

	err := run(&out, keyPath)
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
