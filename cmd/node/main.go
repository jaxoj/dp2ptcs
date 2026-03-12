package main

import (
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"dp2ptcs/internal/usecase"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	// define the default path for the identity key
	keyPath := "node.key"

	// Execute the application injecting standard output for log
	if err := run(os.Stdout, keyPath); err != nil {
		log.Fatalf("[Fetal]: %v", err)
	}
}

// run separates dependency injection and execution from the main() scope,
// allowing us to test the application wiring cleanly.
func run(out io.Writer, keyPath string) error {
	// Frameworks & Drivers: Instantiate concrete dependencies
	entropy := rand.Reader
	store := crypto.NewFileIdentityStore(keyPath)

	// Interface Adapters ->  Wire the manager
	manager := usecase.NewIdentityManager(store, entropy)

	// Execute Core Logic
	identity, err := manager.LoadOrCreate()
	if err != nil {
		return fmt.Errorf("failed to load or create identity: %w", err)
	}

	// Output the result to the injected writer
	fmt.Fprintln(out, "Tactical Node Initialized.")
	// The Node ID is binary, so we encode it to a readable hex string
	fmt.Fprintf(out, "Node ID: %s\n", hex.EncodeToString(identity.NodeID))

	return nil
}
