package main

import (
	"bytes"
	"crypto/rand"
	"dp2ptcs/internal/crypto"
	"dp2ptcs/internal/dht"
	"dp2ptcs/internal/network"
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
	if err := run(os.Stdout, keyPath, os.Args[1:]); err != nil {
		log.Fatalf("[Fetal]: %v", err)
	}
}

// run separates dependency injection and execution from the main() scope,
// allowing us to test the application wiring cleanly.
func run(out io.Writer, keyPath string, args []string) error {
	// Frameworks & Drivers: Instantiate concrete dependencies
	entropy := rand.Reader
	store := crypto.NewFileIdentityStore(keyPath)

	// Define our bootstrap node (Command Post)
	cpID := bytes.Repeat([]byte{0xAA}, 32)
	cpPeer, _ := dht.NewPeer(cpID, []string{"10.55.0.1:9000"})

	// Instantiate the interface adapter for discovery
	discoverer := network.NewStaticDiscoverer([]*dht.Peer{cpPeer})

	// Interface Adapters ->  Wire the manager
	manager := usecase.NewIdentityManager(store, entropy)
	connectionManager := usecase.NewConnectionManager(discoverer, nil)

	// Execute Core Logic
	identity, err := manager.LoadOrCreate()
	if err != nil {
		return fmt.Errorf("failed to load or create identity: %w", err)
	}

	// Output the result to the injected writer
	fmt.Fprintln(out, "Tactical Node Initialized.")
	// The Node ID is binary, so we encode it to a readable hex string
	fmt.Fprintf(out, "Node ID: %s\n", hex.EncodeToString(identity.NodeID))

	// If target ID was provided via CLI, attempt discovery
	if len(args) > 0 {
		targetHex := args[0]
		targetID, err := hex.DecodeString(targetHex)
		if err != nil {
			return fmt.Errorf("invalid hex encoding for target ID: %w", err)
		}

		fmt.Fprintf(out, "Attempting to resolve peer: %s...\n", targetHex)

		peer, err := connectionManager.ResolvePeer(targetID)
		if err != nil {
			return fmt.Errorf("Peer discovery failed: %w", err)
		}
		fmt.Fprintf(out, "Successfully resolved peer! Available at addresses: %v\n", peer.Addresses)
	}

	return nil
}
