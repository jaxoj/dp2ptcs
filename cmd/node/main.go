package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dp2ptcs/internal/crypto"
	"dp2ptcs/internal/dht"
	"dp2ptcs/internal/domain"
	"dp2ptcs/internal/handshake"
	"dp2ptcs/internal/messaging"
	"dp2ptcs/internal/transport"
	"dp2ptcs/internal/usecase"
)

func main() {
	keyPath := "node.key"
	listenAddr := "0.0.0.0:9000" // In a real deployment, this might be passed via ENV or flags

	// Application Context (Handles graceful shutdown on CTRL+C)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutdown signal received. Securing node and halting...")
		cancel()
	}()

	if err := run(ctx, os.Stdout, keyPath, listenAddr, os.Args[1:]); err != nil {
		log.Fatalf("[Fatal]: %v", err)
	}
}

// run separates dependency injection and execution from the main() scope.
func run(ctx context.Context, out io.Writer, keyPath, listenAddr string, args []string) error {
	// ---------------------------------------------------------
	// PHASE 1: Cryptography & Local Identity
	// ---------------------------------------------------------
	store := crypto.NewFileIdentityStore(keyPath)
	idManager := usecase.NewIdentityManager(store, rand.Reader)

	const passphrase = "operation-alpha-key"
	identity, err := idManager.LoadOrCreate(passphrase)
	if err != nil {
		return fmt.Errorf("failed to load or create identity: %w", err)
	}

	sessionManager := usecase.NewInMemorySessionManager()
	handshakeProtocol := handshake.NewHandshakeProtocol(identity.PrivateKey, identity.PublicKey)

	fmt.Fprintln(out, "Tactical Node Initialized.")
	fmt.Fprintf(out, "Node ID: %s\n", hex.EncodeToString(identity.NodeID))

	// ---------------------------------------------------------
	// PHASE 2: Transport & Framing
	// ---------------------------------------------------------
	// Assuming you have a constructor for your QUIC transport and Protobuf serializer
	// Generate the TLS config and pass it to the QUIC transport
	tlsConf := transport.GenerateEphemeralTLSConfig()
	quicTransport := transport.NewQUICTransport(tlsConf)
	serializer := messaging.NewProtobufSerializer()

	// ---------------------------------------------------------
	// PHASE 3: Control Plane (DHT)
	// ---------------------------------------------------------
	routingTable := dht.NewRoutingTable(identity.NodeID, 20)
	dhtService := dht.NewDHTService(routingTable)

	connManager := usecase.NewConnectionManager(nil, quicTransport)
	rpcClient := dht.NewNetworkRPCClient(connManager, serializer, handshakeProtocol, identity.NodeID)
	discoveryManager := usecase.NewDiscoveryManager(dhtService, rpcClient, identity.NodeID)

	// ---------------------------------------------------------
	// PHASE 4: Data Plane (NodeServer & Application Router)
	// ---------------------------------------------------------
	nodeServer := usecase.NewNodeServer(quicTransport, serializer, sessionManager, handshakeProtocol)

	// Assuming AppRouter is defined in another file in the main package (cmd/node/app_router.go)
	appRouter := NewAppRouter(dhtService, identity.NodeID)

	// Start the listener in a non-blocking goroutine
	go func() {
		fmt.Fprintf(out, "Starting multiplexed listener on %s...\n", listenAddr)
		if err := nodeServer.Start(ctx, listenAddr, appRouter.HandleMessage); err != nil {
			// Ignore context cancellation errors during standard shutdown
			if err != context.Canceled {
				log.Printf("NodeServer halted with error: %v", err)
			}
		}
	}()

	// Give the server a fraction of a second to bind to the port
	time.Sleep(100 * time.Millisecond)

	// ---------------------------------------------------------
	// PHASE 5: Network Bootstrapping
	// ---------------------------------------------------------
	// Define our bootstrap node (Command Post / Entry point)
	cpID := bytes.Repeat([]byte{0xAA}, 32)
	cpPeer, _ := domain.NewPeer(cpID, []string{"10.55.0.1:9000"})

	fmt.Fprintln(out, "Attempting to bootstrap to tactical network...")

	// We use a timeout context just for the bootstrap phase
	bootCtx, bootCancel := context.WithTimeout(ctx, 5*time.Second)
	defer bootCancel()

	if err := discoveryManager.Bootstrap(bootCtx, cpPeer); err != nil {
		fmt.Fprintf(out, "[Warning]: Bootstrap failed: %v. Running in isolated mode.\n", err)
	} else {
		fmt.Fprintln(out, "Bootstrap successful. Routing table populated.")
	}

	// ---------------------------------------------------------
	// PHASE 6: CLI Command Execution (e.g., Target Discovery)
	// ---------------------------------------------------------
	if len(args) > 0 {
		targetHex := args[0]
		targetID, err := hex.DecodeString(targetHex)
		if err != nil {
			return fmt.Errorf("invalid hex encoding for target ID: %w", err)
		}

		fmt.Fprintf(out, "\nExecuting iterative lookup for peer: %s...\n", targetHex)

		// This now triggers the real Kademlia iterative search!
		addresses, err := discoveryManager.FindPeer(ctx, targetID)
		if err != nil {
			return fmt.Errorf("peer discovery failed: %w", err)
		}
		fmt.Fprintf(out, "Successfully resolved peer! Available at addresses: %v\n", addresses)
	}

	// Block the main thread until the context is canceled (CTRL+C)
	<-ctx.Done()
	return nil
}
