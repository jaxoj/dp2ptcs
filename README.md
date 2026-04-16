# DP2PTCS (Decentralized Peer-2-Peer Tactical Communication System)
## 1. Project Overview

In high-stakes tactical or conflict environments, communication infrastructure is a primary target. Traditional centralized networks rely on single points of failure—servers, DNS registries, or fixed routing hubs—which can be seized, targeted by kinetic strikes, or disabled via Distributed Denial of Service (DDoS) attacks.

A **Decentralized P2P Tactical Communication System** eliminates these vulnerabilities by distributing the network's logic across every participating node. By removing centralized command-and-control (C2) servers, the system inherently gains survivability. As long as a path exists between two nodes—whether via satellite IP, tactical radios, or ad-hoc WiFi—communication persists. This architecture ensures resilience, absolute data sovereignty, and robust operational security (OPSEC).

## 2. System Architecture

The system operates as a layered, modular stack, ensuring that transport, routing, and cryptography remain strictly decoupled.

* **Peer Nodes:** Every client (soldier, vehicle, or drone) runs a fully functioning node. There are no "dumb" clients.
* **Peer Discovery System:** A distributed mechanism to locate nodes on the network without a central directory.
* **Routing Layer:** Determines the optimal path to deliver payloads, whether directly or multi-hop.
* **Transport Layer:** Handles reliable, multiplexed packet delivery over lossy physical links.
* **Cryptographic Identity Layer:** Manages self-sovereign identities using asymmetric cryptography.
* **Secure Communication Layer:** Ensures End-to-End Encryption (E2EE), Perfect Forward Secrecy (PFS), and Post-Compromise Security (PCS).

**Interaction:** The Transport Layer establishes the physical connection. The DHT maps identities to temporary IP addresses. The Routing layer determines the hop path. The Messaging layer formats the payload, which the Secure Communication layer encrypts before transport.

## 3. Peer Discovery (No Central Server)

To locate peers without a central server, the system utilizes a **Kademlia Distributed Hash Table (DHT)**.

* **Node IDs:** Upon initialization, a node generates an Ed25519 keypair. The Node ID is a 256-bit SHA-256 hash of the public key.
* **Routing Tables:** Kademlia organizes peers using a binary tree routing table based on the XOR metric. The mathematical distance between two nodes, $x$ and $y$, is calculated as:

$$d(x, y) = x \oplus y$$


* **Bootstrapping:** Nodes must connect to the network initially. In tactical environments, bootstrapping occurs via pre-shared static IPs (e.g., a command vehicle) or local multicast (mDNS) if operating on a localized mesh.
* **Address Resolution:** To find a peer, a node queries the DHT for the target's Node ID. The network iteratively returns the IP/Port of peers progressively "closer" (in XOR distance) to the target until the target's current network address is resolved.

## 4. NAT Traversal

Tactical nodes are often hidden behind Carrier-Grade NATs (CGNAT) or strict firewalls. Because we are using UDP, we can utilize standard traversal techniques:

* **UDP Hole Punching:** When Node A and Node B both sit behind NATs, they cannot connect directly. A mutually accessible third peer (acting as an introducer) shares their public IP/Port mappings. A and B then simultaneously send UDP packets to each other, "punching a hole" in their respective NAT firewalls.
* **STUN (Session Traversal Utilities for NAT):** Nodes use STUN to discover their own public IP addresses and port mappings by querying public or allied STUN servers.
* **ICE (Interactive Connectivity Establishment):** Implemented via Go libraries like `pion/ice`, the system gathers all possible connection candidates (local LAN IP, STUN-discovered public IP, and relayed IPs) and systematically tests them to find the most direct communication path.

## 5. Transport Layer Design

The system abandons TCP in favor of **QUIC** (via `quic-go`), operating directly over UDP.

* **Connection Establishment:** QUIC combines the cryptographic handshake (TLS 1.3) and transport handshake into a single round trip (1-RTT), or 0-RTT for known peers, vastly reducing latency.
* **Multiplexed Streams:** QUIC avoids TCP's Head-of-Line Blocking. If a single packet containing a text message is dropped, simultaneous file transfer streams are not delayed.
* **Connection Migration:** *This is critical for tactical networks.* A node can transition from a WiFi mesh to an LTE network or SATCOM link. Because QUIC identifies connections by a Connection ID rather than an IP/Port tuple, the session survives the IP change without renegotiating cryptography.
* **Congestion Control:** Custom congestion control algorithms (like BBR) can be tuned for high-latency, lossy links (e.g., tactical radios).

## 6. Cryptographic Identity

The system relies on a Zero-Knowledge, decentralized identity model.

* **Generation:** A local Ed25519 keypair is generated on the device.
* **Identity Mapping:** The user's network identity is purely the hash of their public key:

$$ID = H(PK_{Ed25519})$$


* **Verification:** There are no usernames or centralized Certificate Authorities (CAs). Identities are verified out-of-band (e.g., scanning a QR code on a comrade's device before deployment) or via Trust on First Use (TOFU).
* **Impersonation Defense:** Any message must be signed by the private key corresponding to the public key from which the ID was derived.

## 7. End-to-End Encryption

All payloads are secured using the Signal Protocol architecture.

* **X3DH (Extended Triple Diffie-Hellman):** Used for initial key agreement. Node A fetches Node B's pre-keys from the DHT. Node A calculates a shared secret by mixing Identity Keys ($IK$), Signed Pre-Keys ($SPK$), and One-Time Pre-Keys ($OPK$) using an HMAC-based Key Derivation Function (HKDF).
* **Double Ratchet Algorithm:** Once the session is established, every single message sent generates a new, unique message key.
* **Perfect Forward Secrecy (PFS):** If a node is captured and its current keys are extracted, past messages cannot be decrypted because previous keys are deterministically destroyed.
* **Post-Compromise Security (PCS):** If a node is temporarily compromised but regains security, new Diffie-Hellman ratchets mathematically "heal" the session, locking the attacker out of future messages.



## 8. Metadata Protection

Encrypting the payload is not enough; adversaries can map the command structure by analyzing "who talks to whom" (metadata).

* **Intermediate Peer Routing:** Direct P2P connections reveal the IP addresses of both parties. To mitigate this, traffic can be routed through a mutually selected intermediate peer (a one-hop proxy).
* **Cover Traffic:** Nodes continuously send fixed-size, randomized packets at a constant rate. An adversary observing the network sees a continuous stream of white noise, making it impossible to distinguish between a heartbeat ping and a tactical order.
* **Delayed Relays:** Intermediate nodes hold messages in memory for randomized microsecond intervals before forwarding them, destroying temporal correlation attacks.

## 9. Traffic Obfuscation

To survive Deep Packet Inspection (DPI) by hostile state actors, the system must disguise its network signature.

* **QUIC Header Encryption:** QUIC inherently encrypts most of its headers, unlike TCP.
* **Packet Padding:** All messages are padded to uniform block sizes (e.g., 2KB or 4KB). An adversary cannot infer message intent based on packet size (e.g., 50 bytes = text, 2MB = image).
* **Protocol Disguise:** Obfuscation layers (like Pluggable Transports or Shadowsocks concepts) can wrap the UDP packets to mimic standard HTTPS or WebRTC video call traffic.

## 10. Message Routing

Because tactical networks partition and merge frequently, routing must be highly adaptable.

* **Direct Messaging:** Used when nodes are on the same subnet or have established a direct QUIC connection.
* **Store-and-Forward (DTN):** Delay Tolerant Networking is vital. If Node B is offline, Node A encrypts the message and passes it to Node C, requesting Node C to hold it. When Node B comes online and announces itself to the DHT, Node C delivers the payload.
* **Multi-hop Routing:** If nodes are spread across a wide physical area, messages are routed hop-by-hop across the ad-hoc mesh.

## 11. Implementation Plan

A realistic Go implementation roadmap:

* **Phase 1 – Basic P2P Node:** Establish the Go binary. Implement basic UDP listeners, Ed25519 key generation, and basic CLI interactions.
* **Phase 2 – DHT Peer Discovery:** Integrate `go-libp2p-kad-dht`. Prove nodes can find each other across a LAN without hardcoded IPs.
* **Phase 3 – QUIC Transport:** Replace raw UDP with `quic-go`. Implement connection multiplexing and test connection migration.
* **Phase 4 – Cryptographic Identity:** Build the key store. Implement identity fingerprinting and out-of-band verification logic.
* **Phase 5 – E2EE Messaging:** Implement X3DH and the Double Ratchet. Build the messaging structs and serialization (using Protocol Buffers).
* **Phase 6 – NAT Traversal:** Integrate `pion/ice` and set up STUN resolution. Test across real-world cellular/ISP boundaries.
* **Phase 7 – Metadata Protection:** Implement constant-rate cover traffic and uniform packet padding.

## 12. Project Directory Structure

```text
/decent-comms
├── cmd/
│   └── node/              # Main application entrypoint (main.go)
├── internal/
│   ├── crypto/            # Ed25519, X3DH, Double Ratchet, KDFs
│   ├── dht/               # Kademlia implementation/wrappers
│   ├── messaging/         # Protobuf definitions, message queuing, DTN
│   ├── network/           # IP routing, ICE/STUN/NAT traversal logic
│   └── transport/         # QUIC connection management, multiplexing
├── pkg/                   # Publicly importable utility libraries
├── deployments/           # Dockerfiles, Mininet simulation scripts
├── go.mod
└── go.sum

```

## 13. Deployment and Testing

Rigorous testing is required for a military-grade application:

* **Local Simulation:** Use **Docker Compose** to spin up 50+ headless Go nodes in containers, mapped to virtual subnets.
* **Network Conditioning:** Use Linux `tc` (Traffic Control) and `netem` to simulate tactical radio constraints: artificially inject 500ms latency, 15% packet loss, and 50kbps bandwidth limits to verify QUIC's resilience.
* **NAT Testing:** Use **Mininet** to construct virtual network topologies that include simulated firewalls and symmetric NATs to validate ICE negotiation.

## 14. Security Considerations

* **Sybil Attacks:** An attacker floods the DHT with thousands of fake nodes to isolate a target (Eclipse attack). *Mitigation:* Require a computationally expensive Proof-of-Work (PoW) to generate a valid Node ID, or use a pre-shared cryptographic whitelist of authorized deployment keys.
* **Compromised Peers:** A physical device is captured. *Mitigation:* Remote kill-switches via the DHT, password-protected hardware enclaves (TPM/Secure Enclave) for key storage, and PFS limiting retroactive decryption.
* **Traffic Analysis:** *Mitigation:* The cover traffic and uniform packet sizing detailed in Section 8.

## 15. Future Improvements

To expand this beyond a portfolio project into a production-ready C2 system:

* **Mesh Radio Integration:** Abstracting the transport layer to operate over serial interfaces connected to LoRa radios or military MANET (Mobile Ad-hoc Network) hardware.
* **Anonymous Routing (Onion Layer):** Implementing Sphinx packet formats to route messages through 3+ nodes blindly, fully masking sender and receiver identities.
* **Mobile Nodes:** Compiling the core Go logic via `gomobile` into Android/AAR libraries to run on ATAK (Android Team Awareness Kit) devices.

---

## 16. QUIC UDP Buffer Warning (Important)

When running this system with `quic-go`, you may encounter warnings related to UDP buffer sizes.

This is expected behavior.

QUIC operates entirely over UDP and implements its own congestion control and packet reassembly in user space (unlike TCP, which relies on kernel-level buffering). To sustain high-throughput communication without packet loss, `quic-go` attempts to allocate large UDP receive/send buffers (~7MB).

However, most operating systems enforce conservative default limits on UDP buffer sizes to prevent memory exhaustion. As a result, the OS may cap the buffer (e.g., ~416 KB), triggering warnings like:

> failed to sufficiently increase receive buffer size

### Why This Matters

The application will still run, but:

* Throughput will be artificially limited
* Packet loss increases under load
* QUIC performance (especially over lossy links) degrades significantly

For a tactical communication system operating in constrained or high-latency environments, this bottleneck is unacceptable.

### The Fix: Increase OS UDP Buffer Limits

You must explicitly allow larger UDP buffers at the OS level.

#### Linux

Temporarily set:

```bash
sudo sysctl -w net.core.rmem_max=2500000
sudo sysctl -w net.core.wmem_max=2500000
```

Persist across reboots by adding to `/etc/sysctl.conf`:

```bash
net.core.rmem_max=2500000
net.core.wmem_max=2500000
```

#### macOS

```bash
sudo sysctl -w kern.ipc.maxsockbuf=3145728
```

#### Windows

Windows typically auto-tunes buffers, but you can mitigate related issues by running PowerShell as Administrator:

```powershell
Set-NetUDPSetting -DynamicPortRangeStartPort 1024 -DynamicPortRangeNumberOfPorts 64511
```

### Result

After applying these settings and restarting the application:

* The warning should disappear
* QUIC operates without OS-level throttling
* Network throughput and reliability improve significantly

---
