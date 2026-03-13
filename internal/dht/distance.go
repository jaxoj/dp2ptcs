package dht

import "errors"

// ErrLengthMismatch is returned when comparing Node IDs of different sizes.
var ErrLengthMismatch = errors.New("Node IDs must be of equal length to calculate XOR distance")

// XORDistance calculates the logical kademlia distance between two Node IDs.
// It returns a byte slice representing the distance.
func XORDistance(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, ErrLengthMismatch
	}

	distance := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		distance[i] = a[i] ^ b[i]
	}
	return distance, nil
}
