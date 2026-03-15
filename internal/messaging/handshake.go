package messaging

import "io"

// In highly-security environments, X25519 public keys are always exactly 32-bytes.
const KeySize = 32
const HandshakePayloadSize = KeySize * 2 // IdentityPub (32) + EphemeralPub (32)

// HandshakeExchange represents the unencrypted public keys sent during connection setup.
type HandshakeExchange struct {
	IdentityPub  []byte
	EphemeralPub []byte
}

func (h *HandshakeExchange) WriteTo(w io.Writer) error {
	if _, err := w.Write(h.IdentityPub); err != nil {
		return err
	}
	_, err := w.Write(h.EphemeralPub)
	return err
}

// ReadFrom reads exactly 64-bytes from the stream to construct the keys
func (h *HandshakeExchange) ReadFrom(r io.Reader) error {
	h.IdentityPub = make([]byte, KeySize)
	h.EphemeralPub = make([]byte, KeySize)

	if _, err := io.ReadFull(r, h.IdentityPub); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, h.EphemeralPub); err != nil {
		return nil
	}
	return nil
}
