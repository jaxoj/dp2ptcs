package messaging

import (
	"dp2ptcs/internal/messaging/pb"
	"encoding/binary"
	"io"

	"google.golang.org/protobuf/proto"
)

// ProtobufSerializer implements Serializer using varint length-prefixed protocol buffers.
type ProtobufSerializer struct{}

func NewProtobufSerializer() *ProtobufSerializer {
	return &ProtobufSerializer{}
}

// Encode writes the size of the message as a varint, followed by the protobuf bytes.
func (ps *ProtobufSerializer) Encode(w io.Writer, msg Message) error {
	// Map our domain entity to Protobuf DTO
	pbMsg := &pb.TacticalMessage{
		SenderId:            msg.SenderID,
		Type:                pb.MessageType(msg.Type),
		DhPublicKey:         msg.DHPublicKey,
		Payload:             msg.Payload,
		MessageNumber:       msg.MessageNumber,
		PreviousChainLength: msg.PreviousChainLength,
	}

	data, err := proto.Marshal(pbMsg)
	if err != nil {
		return err
	}

	// Create a varint buffer for the length prefix
	sizeBuf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(sizeBuf, uint64(len(data)))

	// Write the prefix then the payload
	if _, err := w.Write(sizeBuf[:n]); err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
}

func (ps *ProtobufSerializer) Decode(r io.Reader) (Message, error) {
	// Read the length prefix (varint)
	varReader := byteReader{r}
	length, err := binary.ReadUvarint(varReader)
	if err != nil {
		return Message{}, err
	}

	// Read exactly 'length' bytes
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return Message{}, err
	}

	// UnMarshal into the Protobuf DTO
	var pbMsg pb.TacticalMessage
	if err := proto.Unmarshal(data, &pbMsg); err != nil {
		return Message{}, err
	}

	return Message{
		SenderID:            pbMsg.SenderId,
		Type:                MessageType(pbMsg.Type),
		DHPublicKey:         pbMsg.DhPublicKey,
		Payload:             pbMsg.Payload,
		MessageNumber:       pbMsg.MessageNumber,
		PreviousChainLength: pbMsg.PreviousChainLength,
	}, nil
}

// byteReader is a simple wrapper to satisfy binary.ReadUvarint's io.ByteReader requirement
type byteReader struct {
	io.Reader
}

func (b byteReader) ReadByte() (byte, error) {
	buf := make([]byte, 1)
	_, err := b.Read(buf)
	return buf[0], err
}
