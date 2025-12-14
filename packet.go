package streaming

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/rs/zerolog/log"
)

// Packet flags per I2P streaming specification
const (
	// FlagSYN indicates synchronize - used in connection setup
	FlagSYN uint16 = 1 << 0
	// FlagACK indicates acknowledgment
	FlagACK uint16 = 1 << 1
	// FlagFIN indicates finish - no more data (deprecated, use CLOSE)
	FlagFIN uint16 = 1 << 2
	// FlagRESET indicates reset - abort connection
	FlagRESET uint16 = 1 << 3
	// FlagCLOSE indicates close - proper connection termination
	FlagCLOSE uint16 = 1 << 4
	// FlagECHO indicates ping/pong packet
	FlagECHO uint16 = 1 << 5
	// FlagSignatureIncluded indicates signature is present
	FlagSignatureIncluded uint16 = 1 << 6
	// FlagFromIncluded indicates from field is present
	FlagFromIncluded uint16 = 1 << 7
	// FlagDelayRequested indicates optional delay field is present (bit 6)
	FlagDelayRequested uint16 = 1 << 8
	// FlagMaxPacketSizeIncluded indicates MTU is present (bit 7)
	FlagMaxPacketSizeIncluded uint16 = 1 << 9
)

// Packet represents an I2P streaming protocol packet.
// Per spec, packets are variable length with optional fields.
//
// Design rationale:
//   - Implements I2P streaming packet format per specification
//   - Uses standard library encoding/binary for serialization
//   - Keeps packet format simple for MVP (no advanced options initially)
type Packet struct {
	// Required fields (always present)
	SendStreamID uint32 // Stream ID from sender's perspective
	RecvStreamID uint32 // Stream ID from receiver's perspective
	SequenceNum  uint32 // Packet sequence number
	AckThrough   uint32 // Highest sequence number acknowledged
	Flags        uint16 // Packet flags (SYN, ACK, CLOSE, etc.)

	// Optional fields (presence indicated by flags or special values)
	NACKs         []uint32 // Negative acknowledgments for selective ACK or replay prevention (destination hash in SYN)
	OptionalDelay uint16   // Optional delay in ms (0-60000 = delay, >60000 = choked)
	ResendDelay   uint8    // Resend delay hint (changed from uint16 per spec)
	MaxPacketSize uint16   // MTU - maximum payload size in bytes (sent with SYN)

	// Authentication fields (presence indicated by FlagFromIncluded and FlagSignatureIncluded)
	FromDestination *go_i2cp.Destination // Source destination when FlagFromIncluded is set (387+ bytes)
	Signature       []byte               // Packet signature when FlagSignatureIncluded is set (variable length based on key type)

	// Payload
	Payload []byte
}

// Marshal serializes a Packet to bytes per I2P streaming protocol format.
//
// Packet format (all multi-byte integers in big-endian):
//   - SendStreamID: 4 bytes
//   - RecvStreamID: 4 bytes
//   - SequenceNum: 4 bytes
//   - AckThrough: 4 bytes
//   - NACKCount: 1 byte (number of NACKs, 0-255)
//   - ResendDelay: 1 byte (changed from 2 bytes per spec)
//   - NACKs: 4 bytes each (NACKCount × 4 bytes total)
//   - Flags: 2 bytes
//   - Option Size: 2 bytes (length of option data)
//   - Option Data: variable length (determined by flags)
//   - OptionalDelay: 2 bytes (if FlagDelayRequested is set)
//   - MaxPacketSize: 2 bytes (if FlagMaxPacketSizeIncluded is set)
//   - Payload: variable length
//
// NACKs field is used for:
//   - Selective acknowledgment: indicate which packets were not received
//   - Replay prevention: SYN packets include 8 NACKs containing destination hash
//
// Signature and FROM destination fields (when flags are set):
//   - FROM destination: variable length (387+ bytes for standard EdDSA destination)
//   - Signature: variable length based on destination key type (40-512 bytes)
func (p *Packet) Marshal() ([]byte, error) {
	// Calculate option data size based on flags
	optionSize := uint16(0)
	if p.Flags&FlagDelayRequested != 0 {
		optionSize += 2 // OptionalDelay
	}
	if p.Flags&FlagMaxPacketSizeIncluded != 0 {
		optionSize += 2 // MaxPacketSize
	}

	// Calculate FROM destination size (if included)
	var fromBytes []byte
	if p.Flags&FlagFromIncluded != 0 {
		if p.FromDestination == nil {
			return nil, fmt.Errorf("FlagFromIncluded set but FromDestination is nil")
		}
		// Encode destination to I2CP message format
		stream := go_i2cp.NewStream(make([]byte, 0, 512))
		if err := p.FromDestination.WriteToMessage(stream); err != nil {
			return nil, fmt.Errorf("encode FROM destination: %w", err)
		}
		fromBytes = stream.Bytes()
		optionSize += uint16(len(fromBytes))
	}

	// Calculate signature size (if included)
	sigLen := 0
	if p.Flags&FlagSignatureIncluded != 0 {
		sigLen = getSignatureLength(p.FromDestination)
		if sigLen == 0 {
			return nil, fmt.Errorf("FlagSignatureIncluded set but cannot determine signature length")
		}
		optionSize += uint16(sigLen)
	}

	// Estimate buffer size: header (22 bytes) + options + payload
	buf := make([]byte, 0, 22+int(optionSize)+len(p.Payload))

	// Required fields (18 bytes)
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], p.SendStreamID)
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint32(tmp[:], p.RecvStreamID)
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint32(tmp[:], p.SequenceNum)
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint32(tmp[:], p.AckThrough)
	buf = append(buf, tmp[:]...)

	// NACKCount (1 byte) - number of NACKs in the list
	if len(p.NACKs) > 255 {
		return nil, fmt.Errorf("too many NACKs: got %d, max 255", len(p.NACKs))
	}
	nackCount := byte(len(p.NACKs))
	buf = append(buf, nackCount)

	// ResendDelay (1 byte) - changed from 2 bytes per spec
	buf = append(buf, p.ResendDelay)

	// Write NACK data (4 bytes per NACK)
	for _, nack := range p.NACKs {
		binary.BigEndian.PutUint32(tmp[:], nack)
		buf = append(buf, tmp[:]...)
	}

	// Flags (2 bytes)
	var tmp2 [2]byte
	binary.BigEndian.PutUint16(tmp2[:], p.Flags)
	buf = append(buf, tmp2[:]...)

	// Option Size (2 bytes)
	binary.BigEndian.PutUint16(tmp2[:], optionSize)
	buf = append(buf, tmp2[:]...)

	// Option Data (variable length, determined by flags)
	// Order matters per spec: DELAY_REQUESTED, MAX_PACKET_SIZE_INCLUDED, FROM_INCLUDED, SIGNATURE_INCLUDED
	if p.Flags&FlagDelayRequested != 0 {
		binary.BigEndian.PutUint16(tmp2[:], p.OptionalDelay)
		buf = append(buf, tmp2[:]...)
	}
	if p.Flags&FlagMaxPacketSizeIncluded != 0 {
		binary.BigEndian.PutUint16(tmp2[:], p.MaxPacketSize)
		buf = append(buf, tmp2[:]...)
	}
	if p.Flags&FlagFromIncluded != 0 {
		buf = append(buf, fromBytes...)
	}
	if p.Flags&FlagSignatureIncluded != 0 {
		// If signature is already set, use it; otherwise reserve space with zeros
		if len(p.Signature) > 0 {
			if len(p.Signature) != sigLen {
				return nil, fmt.Errorf("signature length mismatch: expected %d, got %d", sigLen, len(p.Signature))
			}
			buf = append(buf, p.Signature...)
		} else {
			// Reserve space for signature (caller will fill it later)
			buf = append(buf, make([]byte, sigLen)...)
		}
	}

	// Payload
	buf = append(buf, p.Payload...)

	return buf, nil
}

// Unmarshal parses bytes into a Packet per I2P streaming protocol format.
//
// This is the inverse of Marshal(). It handles variable-length packets with
// optional fields and NACKs. The minimum packet size is 22 bytes (header with no optional fields or NACKs).
//
// Packet format (all multi-byte integers in big-endian):
//   - SendStreamID: 4 bytes (required)
//   - RecvStreamID: 4 bytes (required)
//   - SequenceNum: 4 bytes (required)
//   - AckThrough: 4 bytes (required)
//   - NACKCount: 1 byte (required, 0-255)
//   - ResendDelay: 1 byte (required, changed from 2 bytes per spec)
//   - NACKs: 4 bytes each (NACKCount × 4 bytes, optional if NACKCount > 0)
//   - Flags: 2 bytes (required)
//   - Option Size: 2 bytes (required)
//   - Option Data: variable length (determined by flags and Option Size)
//   - OptionalDelay: 2 bytes (if FlagDelayRequested is set)
//   - MaxPacketSize: 2 bytes (if FlagMaxPacketSizeIncluded is set)
//   - FROM destination: variable length 387+ bytes (if FlagFromIncluded is set)
//   - Signature: variable length 40-512 bytes (if FlagSignatureIncluded is set)
//   - Payload: variable length (everything remaining after options)
//
// Returns an error if the data is too short or malformed.
func (p *Packet) Unmarshal(data []byte) error {
	// Minimum packet size: 22 bytes (18 required + 1 NACKCount + 1 ResendDelay + 2 Flags + 2 OptionSize)
	if len(data) < 22 {
		return fmt.Errorf("packet too short: got %d bytes, need at least 22", len(data))
	}

	offset := 0

	// Parse required fields (18 bytes)
	p.SendStreamID = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	p.RecvStreamID = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	p.SequenceNum = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	p.AckThrough = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// NACKCount (1 byte) - number of NACKs following
	nackCount := data[offset]
	offset++

	// ResendDelay (1 byte) - changed from 2 bytes per spec
	p.ResendDelay = uint8(data[offset])
	offset++

	// Parse NACKs (4 bytes each)
	if nackCount > 0 {
		// Validate we have enough data for all NACKs
		if len(data) < offset+int(nackCount)*4 {
			return fmt.Errorf("packet too short for NACKs: got %d bytes, need %d for %d NACKs",
				len(data)-offset, int(nackCount)*4, nackCount)
		}

		p.NACKs = make([]uint32, nackCount)
		for i := 0; i < int(nackCount); i++ {
			p.NACKs[i] = binary.BigEndian.Uint32(data[offset:])
			offset += 4
		}
	}

	// Flags (2 bytes)
	p.Flags = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Option Size (2 bytes)
	optionSize := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	// Validate we have enough data for options
	if len(data) < offset+int(optionSize) {
		return fmt.Errorf("packet too short for options: got %d bytes, need %d", len(data), offset+int(optionSize))
	}

	// Parse option data based on flags
	// Order matters per spec: DELAY_REQUESTED, MAX_PACKET_SIZE_INCLUDED, FROM_INCLUDED, SIGNATURE_INCLUDED
	optionsEnd := offset + int(optionSize)
	if p.Flags&FlagDelayRequested != 0 {
		if offset+2 > optionsEnd {
			return fmt.Errorf("option data too short for OptionalDelay")
		}
		p.OptionalDelay = binary.BigEndian.Uint16(data[offset:])
		offset += 2
	}
	if p.Flags&FlagMaxPacketSizeIncluded != 0 {
		if offset+2 > optionsEnd {
			return fmt.Errorf("option data too short for MaxPacketSize")
		}
		p.MaxPacketSize = binary.BigEndian.Uint16(data[offset:])
		offset += 2
	}
	if p.Flags&FlagFromIncluded != 0 {
		// Parse FROM destination (variable length, minimum 387 bytes for standard EdDSA)
		if offset >= optionsEnd {
			return fmt.Errorf("option data too short for FROM destination")
		}
		// Decode destination from I2CP message format
		stream := go_i2cp.NewStream(data[offset:optionsEnd])
		dest, err := go_i2cp.NewDestinationFromMessage(stream, nil)
		if err != nil {
			return fmt.Errorf("unmarshal FROM destination: %w", err)
		}
		p.FromDestination = dest
		// Calculate how many bytes were consumed by encoding the destination
		// We encode it again to determine its size
		tempStream := go_i2cp.NewStream(make([]byte, 0, 512))
		if err := dest.WriteToMessage(tempStream); err != nil {
			return fmt.Errorf("calculate FROM destination size: %w", err)
		}
		bytesRead := len(tempStream.Bytes())
		offset += bytesRead
	}
	if p.Flags&FlagSignatureIncluded != 0 {
		// Parse signature (variable length based on destination key type)
		sigLen := getSignatureLength(p.FromDestination)
		if sigLen == 0 {
			return fmt.Errorf("cannot determine signature length (no FROM destination)")
		}
		if offset+sigLen > optionsEnd {
			return fmt.Errorf("option data too short for signature: need %d bytes, have %d", sigLen, optionsEnd-offset)
		}
		p.Signature = make([]byte, sigLen)
		copy(p.Signature, data[offset:offset+sigLen])
		offset += sigLen
	}

	// Skip any unrecognized option data
	offset = optionsEnd

	// Payload is everything remaining
	if offset < len(data) {
		p.Payload = data[offset:]
	}

	return nil
}

// sendRaw sends a raw packet with specified flags and payload.
// This is the core primitive for all packet transmission.
//
// Design decisions:
//   - Uses I2CP protocol 6 (PROTOCOL_STREAMING) per spec
//   - Increments sendSeq after each send (caller's responsibility to manage)
//   - Simple error propagation (wrap I2CP errors with context)
//   - No retransmission logic (Phase 1 MVP - send once and hope)
//   - Logs all packet sends for debugging (essential for streaming protocol development)
func (s *StreamConn) sendRaw(flags uint16, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		log.Warn().
			Uint16("localPort", s.localPort).
			Uint16("remotePort", s.remotePort).
			Msg("attempted to send on closed connection")
		return fmt.Errorf("connection closed")
	}

	// Construct packet
	pkt := &Packet{
		SendStreamID: uint32(s.localPort), // Using port as stream ID for now
		RecvStreamID: uint32(s.remotePort),
		SequenceNum:  s.sendSeq,
		AckThrough:   s.recvSeq,
		Flags:        flags,
		Payload:      payload,
	}

	// Log packet details before sending
	log.Debug().
		Uint32("sendStreamID", pkt.SendStreamID).
		Uint32("recvStreamID", pkt.RecvStreamID).
		Uint32("seq", pkt.SequenceNum).
		Uint32("ack", pkt.AckThrough).
		Uint16("flags", flags).
		Int("payloadLen", len(payload)).
		Msg("sending packet")

	// Serialize packet
	data, err := pkt.Marshal()
	if err != nil {
		log.Error().
			Err(err).
			Msg("failed to marshal packet")
		return fmt.Errorf("marshal packet: %w", err)
	}

	// Send via I2CP
	// Protocol 6 = PROTOCOL_STREAMING per I2CP spec
	stream := go_i2cp.NewStream(data)
	err = s.session.SendMessage(
		s.dest,
		6, // PROTOCOL_STREAMING
		s.localPort,
		s.remotePort,
		stream,
		0, // nonce
	)
	if err != nil {
		log.Error().
			Err(err).
			Uint16("localPort", s.localPort).
			Uint16("remotePort", s.remotePort).
			Msg("failed to send I2CP message")
		return fmt.Errorf("send i2cp message: %w", err)
	}

	// Increment sequence number for next packet
	s.sendSeq++

	log.Trace().
		Uint32("newSeq", s.sendSeq).
		Msg("incremented sequence number")

	return nil
}

// generateISN generates a random Initial Sequence Number.
// Per RFC 6528 and I2P streaming spec, ISN should be unpredictable
// to prevent sequence number attacks.
//
// Returns a cryptographically random 32-bit value.
func generateISN() (uint32, error) {
	var isn [4]byte
	_, err := rand.Read(isn[:])
	if err != nil {
		return 0, fmt.Errorf("generate random ISN: %w", err)
	}
	return binary.BigEndian.Uint32(isn[:]), nil
}

// generateStreamID generates a random stream ID for connection identification.
// Per I2P streaming spec, stream IDs must be:
//   - Random (not sequential or predictable)
//   - Non-zero (0 is reserved for initial SYN packets)
//   - Unique per connection (probability of collision is negligible with 32-bit space)
//
// Returns a random uint32 > 0.
func generateStreamID() (uint32, error) {
	// Loop until we get a non-zero value
	// Expected iterations: ~1 (probability of 0 is 1/2^32)
	for {
		var buf [4]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, fmt.Errorf("generate random stream ID: %w", err)
		}
		id := binary.BigEndian.Uint32(buf[:])
		if id > 0 {
			return id, nil
		}
	}
}

// getSignatureLength returns the signature length in bytes for a given destination's key type.
//
// I2P modern streaming protocol uses Ed25519 signatures:
//   - EdDSA (Ed25519): 64 bytes - current standard (go-i2cp constant ED25519_SHA256 = 7)
//
// Design rationale:
//   - Returns 0 for nil destination (no signature space needed)
//   - Returns 64 bytes (Ed25519 size) as go-i2cp only supports Ed25519 signatures
//   - Legacy signature types (DSA, ECDSA, RSA) are not supported by go-i2cp
func getSignatureLength(dest *go_i2cp.Destination) int {
	if dest == nil {
		return 0
	}
	// go-i2cp only supports Ed25519 signatures (64 bytes)
	// All modern I2P destinations use Ed25519
	return 64
}
