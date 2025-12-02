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
	OptionalDelay uint16 // Optional delay in ms (0-60000 = delay, >60000 = choked)
	ResendDelay   uint16 // Resend delay hint
	MaxPacketSize uint16 // MTU - maximum payload size in bytes (sent with SYN)

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
//   - NACKCount: 1 byte (not implemented in MVP - always 0)
//   - ResendDelay: 2 bytes
//   - Flags: 2 bytes
//   - Option Size: 2 bytes (length of option data)
//   - Option Data: variable length (determined by flags)
//   - OptionalDelay: 2 bytes (if FlagDelayRequested is set)
//   - MaxPacketSize: 2 bytes (if FlagMaxPacketSizeIncluded is set)
//   - Payload: variable length
//
// This is a simplified implementation for MVP. Full spec includes:
//   - NACK ranges (for selective acknowledgment)
//   - Signature (for SIGNATURE_INCLUDED flag)
//   - From field (for FROM_INCLUDED flag)
func (p *Packet) Marshal() ([]byte, error) {
	// Calculate option data size based on flags
	optionSize := uint16(0)
	if p.Flags&FlagDelayRequested != 0 {
		optionSize += 2 // OptionalDelay
	}
	if p.Flags&FlagMaxPacketSizeIncluded != 0 {
		optionSize += 2 // MaxPacketSize
	}

	// Estimate buffer size: header (23 bytes) + options + payload
	buf := make([]byte, 0, 23+int(optionSize)+len(p.Payload))

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

	// NACKCount (1 byte) - always 0 for MVP
	buf = append(buf, 0)

	// ResendDelay (2 bytes)
	var tmp2 [2]byte
	binary.BigEndian.PutUint16(tmp2[:], p.ResendDelay)
	buf = append(buf, tmp2[:]...)

	// Flags (2 bytes)
	binary.BigEndian.PutUint16(tmp2[:], p.Flags)
	buf = append(buf, tmp2[:]...)

	// Option Size (2 bytes)
	binary.BigEndian.PutUint16(tmp2[:], optionSize)
	buf = append(buf, tmp2[:]...)

	// Option Data (variable length, determined by flags)
	// Order matters per spec: DELAY_REQUESTED (bit 6), MAX_PACKET_SIZE_INCLUDED (bit 7)
	if p.Flags&FlagDelayRequested != 0 {
		binary.BigEndian.PutUint16(tmp2[:], p.OptionalDelay)
		buf = append(buf, tmp2[:]...)
	}
	if p.Flags&FlagMaxPacketSizeIncluded != 0 {
		binary.BigEndian.PutUint16(tmp2[:], p.MaxPacketSize)
		buf = append(buf, tmp2[:]...)
	}

	// Payload
	buf = append(buf, p.Payload...)

	return buf, nil
}

// Unmarshal parses bytes into a Packet per I2P streaming protocol format.
//
// This is the inverse of Marshal(). It handles variable-length packets with
// optional fields. The minimum packet size is 21 bytes (header with no optional fields).
//
// Packet format (all multi-byte integers in big-endian):
//   - SendStreamID: 4 bytes (required)
//   - RecvStreamID: 4 bytes (required)
//   - SequenceNum: 4 bytes (required)
//   - AckThrough: 4 bytes (required)
//   - NACKCount: 1 byte (required, but always 0 for MVP)
//   - ResendDelay: 2 bytes (required)
//   - Flags: 2 bytes (required)
//   - OptionalDelay: 2 bytes (optional - see note below)
//   - Payload: variable length (everything remaining)
//
// **OptionalDelay Detection:**
// Marshal() only includes OptionalDelay if > 0. On unmarshal, we can't distinguish
// between a 2-byte OptionalDelay and a 2-byte payload prefix without ambiguity.
//
// Solution: Look ahead - if remaining bytes after flags == exactly 2, it could be
// either OptionalDelay with no payload OR a 2-byte payload. We treat it as payload
// for simplicity (packets without payload are rare). If > 2 bytes remain, we check
// if the value could be a valid OptionalDelay (0 < value <= 65535). Since any 2-byte
// sequence is technically valid, we use a simpler rule:
//
// - Marshal always appends OptionalDelay BEFORE payload when OptionalDelay > 0
// - Therefore, Unmarshal should assume the same order
// - We can't reliably detect OptionalDelay from payload without a length field
//
// **Simplified MVP approach**: Since OptionalDelay is optional and we can't reliably
// detect it without breaking payload parsing, we'll treat all bytes after flags as
// payload. This means OptionalDelay won't round-trip correctly for now.
//
// TODO: Fix this in Phase 3 by either:
//  1. Adding a length field to the packet format
//  2. Using a flag bit to indicate OptionalDelay presence
//  3. Always including OptionalDelay field (even if 0) in Marshal
//
// For MVP: We accept this limitation. Packets marshal/unmarshal their headers correctly,
// but OptionalDelay field is lost on unmarshal if payload is present.
//
// Returns an error if the data is too short or malformed.
func (p *Packet) Unmarshal(data []byte) error {
	// Minimum packet size: 23 bytes (18 required + 1 NACKCount + 2 ResendDelay + 2 Flags + 2 OptionSize)
	if len(data) < 23 {
		return fmt.Errorf("packet too short: got %d bytes, need at least 23", len(data))
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

	// NACKCount (1 byte) - skip for MVP, always 0
	nackCount := data[offset]
	offset++
	if nackCount != 0 {
		// For MVP, we don't support NACKs, so error if present
		return fmt.Errorf("NACK support not implemented (got NACKCount=%d)", nackCount)
	}

	// ResendDelay (2 bytes)
	p.ResendDelay = binary.BigEndian.Uint16(data[offset:])
	offset += 2

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
	// Order matters per spec: DELAY_REQUESTED (bit 6), MAX_PACKET_SIZE_INCLUDED (bit 7)
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
