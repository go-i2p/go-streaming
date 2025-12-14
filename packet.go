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
// This implementation still lacks (to be added in future phases):
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
