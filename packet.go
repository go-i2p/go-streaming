package streaming

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	go_i2cp "github.com/go-i2p/go-i2cp"
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
	// FlagECHO indicates ping/pong packet.
	// NOTE: This flag is defined per I2P streaming spec but NOT IMPLEMENTED.
	// The flag is reserved for future use. Applications needing ping/pong
	// functionality should implement it at the application layer.
	FlagECHO uint16 = 1 << 5
	// FlagSignatureIncluded indicates signature is present
	FlagSignatureIncluded uint16 = 1 << 6
	// FlagFromIncluded indicates from field is present
	FlagFromIncluded uint16 = 1 << 7
	// FlagDelayRequested indicates optional delay field is present (bit 6)
	FlagDelayRequested uint16 = 1 << 8
	// FlagMaxPacketSizeIncluded indicates MTU is present (bit 7)
	FlagMaxPacketSizeIncluded uint16 = 1 << 9
	// FlagOfflineSignature indicates offline signature (LS2) is present
	FlagOfflineSignature uint16 = 1 << 10
)

// OfflineSig represents an I2P LS2 offline signature block.
// Offline signatures allow a destination to delegate signing authority to a transient key,
// which is useful for LeaseSet2 (LS2) destinations where the signing key may be offline.
//
// Structure per I2P specification:
//   - Expires: Unix timestamp (4 bytes) when the offline signature expires
//   - TransientSigType: Signature type of the transient key (2 bytes)
//   - TransientPublicKey: Public key for the transient signing key (variable length)
//   - DestSignature: Signature by the destination's signing key (variable length)
//
// The destination signs the transient key to prove it authorized the delegation.
type OfflineSig struct {
	Expires            uint32 // Timestamp (seconds since epoch)
	TransientSigType   uint16 // Signature type of transient key
	TransientPublicKey []byte // Variable length based on type
	DestSignature      []byte // Signature by destination key
}

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
	FromDestination  *go_i2cp.Destination // Source destination when FlagFromIncluded is set (387+ bytes)
	Signature        []byte               // Packet signature when FlagSignatureIncluded is set (variable length based on key type)
	OfflineSignature *OfflineSig          // Offline signature (LS2) when FlagOfflineSignature is set

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
//
// calculateFromDestinationSize calculates the size of the FROM destination field.
// Returns the encoded bytes and any error.
func (p *Packet) calculateFromDestinationSize() ([]byte, error) {
	if p.Flags&FlagFromIncluded == 0 {
		return nil, nil
	}
	if p.FromDestination == nil {
		return nil, fmt.Errorf("FlagFromIncluded set but FromDestination is nil")
	}
	stream := go_i2cp.NewStream(make([]byte, 0, 512))
	if err := p.FromDestination.WriteToMessage(stream); err != nil {
		return nil, fmt.Errorf("encode FROM destination: %w", err)
	}
	return stream.Bytes(), nil
}

// calculateSignatureSize returns the signature size if flag is set.
// Returns the signature length and any error.
func (p *Packet) calculateSignatureSize() (int, error) {
	if p.Flags&FlagSignatureIncluded == 0 {
		return 0, nil
	}
	sigLen := getSignatureLength(p.FromDestination)
	if sigLen == 0 {
		return 0, fmt.Errorf("FlagSignatureIncluded set but cannot determine signature length")
	}
	return sigLen, nil
}

// calculateOfflineSignatureSize calculates the size of the offline signature block.
// Returns the size and any error.
func (p *Packet) calculateOfflineSignatureSize() (int, error) {
	if p.Flags&FlagOfflineSignature == 0 {
		return 0, nil
	}
	if p.OfflineSignature == nil {
		return 0, fmt.Errorf("FlagOfflineSignature set but OfflineSignature is nil")
	}
	transientKeyLen := getPublicKeyLength(p.OfflineSignature.TransientSigType)
	destSigLen := getSignatureLength(p.FromDestination)
	return 4 + 2 + transientKeyLen + destSigLen, nil
}

// marshalRequiredFields writes the required packet fields to the buffer.
// Returns the updated buffer.
func (p *Packet) marshalRequiredFields(buf []byte) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], p.SendStreamID)
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint32(tmp[:], p.RecvStreamID)
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint32(tmp[:], p.SequenceNum)
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint32(tmp[:], p.AckThrough)
	buf = append(buf, tmp[:]...)
	return buf
}

// marshalNACKs writes the NACK count and NACK list to the buffer.
// Returns the updated buffer and any error.
func (p *Packet) marshalNACKs(buf []byte) ([]byte, error) {
	if len(p.NACKs) > 255 {
		return nil, fmt.Errorf("too many NACKs: got %d, max 255", len(p.NACKs))
	}
	buf = append(buf, byte(len(p.NACKs)))
	buf = append(buf, p.ResendDelay)

	var tmp [4]byte
	for _, nack := range p.NACKs {
		binary.BigEndian.PutUint32(tmp[:], nack)
		buf = append(buf, tmp[:]...)
	}
	return buf, nil
}

// marshalFlagsAndOptionSize writes the flags and option size to the buffer.
// Returns the updated buffer.
func (p *Packet) marshalFlagsAndOptionSize(buf []byte, optionSize uint16) []byte {
	var tmp2 [2]byte
	binary.BigEndian.PutUint16(tmp2[:], p.Flags)
	buf = append(buf, tmp2[:]...)
	binary.BigEndian.PutUint16(tmp2[:], optionSize)
	buf = append(buf, tmp2[:]...)
	return buf
}

// marshalOptionalFields writes the optional delay and max packet size fields.
// Returns the updated buffer.
func (p *Packet) marshalOptionalFields(buf []byte) []byte {
	var tmp2 [2]byte
	if p.Flags&FlagDelayRequested != 0 {
		binary.BigEndian.PutUint16(tmp2[:], p.OptionalDelay)
		buf = append(buf, tmp2[:]...)
	}
	if p.Flags&FlagMaxPacketSizeIncluded != 0 {
		binary.BigEndian.PutUint16(tmp2[:], p.MaxPacketSize)
		buf = append(buf, tmp2[:]...)
	}
	return buf
}

// marshalSignature writes the signature field to the buffer.
// Returns the updated buffer and any error.
func (p *Packet) marshalSignature(buf []byte, sigLen int) ([]byte, error) {
	if p.Flags&FlagSignatureIncluded == 0 {
		return buf, nil
	}
	if len(p.Signature) > 0 {
		if len(p.Signature) != sigLen {
			return nil, fmt.Errorf("signature length mismatch: expected %d, got %d", sigLen, len(p.Signature))
		}
		buf = append(buf, p.Signature...)
	} else {
		buf = append(buf, make([]byte, sigLen)...)
	}
	return buf, nil
}

// marshalOfflineSignature writes the offline signature block to the buffer.
// Returns the updated buffer and any error.
func (p *Packet) marshalOfflineSignature(buf []byte) ([]byte, error) {
	if p.Flags&FlagOfflineSignature == 0 {
		return buf, nil
	}

	var tmp4 [4]byte
	var tmp2 [2]byte

	binary.BigEndian.PutUint32(tmp4[:], p.OfflineSignature.Expires)
	buf = append(buf, tmp4[:]...)

	binary.BigEndian.PutUint16(tmp2[:], p.OfflineSignature.TransientSigType)
	buf = append(buf, tmp2[:]...)

	transientKeyLen := getPublicKeyLength(p.OfflineSignature.TransientSigType)
	if len(p.OfflineSignature.TransientPublicKey) != transientKeyLen {
		return nil, fmt.Errorf("transient public key length mismatch: expected %d, got %d",
			transientKeyLen, len(p.OfflineSignature.TransientPublicKey))
	}
	buf = append(buf, p.OfflineSignature.TransientPublicKey...)

	destSigLen := getSignatureLength(p.FromDestination)
	if len(p.OfflineSignature.DestSignature) != destSigLen {
		return nil, fmt.Errorf("offline signature dest signature length mismatch: expected %d, got %d",
			destSigLen, len(p.OfflineSignature.DestSignature))
	}
	buf = append(buf, p.OfflineSignature.DestSignature...)

	return buf, nil
}

// calculateOptionSizes computes all size components needed for marshaling optional fields.
// It returns the from destination bytes, signature length, offline signature size, and total option size.
func (p *Packet) calculateOptionSizes() (fromBytes []byte, sigLen int, offlineSigSize int, optionSize uint16, err error) {
	fromBytes, err = p.calculateFromDestinationSize()
	if err != nil {
		return nil, 0, 0, 0, err
	}
	sigLen, err = p.calculateSignatureSize()
	if err != nil {
		return nil, 0, 0, 0, err
	}
	offlineSigSize, err = p.calculateOfflineSignatureSize()
	if err != nil {
		return nil, 0, 0, 0, err
	}

	optionSize = p.calculateTotalOptionSize(len(fromBytes), sigLen, offlineSigSize)
	return fromBytes, sigLen, offlineSigSize, optionSize, nil
}

// calculateTotalOptionSize computes the total size of all optional fields based on flags.
func (p *Packet) calculateTotalOptionSize(fromBytesLen, sigLen, offlineSigSize int) uint16 {
	optionSize := uint16(0)
	if p.Flags&FlagDelayRequested != 0 {
		optionSize += 2
	}
	if p.Flags&FlagMaxPacketSizeIncluded != 0 {
		optionSize += 2
	}
	optionSize += uint16(fromBytesLen + sigLen + offlineSigSize)
	return optionSize
}

// marshalPacketBody assembles the packet body after the required fields.
// It marshals NACKs, flags, optional fields, from destination, signature, and offline signature.
func (p *Packet) marshalPacketBody(buf, fromBytes []byte, sigLen int, optionSize uint16) ([]byte, error) {
	var err error
	buf, err = p.marshalNACKs(buf)
	if err != nil {
		return nil, err
	}

	buf = p.marshalFlagsAndOptionSize(buf, optionSize)
	buf = p.marshalOptionalFields(buf)

	if p.Flags&FlagFromIncluded != 0 {
		buf = append(buf, fromBytes...)
	}

	buf, err = p.marshalSignature(buf, sigLen)
	if err != nil {
		return nil, err
	}

	buf, err = p.marshalOfflineSignature(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// Marshal serializes the Packet into bytes per I2P streaming protocol format.
func (p *Packet) Marshal() ([]byte, error) {
	fromBytes, sigLen, _, optionSize, err := p.calculateOptionSizes()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, 22+int(optionSize)+len(p.Payload))
	buf = p.marshalRequiredFields(buf)

	buf, err = p.marshalPacketBody(buf, fromBytes, sigLen, optionSize)
	if err != nil {
		return nil, err
	}

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
// unmarshalRequiredFields parses the fixed required fields from packet data.
// Returns the offset after parsing (18 bytes consumed).
func (p *Packet) unmarshalRequiredFields(data []byte) int {
	p.SendStreamID = binary.BigEndian.Uint32(data[0:])
	p.RecvStreamID = binary.BigEndian.Uint32(data[4:])
	p.SequenceNum = binary.BigEndian.Uint32(data[8:])
	p.AckThrough = binary.BigEndian.Uint32(data[12:])
	p.ResendDelay = uint8(data[17])
	return 18
}

// unmarshalNACKs parses the NACK list from packet data.
// Returns the new offset and any error.
func (p *Packet) unmarshalNACKs(data []byte, offset int, nackCount uint8) (int, error) {
	if nackCount == 0 {
		return offset, nil
	}

	if len(data) < offset+int(nackCount)*4 {
		return offset, fmt.Errorf("packet too short for NACKs: got %d bytes, need %d for %d NACKs",
			len(data)-offset, int(nackCount)*4, nackCount)
	}

	p.NACKs = make([]uint32, nackCount)
	for i := 0; i < int(nackCount); i++ {
		p.NACKs[i] = binary.BigEndian.Uint32(data[offset:])
		offset += 4
	}
	return offset, nil
}

// unmarshalOptionalDelay parses the optional delay field if present.
// Returns the new offset and any error.
func (p *Packet) unmarshalOptionalDelay(data []byte, offset, optionsEnd int) (int, error) {
	if p.Flags&FlagDelayRequested == 0 {
		return offset, nil
	}
	if offset+2 > optionsEnd {
		return offset, fmt.Errorf("option data too short for OptionalDelay")
	}
	p.OptionalDelay = binary.BigEndian.Uint16(data[offset:])
	return offset + 2, nil
}

// unmarshalMaxPacketSize parses the max packet size field if present.
// Returns the new offset and any error.
func (p *Packet) unmarshalMaxPacketSize(data []byte, offset, optionsEnd int) (int, error) {
	if p.Flags&FlagMaxPacketSizeIncluded == 0 {
		return offset, nil
	}
	if offset+2 > optionsEnd {
		return offset, fmt.Errorf("option data too short for MaxPacketSize")
	}
	p.MaxPacketSize = binary.BigEndian.Uint16(data[offset:])
	return offset + 2, nil
}

// unmarshalFromDestination parses the FROM destination field if present.
// Returns the new offset and any error.
func (p *Packet) unmarshalFromDestination(data []byte, offset, optionsEnd int) (int, error) {
	if p.Flags&FlagFromIncluded == 0 {
		return offset, nil
	}
	if offset >= optionsEnd {
		return offset, fmt.Errorf("option data too short for FROM destination")
	}

	stream := go_i2cp.NewStream(data[offset:optionsEnd])
	dest, err := go_i2cp.NewDestinationFromMessage(stream, nil)
	if err != nil {
		return offset, fmt.Errorf("unmarshal FROM destination: %w", err)
	}
	p.FromDestination = dest

	tempStream := go_i2cp.NewStream(make([]byte, 0, 512))
	if err := dest.WriteToMessage(tempStream); err != nil {
		return offset, fmt.Errorf("calculate FROM destination size: %w", err)
	}
	return offset + len(tempStream.Bytes()), nil
}

// unmarshalSignature parses the signature field if present.
// Returns the new offset and any error.
func (p *Packet) unmarshalSignature(data []byte, offset, optionsEnd int) (int, error) {
	if p.Flags&FlagSignatureIncluded == 0 {
		return offset, nil
	}

	sigLen := getSignatureLength(p.FromDestination)
	if sigLen == 0 {
		return offset, fmt.Errorf("cannot determine signature length (no FROM destination)")
	}
	if offset+sigLen > optionsEnd {
		return offset, fmt.Errorf("option data too short for signature: need %d bytes, have %d", sigLen, optionsEnd-offset)
	}
	p.Signature = make([]byte, sigLen)
	copy(p.Signature, data[offset:offset+sigLen])
	return offset + sigLen, nil
}

// unmarshalOfflineSignature parses the offline signature (LS2) block if present.
// Returns the new offset and any error.
func (p *Packet) unmarshalOfflineSignature(data []byte, offset, optionsEnd int) (int, error) {
	if p.Flags&FlagOfflineSignature == 0 {
		return offset, nil
	}

	if offset+6 > optionsEnd {
		return offset, fmt.Errorf("option data too short for offline signature header")
	}

	offsig := &OfflineSig{}
	offset = p.unmarshalOfflineSigHeader(data, offset, offsig)

	var err error
	offset, err = p.unmarshalTransientKey(data, offset, optionsEnd, offsig)
	if err != nil {
		return offset, err
	}

	offset, err = p.unmarshalDestSignature(data, offset, optionsEnd, offsig)
	if err != nil {
		return offset, err
	}

	p.OfflineSignature = offsig
	return offset, nil
}

// unmarshalOfflineSigHeader parses the expires and transient sig type fields.
func (p *Packet) unmarshalOfflineSigHeader(data []byte, offset int, offsig *OfflineSig) int {
	offsig.Expires = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	offsig.TransientSigType = binary.BigEndian.Uint16(data[offset:])
	offset += 2
	return offset
}

// unmarshalTransientKey parses the transient public key from the offline signature.
func (p *Packet) unmarshalTransientKey(data []byte, offset, optionsEnd int, offsig *OfflineSig) (int, error) {
	transientKeyLen := getPublicKeyLength(offsig.TransientSigType)
	if transientKeyLen == 0 {
		return offset, fmt.Errorf("cannot determine transient public key length for type %d", offsig.TransientSigType)
	}
	if offset+transientKeyLen > optionsEnd {
		return offset, fmt.Errorf("option data too short for transient public key: need %d bytes, have %d",
			transientKeyLen, optionsEnd-offset)
	}
	offsig.TransientPublicKey = make([]byte, transientKeyLen)
	copy(offsig.TransientPublicKey, data[offset:offset+transientKeyLen])
	return offset + transientKeyLen, nil
}

// unmarshalDestSignature parses the destination signature from the offline signature.
func (p *Packet) unmarshalDestSignature(data []byte, offset, optionsEnd int, offsig *OfflineSig) (int, error) {
	destSigLen := getSignatureLength(p.FromDestination)
	if destSigLen == 0 {
		return offset, fmt.Errorf("cannot determine offline signature dest signature length (no FROM destination)")
	}
	if offset+destSigLen > optionsEnd {
		return offset, fmt.Errorf("option data too short for offline signature dest signature: need %d bytes, have %d",
			destSigLen, optionsEnd-offset)
	}
	offsig.DestSignature = make([]byte, destSigLen)
	copy(offsig.DestSignature, data[offset:offset+destSigLen])
	return offset + destSigLen, nil
}

// unmarshalHeader parses the packet header including NACKs, flags, and option size.
// It returns the offset after the header, the option size, and the options end position.
func (p *Packet) unmarshalHeader(data []byte) (offset int, optionsEnd int, err error) {
	offset = p.unmarshalRequiredFields(data)
	nackCount := data[16]

	offset, err = p.unmarshalNACKs(data, offset, nackCount)
	if err != nil {
		return 0, 0, err
	}

	p.Flags = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	optionSize := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	if len(data) < offset+int(optionSize) {
		return 0, 0, fmt.Errorf("packet too short for options: got %d bytes, need %d", len(data), offset+int(optionSize))
	}

	return offset, offset + int(optionSize), nil
}

// unmarshalOptions parses all optional fields from the packet data.
func (p *Packet) unmarshalOptions(data []byte, offset, optionsEnd int) error {
	var err error
	if offset, err = p.unmarshalOptionalDelay(data, offset, optionsEnd); err != nil {
		return err
	}
	if offset, err = p.unmarshalMaxPacketSize(data, offset, optionsEnd); err != nil {
		return err
	}
	if offset, err = p.unmarshalFromDestination(data, offset, optionsEnd); err != nil {
		return err
	}
	if offset, err = p.unmarshalSignature(data, offset, optionsEnd); err != nil {
		return err
	}
	if _, err = p.unmarshalOfflineSignature(data, offset, optionsEnd); err != nil {
		return err
	}
	return nil
}

// Unmarshal parses bytes into a Packet per I2P streaming protocol format.
func (p *Packet) Unmarshal(data []byte) error {
	if len(data) < 22 {
		return fmt.Errorf("packet too short: got %d bytes, need at least 22", len(data))
	}

	offset, optionsEnd, err := p.unmarshalHeader(data)
	if err != nil {
		return err
	}

	if err := p.unmarshalOptions(data, offset, optionsEnd); err != nil {
		return err
	}

	if optionsEnd < len(data) {
		p.Payload = data[optionsEnd:]
	}

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

// I2P Signature Type Constants
// These match the I2P specification for signature types in destination certificates.
// Reference: https://geti2p.net/spec/common-structures#certificate
const (
	// SignatureTypeDSA_SHA1 is the original I2P signature type (legacy, pre-0.9.12)
	SignatureTypeDSA_SHA1 = 0
	// SignatureTypeECDSA_SHA256_P256 uses ECDSA with P-256 curve
	SignatureTypeECDSA_SHA256_P256 = 1
	// SignatureTypeECDSA_SHA384_P384 uses ECDSA with P-384 curve
	SignatureTypeECDSA_SHA384_P384 = 2
	// SignatureTypeECDSA_SHA512_P521 uses ECDSA with P-521 curve
	SignatureTypeECDSA_SHA512_P521 = 3
	// SignatureTypeRSA_SHA256_2048 uses RSA with 2048-bit key
	SignatureTypeRSA_SHA256_2048 = 4
	// SignatureTypeRSA_SHA384_3072 uses RSA with 3072-bit key
	SignatureTypeRSA_SHA384_3072 = 5
	// SignatureTypeRSA_SHA512_4096 uses RSA with 4096-bit key
	SignatureTypeRSA_SHA512_4096 = 6
	// SignatureTypeEd25519 is the modern I2P signature type (default since 0.9.15)
	SignatureTypeEd25519 = 7
	// SignatureTypeEd25519ph is Ed25519 with pre-hashing
	SignatureTypeEd25519ph = 8
)

// getSignatureLength returns the signature length in bytes for a given destination's key type.
//
// I2P streaming protocol supports multiple signature algorithms:
//   - EdDSA (Ed25519): 64 bytes - current standard (type 7)
//   - DSA: 40 bytes - legacy (type 0)
//   - ECDSA P-256: 64 bytes (type 1)
//   - ECDSA P-384: 96 bytes (type 2)
//   - ECDSA P-521: 132 bytes (type 3)
//   - RSA 2048: 256 bytes (type 4)
//   - RSA 3072: 384 bytes (type 5)
//   - RSA 4096: 512 bytes (type 6)
//
// Design rationale:
//   - Returns 0 for nil destination (no signature space needed)
//   - Detects signature type from destination certificate
//   - go-i2cp only generates Ed25519, but we must parse other types for Java I2P interop
//   - Falls back to 64 bytes (Ed25519) if type detection fails
func getSignatureLength(dest *go_i2cp.Destination) int {
	if dest == nil {
		return 0
	}

	// Get signature type from destination certificate
	// The destination is encoded as: encryption_key + signing_key + certificate
	// We need to parse the certificate to extract the signature type
	sigType := getSignatureTypeFromDestination(dest)

	// Return signature length based on type
	switch sigType {
	case SignatureTypeDSA_SHA1:
		return 40
	case SignatureTypeECDSA_SHA256_P256:
		return 64
	case SignatureTypeECDSA_SHA384_P384:
		return 96
	case SignatureTypeECDSA_SHA512_P521:
		return 132
	case SignatureTypeRSA_SHA256_2048:
		return 256
	case SignatureTypeRSA_SHA384_3072:
		return 384
	case SignatureTypeRSA_SHA512_4096:
		return 512
	case SignatureTypeEd25519, SignatureTypeEd25519ph:
		return 64
	default:
		// Default to Ed25519 size for unknown types
		// This is the most common modern signature type
		return 64
	}
}

// getPublicKeyLength returns the public key length in bytes for a given signature type.
//
// I2P signature types use different public key sizes:
//   - DSA: 128 bytes
//   - ECDSA P-256: 64 bytes (32 bytes x + 32 bytes y)
//   - ECDSA P-384: 96 bytes (48 bytes x + 48 bytes y)
//   - ECDSA P-521: 132 bytes (66 bytes x + 66 bytes y)
//   - RSA 2048: 256 bytes
//   - RSA 3072: 384 bytes
//   - RSA 4096: 512 bytes
//   - Ed25519: 32 bytes
//
// Design rationale:
//   - Required for parsing offline signatures (LS2) where transient key is variable length
//   - Maps signature type constants to corresponding public key sizes
//   - Returns 0 for unknown types (caller should handle error)
func getPublicKeyLength(sigType uint16) int {
	switch int(sigType) {
	case SignatureTypeDSA_SHA1:
		return 128
	case SignatureTypeECDSA_SHA256_P256:
		return 64
	case SignatureTypeECDSA_SHA384_P384:
		return 96
	case SignatureTypeECDSA_SHA512_P521:
		return 132
	case SignatureTypeRSA_SHA256_2048:
		return 256
	case SignatureTypeRSA_SHA384_3072:
		return 384
	case SignatureTypeRSA_SHA512_4096:
		return 512
	case SignatureTypeEd25519, SignatureTypeEd25519ph:
		return 32
	default:
		// Unknown signature type
		return 0
	}
}

// getSignatureTypeFromDestination extracts the signature type from a destination's certificate.
//
// I2P destination format (binary encoding):
//   - Public encryption key (256 bytes for ElGamal, variable for newer types)
//   - Public signing key (variable length based on signature type)
//   - Certificate (variable length, contains signature type)
//
// Certificate format for KeyCertificate (most common):
//   - Type: 5 (CERTIFICATE_TYPE_KEY)
//   - Length: variable
//   - Payload:
//   - Signing public key type (2 bytes)
//   - Crypto public key type (2 bytes)
//   - Signing public key (variable)
//   - Crypto public key (variable - usually 0 bytes as ElGamal is in dest already)
//
// For simplicity, this implementation uses a heuristic based on the destination size:
//   - Standard Ed25519 destination: ~387 bytes (256 ElGamal + 32 Ed25519 + cert)
//   - Legacy DSA destination: ~387 bytes (256 ElGamal + 128 DSA + minimal cert)
//   - Larger destinations indicate different signature types
//
// Returns SignatureTypeEd25519 as default since:
//  1. go-i2cp only creates Ed25519 destinations
//  2. It's the most common type in modern I2P network
//  3. Java I2P defaults to Ed25519 since version 0.9.15
func getSignatureTypeFromDestination(dest *go_i2cp.Destination) int {
	if dest == nil {
		return SignatureTypeEd25519
	}

	destSize := getDestinationSize(dest)
	if destSize < 0 {
		return SignatureTypeEd25519
	}

	return inferSignatureTypeFromSize(destSize)
}

// getDestinationSize serializes the destination and returns its size.
// Returns -1 if serialization fails.
func getDestinationSize(dest *go_i2cp.Destination) int {
	stream := go_i2cp.NewStream(make([]byte, 0, 512))
	if err := dest.WriteToMessage(stream); err != nil {
		return -1
	}
	return len(stream.Bytes())
}

// inferSignatureTypeFromSize uses size-based heuristics to determine signature type.
// Ed25519 destinations are typically 387-391 bytes. DSA destinations are ~387 bytes.
// Since go-i2cp only creates Ed25519 destinations (default since Java I2P 0.9.15),
// we default to Ed25519. When receiving packets from Java I2P with other signature
// types, the signature length is explicitly provided in the packet's option data.
func inferSignatureTypeFromSize(destSize int) int {
	// Standard size range for Ed25519 or DSA destinations
	if destSize >= 385 && destSize <= 395 {
		return SignatureTypeEd25519
	}
	// For non-standard sizes, default to Ed25519
	return SignatureTypeEd25519
}
