package streaming

import (
	"encoding/binary"
	"testing"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPacketMarshal verifies that Packet.Marshal() creates correctly formatted bytes.
func TestPacketMarshal(t *testing.T) {
	tests := []struct {
		name    string
		packet  *Packet
		wantLen int
		check   func(*testing.T, []byte)
	}{
		{
			name: "minimal packet (no payload, no optional fields)",
			packet: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  100,
				AckThrough:   99,
				Flags:        FlagSYN,
			},
			wantLen: 22, // 4+4+4+4+1+1+2+2 = 22 bytes (ResendDelay changed from 2 to 1 byte)
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint32(1), binary.BigEndian.Uint32(data[0:4]), "SendStreamID")
				assert.Equal(t, uint32(2), binary.BigEndian.Uint32(data[4:8]), "RecvStreamID")
				assert.Equal(t, uint32(100), binary.BigEndian.Uint32(data[8:12]), "SequenceNum")
				assert.Equal(t, uint32(99), binary.BigEndian.Uint32(data[12:16]), "AckThrough")
				assert.Equal(t, uint8(0), data[16], "NACKCount")
				assert.Equal(t, uint8(0), data[17], "ResendDelay")
				assert.Equal(t, FlagSYN, binary.BigEndian.Uint16(data[18:20]), "Flags")
				assert.Equal(t, uint16(0), binary.BigEndian.Uint16(data[20:22]), "Option Size")
			},
		},
		{
			name: "packet with payload",
			packet: &Packet{
				SendStreamID: 10,
				RecvStreamID: 20,
				SequenceNum:  1000,
				AckThrough:   999,
				Flags:        0, // No flags needed - ackThrough always valid per spec
				Payload:      []byte("hello"),
			},
			wantLen: 27, // 22 + 5 bytes payload
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, []byte("hello"), data[22:], "Payload")
			},
		},
		{
			name: "packet with optional delay",
			packet: &Packet{
				SendStreamID:  1,
				RecvStreamID:  2,
				SequenceNum:   1,
				AckThrough:    0,
				Flags:         FlagDelayRequested,
				OptionalDelay: 1000, // 1 second delay
			},
			wantLen: 24, // 22 + 2 bytes optional delay
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint16(2), binary.BigEndian.Uint16(data[20:22]), "Option Size")
				assert.Equal(t, uint16(1000), binary.BigEndian.Uint16(data[22:24]), "OptionalDelay")
			},
		},
		{
			name: "choked packet (optional delay > 60000)",
			packet: &Packet{
				SendStreamID:  1,
				RecvStreamID:  2,
				SequenceNum:   1,
				AckThrough:    0,
				Flags:         FlagDelayRequested,
				OptionalDelay: 60001, // Indicates choking
			},
			wantLen: 24,
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint16(2), binary.BigEndian.Uint16(data[20:22]), "Option Size")
				assert.Equal(t, uint16(60001), binary.BigEndian.Uint16(data[22:24]), "OptionalDelay (choked)")
			},
		},
		{
			name: "multiple flags",
			packet: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  1,
				AckThrough:   0,
				Flags:        FlagSYN | 0, // No flags needed - ackThrough always valid per spec
			},
			wantLen: 22,
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, FlagSYN, binary.BigEndian.Uint16(data[18:20]), "Flags")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.packet.Marshal()
			require.NoError(t, err, "Marshal should not fail")

			assert.Equal(t, tt.wantLen, len(data), "Marshal length")

			if tt.check != nil {
				tt.check(t, data)
			}
		})
	}
}

// TestPacketMarshalBigEndian verifies all multi-byte fields use big-endian encoding.
func TestPacketMarshalBigEndian(t *testing.T) {
	pkt := &Packet{
		SendStreamID: 0x12345678,
		RecvStreamID: 0x9ABCDEF0,
		SequenceNum:  0xFEDCBA98,
		AckThrough:   0x76543210,
		Flags:        FlagSYN | FlagDelayRequested | FlagMaxPacketSizeIncluded, // Use valid flags that don't require option data
	}

	data, err := pkt.Marshal()
	require.NoError(t, err, "Marshal should not fail")

	// Verify big-endian byte order for each field
	tests := []struct {
		name     string
		offset   int
		expected []byte
	}{
		{"SendStreamID", 0, []byte{0x12, 0x34, 0x56, 0x78}},
		{"RecvStreamID", 4, []byte{0x9A, 0xBC, 0xDE, 0xF0}},
		{"SequenceNum", 8, []byte{0xFE, 0xDC, 0xBA, 0x98}},
		{"AckThrough", 12, []byte{0x76, 0x54, 0x32, 0x10}},
		{"Flags", 18, []byte{0x00, 0xC1}}, // FlagSYN (0x01) | FlagDelayRequested (0x40) | FlagMaxPacketSizeIncluded (0x80) = 0x00C1
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := data[tt.offset : tt.offset+len(tt.expected)]
			assert.Equal(t, tt.expected, got, "%s bytes", tt.name)
		})
	}
}

// TestGenerateISN verifies ISN generation produces valid random values.
func TestGenerateISN(t *testing.T) {
	// Generate multiple ISNs and verify they're different (randomness check)
	seen := make(map[uint32]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		isn, err := generateISN()
		require.NoError(t, err, "generateISN should not fail")

		assert.False(t, seen[isn], "generateISN() produced duplicate value %d", isn)
		seen[isn] = true
	}

	// Verify we got 100 unique values (extremely unlikely to fail with crypto/rand)
	assert.Equal(t, iterations, len(seen), "generateISN() should produce unique values")
}

// TestPacketFlags verifies flag constants are correct per I2P spec.
// Per https://geti2p.net/spec/streaming - bit order 15....0 (15 is MSB)
func TestPacketFlags(t *testing.T) {
	tests := []struct {
		name string
		flag uint16
		want uint16
	}{
		{"SYN (bit 0)", FlagSYN, 1 << 0},
		{"CLOSE (bit 1)", FlagCLOSE, 1 << 1},
		{"RESET (bit 2)", FlagRESET, 1 << 2},
		{"SignatureIncluded (bit 3)", FlagSignatureIncluded, 1 << 3},
		{"SignatureRequested (bit 4)", FlagSignatureRequested, 1 << 4},
		{"FromIncluded (bit 5)", FlagFromIncluded, 1 << 5},
		{"DelayRequested (bit 6)", FlagDelayRequested, 1 << 6},
		{"MaxPacketSizeIncluded (bit 7)", FlagMaxPacketSizeIncluded, 1 << 7},
		{"ProfileInteractive (bit 8)", FlagProfileInteractive, 1 << 8},
		{"ECHO (bit 9)", FlagECHO, 1 << 9},
		{"NoACK (bit 10)", FlagNoACK, 1 << 10},
		{"OfflineSignature (bit 11)", FlagOfflineSignature, 1 << 11},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.flag, "%s flag", tt.name)
		})
	}
}

// TestPacketMarshalLargePayload verifies handling of MTU-sized payloads.
func TestPacketMarshalLargePayload(t *testing.T) {
	// Test with default MTU size
	payload := make([]byte, DefaultMTU)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  1,
		AckThrough:   0,
		Flags:        0, // No flags needed - ackThrough always valid per spec
		Payload:      payload,
	}

	data, err := pkt.Marshal()
	require.NoError(t, err, "Marshal should not fail")

	expectedLen := 22 + DefaultMTU
	assert.Equal(t, expectedLen, len(data), "Marshal length")

	// Verify payload integrity
	assert.Equal(t, payload, data[22:], "Payload should not be corrupted")
}

// TestPacketMarshalZeroValues verifies handling of zero-value fields.
func TestPacketMarshalZeroValues(t *testing.T) {
	pkt := &Packet{
		// All fields zero except Flags
		Flags: FlagSYN,
	}

	data, err := pkt.Marshal()
	require.NoError(t, err, "Marshal should not fail")

	// Verify zero values are properly encoded
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(data[0:4]), "SendStreamID")
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(data[4:8]), "RecvStreamID")
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(data[8:12]), "SequenceNum")
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(data[12:16]), "AckThrough")
}

// TestPacketUnmarshal verifies that Packet.Unmarshal() correctly parses bytes.
//
// **MVP Limitation**: OptionalDelay won't be detected when payload is present.
// Tests are adjusted accordingly.
func TestPacketUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    *Packet
		wantErr bool
	}{
		{
			name: "minimal packet (no payload, no optional fields)",
			data: func() []byte {
				// Manually construct a minimal packet
				buf := make([]byte, 22)
				binary.BigEndian.PutUint32(buf[0:], 1)        // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 2)        // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 100)      // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 99)      // AckThrough
				buf[16] = 0                                   // NACKCount
				buf[17] = 0                                   // ResendDelay (1 byte)
				binary.BigEndian.PutUint16(buf[18:], FlagSYN) // Flags
				binary.BigEndian.PutUint16(buf[20:], 0)       // Option Size
				return buf
			}(),
			want: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  100,
				AckThrough:   99,
				Flags:        FlagSYN,
			},
		},
		{
			name: "packet with payload",
			data: func() []byte {
				buf := make([]byte, 22)
				binary.BigEndian.PutUint32(buf[0:], 10)
				binary.BigEndian.PutUint32(buf[4:], 20)
				binary.BigEndian.PutUint32(buf[8:], 1000)
				binary.BigEndian.PutUint32(buf[12:], 999)
				buf[16] = 0
				buf[17] = 0
				binary.BigEndian.PutUint16(buf[18:], 0) // No flags - ackThrough always valid per spec
				binary.BigEndian.PutUint16(buf[20:], 0) // Option Size
				buf = append(buf, []byte("hello")...)
				return buf
			}(),
			want: &Packet{
				SendStreamID: 10,
				RecvStreamID: 20,
				SequenceNum:  1000,
				AckThrough:   999,
				Flags:        0, // No flags needed - ackThrough always valid per spec
				Payload:      []byte("hello"),
			},
		},
		{
			name: "packet with optional delay",
			data: func() []byte {
				buf := make([]byte, 24)
				binary.BigEndian.PutUint32(buf[0:], 1)
				binary.BigEndian.PutUint32(buf[4:], 2)
				binary.BigEndian.PutUint32(buf[8:], 1)
				binary.BigEndian.PutUint32(buf[12:], 0)
				buf[16] = 0
				buf[17] = 0
				binary.BigEndian.PutUint16(buf[18:], FlagDelayRequested)
				binary.BigEndian.PutUint16(buf[20:], 2)    // Option Size
				binary.BigEndian.PutUint16(buf[22:], 1000) // OptionalDelay
				return buf
			}(),
			want: &Packet{
				SendStreamID:  1,
				RecvStreamID:  2,
				SequenceNum:   1,
				AckThrough:    0,
				Flags:         FlagDelayRequested,
				OptionalDelay: 1000,
			},
		},
		{
			name: "choked packet (optional delay > 60000)",
			data: func() []byte {
				buf := make([]byte, 24)
				binary.BigEndian.PutUint32(buf[0:], 1)
				binary.BigEndian.PutUint32(buf[4:], 2)
				binary.BigEndian.PutUint32(buf[8:], 1)
				binary.BigEndian.PutUint32(buf[12:], 0)
				buf[16] = 0
				buf[17] = 0
				binary.BigEndian.PutUint16(buf[18:], FlagDelayRequested)
				binary.BigEndian.PutUint16(buf[20:], 2)     // Option Size
				binary.BigEndian.PutUint16(buf[22:], 60001) // Choking indicator
				return buf
			}(),
			want: &Packet{
				SendStreamID:  1,
				RecvStreamID:  2,
				SequenceNum:   1,
				AckThrough:    0,
				Flags:         FlagDelayRequested,
				OptionalDelay: 60001,
			},
		},
		{
			name: "multiple flags",
			data: func() []byte {
				buf := make([]byte, 22)
				binary.BigEndian.PutUint32(buf[0:], 1)
				binary.BigEndian.PutUint32(buf[4:], 2)
				binary.BigEndian.PutUint32(buf[8:], 1)
				binary.BigEndian.PutUint32(buf[12:], 0)
				buf[16] = 0
				buf[17] = 0
				binary.BigEndian.PutUint16(buf[18:], FlagSYN)
				binary.BigEndian.PutUint16(buf[20:], 0) // Option Size
				return buf
			}(),
			want: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  1,
				AckThrough:   0,
				Flags:        FlagSYN | 0, // No flags needed - ackThrough always valid per spec
			},
		},
		{
			name:    "packet too short (error case)",
			data:    make([]byte, 21), // Need at least 22 bytes
			wantErr: true,
		},
		{
			name: "packet with NACK count (error case - not supported)",
			data: func() []byte {
				buf := make([]byte, 22)
				binary.BigEndian.PutUint32(buf[0:], 1)
				binary.BigEndian.PutUint32(buf[4:], 2)
				binary.BigEndian.PutUint32(buf[8:], 1)
				binary.BigEndian.PutUint32(buf[12:], 0)
				buf[16] = 5 // Non-zero NACK count
				buf[17] = 0
				binary.BigEndian.PutUint16(buf[18:], 0) // No flags - ackThrough always valid per spec
				binary.BigEndian.PutUint16(buf[20:], 0) // Option Size
				return buf
			}(),
			wantErr: true,
		},
		{
			name: "large payload (MTU size)",
			data: func() []byte {
				buf := make([]byte, 22)
				binary.BigEndian.PutUint32(buf[0:], 1)
				binary.BigEndian.PutUint32(buf[4:], 2)
				binary.BigEndian.PutUint32(buf[8:], 1)
				binary.BigEndian.PutUint32(buf[12:], 0)
				buf[16] = 0
				buf[17] = 0
				binary.BigEndian.PutUint16(buf[18:], 0) // No flags - ackThrough always valid per spec
				binary.BigEndian.PutUint16(buf[20:], 0) // Option Size

				payload := make([]byte, DefaultMTU)
				for i := range payload {
					payload[i] = byte(i % 256)
				}
				buf = append(buf, payload...)
				return buf
			}(),
			want: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  1,
				AckThrough:   0,
				Flags:        0, // No flags needed - ackThrough always valid per spec
				Payload: func() []byte {
					p := make([]byte, DefaultMTU)
					for i := range p {
						p[i] = byte(i % 256)
					}
					return p
				}(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &Packet{}
			err := pkt.Unmarshal(tt.data)

			if tt.wantErr {
				assert.Error(t, err, "Unmarshal should fail")
				return
			}

			require.NoError(t, err, "Unmarshal should not fail")
			assert.Equal(t, tt.want.SendStreamID, pkt.SendStreamID, "SendStreamID")
			assert.Equal(t, tt.want.RecvStreamID, pkt.RecvStreamID, "RecvStreamID")
			assert.Equal(t, tt.want.SequenceNum, pkt.SequenceNum, "SequenceNum")
			assert.Equal(t, tt.want.AckThrough, pkt.AckThrough, "AckThrough")
			assert.Equal(t, tt.want.Flags, pkt.Flags, "Flags")
			assert.Equal(t, tt.want.OptionalDelay, pkt.OptionalDelay, "OptionalDelay")
			assert.Equal(t, tt.want.Payload, pkt.Payload, "Payload")
		})
	}
}

// TestPacketUnmarshalBigEndian verifies all multi-byte fields are parsed as big-endian.
func TestPacketUnmarshalBigEndian(t *testing.T) {
	// Construct packet with known big-endian values
	// Use flags that don't include FlagDelayRequested (bit 8) or FlagMaxPacketSizeIncluded (bit 9)
	// to avoid needing option data
	data := make([]byte, 22)
	// SendStreamID: 0x12345678
	data[0], data[1], data[2], data[3] = 0x12, 0x34, 0x56, 0x78
	// RecvStreamID: 0x9ABCDEF0
	data[4], data[5], data[6], data[7] = 0x9A, 0xBC, 0xDE, 0xF0
	// SequenceNum: 0xFEDCBA98
	data[8], data[9], data[10], data[11] = 0xFE, 0xDC, 0xBA, 0x98
	// AckThrough: 0x76543210
	data[12], data[13], data[14], data[15] = 0x76, 0x54, 0x32, 0x10
	// NACKCount: 0
	data[16] = 0
	// ResendDelay: 0x12 (1 byte now)
	data[17] = 0x12
	// Flags: 0x0117 - FlagSYN(0x01) | FlagClose(0x02) | FlagReset(0x04) | FlagSignatureRequested(0x10) | FlagEcho(0x200)
	// Avoiding flags that require option data: SignatureIncluded, FromIncluded, DelayRequested, MaxPacketSizeIncluded, OfflineSignature
	data[18], data[19] = 0x01, 0x17
	// Option Size: 0
	data[20], data[21] = 0x00, 0x00

	pkt := &Packet{}
	err := pkt.Unmarshal(data)
	require.NoError(t, err, "Unmarshal should not fail")

	assert.Equal(t, uint32(0x12345678), pkt.SendStreamID, "SendStreamID")
	assert.Equal(t, uint32(0x9ABCDEF0), pkt.RecvStreamID, "RecvStreamID")
	assert.Equal(t, uint32(0xFEDCBA98), pkt.SequenceNum, "SequenceNum")
	assert.Equal(t, uint32(0x76543210), pkt.AckThrough, "AckThrough")
	assert.Equal(t, uint8(0x12), pkt.ResendDelay, "ResendDelay")
	assert.Equal(t, uint16(0x0117), pkt.Flags, "Flags")
}

// TestPacketRoundTrip verifies Marshal/Unmarshal are inverse operations.
func TestPacketRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		packet *Packet
	}{
		{
			name: "minimal packet",
			packet: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  100,
				AckThrough:   99,
				Flags:        FlagSYN,
			},
		},
		{
			name: "packet with payload",
			packet: &Packet{
				SendStreamID: 10,
				RecvStreamID: 20,
				SequenceNum:  1000,
				AckThrough:   999,
				Flags:        0, // No flags needed - ackThrough always valid per spec
				Payload:      []byte("test data"),
			},
		},
		{
			name: "packet with optional delay",
			packet: &Packet{
				SendStreamID:  1,
				RecvStreamID:  2,
				SequenceNum:   1,
				AckThrough:    0,
				Flags:         FlagDelayRequested,
				OptionalDelay: 500,
			},
		},
		{
			name: "choked packet",
			packet: &Packet{
				SendStreamID:  1,
				RecvStreamID:  2,
				SequenceNum:   1,
				AckThrough:    0,
				Flags:         FlagDelayRequested,
				OptionalDelay: 60001,
			},
		},
		{
			name: "complex packet with all fields",
			packet: &Packet{
				SendStreamID: 0x12345678,
				RecvStreamID: 0x9ABCDEF0,
				SequenceNum:  0xFEDCBA98,
				AckThrough:   0x76543210,
				Flags:        FlagSYN, // Removed FlagFromIncluded as we don't have a FromDestination
				ResendDelay:  150,     // Changed from 1500 to fit uint8 (max 255)
				Payload:      []byte("round trip test"),
			},
		},
		{
			name: "large payload",
			packet: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  1,
				AckThrough:   0,
				Flags:        0, // No flags needed - ackThrough always valid per spec
				Payload:      make([]byte, DefaultMTU),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal original packet
			data, err := tt.packet.Marshal()
			require.NoError(t, err, "Marshal should not fail")

			// Unmarshal into new packet
			roundTrip := &Packet{}
			err = roundTrip.Unmarshal(data)
			require.NoError(t, err, "Unmarshal should not fail")

			// Compare all fields
			assert.Equal(t, tt.packet.SendStreamID, roundTrip.SendStreamID, "SendStreamID")
			assert.Equal(t, tt.packet.RecvStreamID, roundTrip.RecvStreamID, "RecvStreamID")
			assert.Equal(t, tt.packet.SequenceNum, roundTrip.SequenceNum, "SequenceNum")
			assert.Equal(t, tt.packet.AckThrough, roundTrip.AckThrough, "AckThrough")
			assert.Equal(t, tt.packet.Flags, roundTrip.Flags, "Flags")
			assert.Equal(t, tt.packet.ResendDelay, roundTrip.ResendDelay, "ResendDelay")
			assert.Equal(t, tt.packet.OptionalDelay, roundTrip.OptionalDelay, "OptionalDelay")
			assert.Equal(t, tt.packet.MaxPacketSize, roundTrip.MaxPacketSize, "MaxPacketSize")
			assert.Equal(t, tt.packet.Payload, roundTrip.Payload, "Payload")
		})
	}
}

// TestPacketUnmarshalEdgeCases verifies handling of edge cases.
func TestPacketUnmarshalEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
			errMsg:  "packet too short",
		},
		{
			name:    "exactly 21 bytes (1 byte short)",
			data:    make([]byte, 21),
			wantErr: true,
			errMsg:  "packet too short",
		},
		{
			name: "exactly 22 bytes (minimal valid)",
			data: func() []byte {
				buf := make([]byte, 22)
				binary.BigEndian.PutUint16(buf[18:], FlagSYN)
				binary.BigEndian.PutUint16(buf[20:], 0) // Option Size
				return buf
			}(),
			wantErr: false,
		},
		{
			name: "23 bytes (22 + 1 byte payload)",
			data: func() []byte {
				buf := make([]byte, 23)
				binary.BigEndian.PutUint16(buf[18:], 0) // No flags - ackThrough always valid per spec
				binary.BigEndian.PutUint16(buf[20:], 0) // Option Size
				buf[22] = 0x42                          // 1 byte payload
				return buf
			}(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &Packet{}
			err := pkt.Unmarshal(tt.data)

			if tt.wantErr {
				assert.Error(t, err, "Unmarshal should fail")
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg, "Error message")
				}
			} else {
				assert.NoError(t, err, "Unmarshal should not fail")
			}
		})
	}
}

// TestPacketMarshalWithNACKs verifies that Packet.Marshal() correctly handles NACKs.
// Per I2P streaming spec: NACKCount | NACKs | ResendDelay | Flags | OptionSize
func TestPacketMarshalWithNACKs(t *testing.T) {
	tests := []struct {
		name    string
		packet  *Packet
		wantLen int
		check   func(*testing.T, []byte)
	}{
		{
			name: "single NACK",
			packet: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  100,
				AckThrough:   99,
				Flags:        0, // No flags needed - ackThrough always valid per spec
				NACKs:        []uint32{50},
			},
			wantLen: 26, // 16 + 1 + 4 + 1 + 2 + 2 = 26
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint8(1), data[16], "NACKCount should be 1")
				// Per spec: NACKs come BEFORE ResendDelay
				assert.Equal(t, uint32(50), binary.BigEndian.Uint32(data[17:21]), "NACK value")
				assert.Equal(t, uint16(0), binary.BigEndian.Uint16(data[22:24]), "Flags")
			},
		},
		{
			name: "three NACKs",
			packet: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  100,
				AckThrough:   99,
				Flags:        0, // No flags needed - ackThrough always valid per spec
				NACKs:        []uint32{10, 20, 30},
			},
			wantLen: 34, // 16 + 1 + 12 + 1 + 2 + 2 = 34
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint8(3), data[16], "NACKCount should be 3")
				// Per spec: NACKs come BEFORE ResendDelay
				assert.Equal(t, uint32(10), binary.BigEndian.Uint32(data[17:21]), "NACK 0")
				assert.Equal(t, uint32(20), binary.BigEndian.Uint32(data[21:25]), "NACK 1")
				assert.Equal(t, uint32(30), binary.BigEndian.Uint32(data[25:29]), "NACK 2")
				assert.Equal(t, uint16(0), binary.BigEndian.Uint16(data[30:32]), "Flags")
			},
		},
		{
			name: "SYN with 8 NACKs (destination hash for replay prevention)",
			packet: &Packet{
				SendStreamID: 0,
				RecvStreamID: 12345,
				SequenceNum:  0,
				AckThrough:   0,
				Flags:        FlagSYN,
				NACKs:        []uint32{0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10, 0x11121314, 0x15161718, 0x191A1B1C, 0x1D1E1F20},
			},
			wantLen: 54, // 16 + 1 + 32 + 1 + 2 + 2 = 54
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint8(8), data[16], "NACKCount should be 8 for SYN")
				// Per spec: NACKs come BEFORE ResendDelay
				// Verify first and last NACK (at positions 17 and 17+28=45)
				assert.Equal(t, uint32(0x01020304), binary.BigEndian.Uint32(data[17:21]), "First NACK")
				assert.Equal(t, uint32(0x1D1E1F20), binary.BigEndian.Uint32(data[45:49]), "Last NACK")
				assert.Equal(t, FlagSYN, binary.BigEndian.Uint16(data[50:52]), "Flags")
			},
		},
		{
			name: "NACKs with payload",
			packet: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  100,
				AckThrough:   99,
				Flags:        0, // No flags needed - ackThrough always valid per spec
				NACKs:        []uint32{50, 55},
				Payload:      []byte("test data"),
			},
			wantLen: 39, // 16 + 1 + 8 + 1 + 2 + 2 + 9 = 39
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint8(2), data[16], "NACKCount should be 2")
				// header(16) + nackCount(1) + nacks(8) + resendDelay(1) + flags(2) + optSize(2) = 30
				assert.Equal(t, []byte("test data"), data[30:], "Payload should be at correct offset")
			},
		},
		{
			name: "NACKs with optional fields",
			packet: &Packet{
				SendStreamID:  1,
				RecvStreamID:  2,
				SequenceNum:   100,
				AckThrough:    99,
				Flags:         FlagDelayRequested | FlagMaxPacketSizeIncluded,
				NACKs:         []uint32{50},
				OptionalDelay: 1000,
				MaxPacketSize: 1500,
			},
			wantLen: 30, // 16 + 1 + 4 + 1 + 2 + 2 + 4 = 30
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint8(1), data[16], "NACKCount should be 1")
				// header(16) + nackCount(1) + nacks(4) + resendDelay(1) + flags(2) + optSize(2) = 26
				assert.Equal(t, uint16(4), binary.BigEndian.Uint16(data[24:26]), "Option Size should be 4")
				assert.Equal(t, uint16(1000), binary.BigEndian.Uint16(data[26:28]), "OptionalDelay")
				assert.Equal(t, uint16(1500), binary.BigEndian.Uint16(data[28:30]), "MaxPacketSize")
			},
		},
		{
			name: "no NACKs (zero-length slice)",
			packet: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  100,
				AckThrough:   99,
				Flags:        0, // No flags needed - ackThrough always valid per spec
				NACKs:        []uint32{},
			},
			wantLen: 22, // Same as packet without NACKs field
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint8(0), data[16], "NACKCount should be 0")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.packet.Marshal()
			require.NoError(t, err, "Marshal should not fail")
			assert.Equal(t, tt.wantLen, len(data), "Packet length")
			if tt.check != nil {
				tt.check(t, data)
			}
		})
	}
}

// TestPacketUnmarshalWithNACKs verifies that Packet.Unmarshal() correctly parses NACKs.
// Per I2P streaming spec: NACKCount | NACKs | ResendDelay | Flags | OptionSize
func TestPacketUnmarshalWithNACKs(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		errMsg  string
		check   func(*testing.T, *Packet)
	}{
		{
			name: "single NACK",
			data: func() []byte {
				// Per spec: header(16) + nackCount(1) + nacks(4) + resendDelay(1) + flags(2) + optSize(2) = 26
				buf := make([]byte, 26)
				binary.BigEndian.PutUint32(buf[0:], 1)   // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 2)   // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 100) // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 99) // AckThrough
				buf[16] = 1                              // NACKCount
				binary.BigEndian.PutUint32(buf[17:], 50) // NACK value (comes BEFORE ResendDelay per spec)
				buf[21] = 0                              // ResendDelay (after NACKs)
				binary.BigEndian.PutUint16(buf[22:], 0)  // Flags
				binary.BigEndian.PutUint16(buf[24:], 0)  // Option Size
				return buf
			}(),
			wantErr: false,
			check: func(t *testing.T, pkt *Packet) {
				require.NotNil(t, pkt.NACKs, "NACKs should not be nil")
				assert.Equal(t, 1, len(pkt.NACKs), "Should have 1 NACK")
				assert.Equal(t, uint32(50), pkt.NACKs[0], "NACK value")
			},
		},
		{
			name: "three NACKs",
			data: func() []byte {
				// Per spec: header(16) + nackCount(1) + nacks(12) + resendDelay(1) + flags(2) + optSize(2) = 34
				buf := make([]byte, 34)
				binary.BigEndian.PutUint32(buf[0:], 1)   // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 2)   // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 100) // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 99) // AckThrough
				buf[16] = 3                              // NACKCount
				binary.BigEndian.PutUint32(buf[17:], 10) // NACK 0
				binary.BigEndian.PutUint32(buf[21:], 20) // NACK 1
				binary.BigEndian.PutUint32(buf[25:], 30) // NACK 2
				buf[29] = 0                              // ResendDelay (after NACKs)
				binary.BigEndian.PutUint16(buf[30:], 0)  // Flags
				binary.BigEndian.PutUint16(buf[32:], 0)  // Option Size
				return buf
			}(),
			wantErr: false,
			check: func(t *testing.T, pkt *Packet) {
				require.NotNil(t, pkt.NACKs, "NACKs should not be nil")
				assert.Equal(t, 3, len(pkt.NACKs), "Should have 3 NACKs")
				assert.Equal(t, []uint32{10, 20, 30}, pkt.NACKs, "NACK values")
			},
		},
		{
			name: "SYN with 8 NACKs (destination hash)",
			data: func() []byte {
				// Per spec: header(16) + nackCount(1) + nacks(32) + resendDelay(1) + flags(2) + optSize(2) = 54
				buf := make([]byte, 54)
				binary.BigEndian.PutUint32(buf[0:], 0)     // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 12345) // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 0)     // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 0)    // AckThrough
				buf[16] = 8                                // NACKCount
				// 8 NACKs (32 bytes total) - come BEFORE ResendDelay per spec
				for i := 0; i < 8; i++ {
					binary.BigEndian.PutUint32(buf[17+i*4:], uint32(i+1)*0x11111111)
				}
				buf[49] = 0                                   // ResendDelay (after NACKs)
				binary.BigEndian.PutUint16(buf[50:], FlagSYN) // Flags
				binary.BigEndian.PutUint16(buf[52:], 0)       // Option Size
				return buf
			}(),
			wantErr: false,
			check: func(t *testing.T, pkt *Packet) {
				require.NotNil(t, pkt.NACKs, "NACKs should not be nil")
				assert.Equal(t, 8, len(pkt.NACKs), "Should have 8 NACKs for SYN")
				assert.Equal(t, uint32(0x11111111), pkt.NACKs[0], "First NACK")
				assert.Equal(t, uint32(0x88888888), pkt.NACKs[7], "Last NACK")
			},
		},
		{
			name: "NACKs with payload",
			data: func() []byte {
				// Per spec: header(16) + nackCount(1) + nacks(8) + resendDelay(1) + flags(2) + optSize(2) + payload(5) = 35
				buf := make([]byte, 35)
				binary.BigEndian.PutUint32(buf[0:], 1)   // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 2)   // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 100) // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 99) // AckThrough
				buf[16] = 2                              // NACKCount
				binary.BigEndian.PutUint32(buf[17:], 50) // NACK 0
				binary.BigEndian.PutUint32(buf[21:], 55) // NACK 1
				buf[25] = 0                              // ResendDelay (after NACKs)
				binary.BigEndian.PutUint16(buf[26:], 0)  // Flags
				binary.BigEndian.PutUint16(buf[28:], 0)  // Option Size
				copy(buf[30:], []byte("hello"))          // Payload
				return buf
			}(),
			wantErr: false,
			check: func(t *testing.T, pkt *Packet) {
				require.NotNil(t, pkt.NACKs, "NACKs should not be nil")
				assert.Equal(t, 2, len(pkt.NACKs), "Should have 2 NACKs")
				assert.Equal(t, []byte("hello"), pkt.Payload, "Payload")
			},
		},
		{
			name: "insufficient data for NACKs",
			data: func() []byte {
				buf := make([]byte, 22)
				binary.BigEndian.PutUint32(buf[0:], 1)   // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 2)   // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 100) // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 99) // AckThrough
				buf[16] = 2                              // NACKCount = 2 but no data
				buf[17] = 0                              // ResendDelay
				binary.BigEndian.PutUint16(buf[18:], 0)  // No flags - ackThrough always valid per spec // Flags (wrong offset but will error before)
				binary.BigEndian.PutUint16(buf[20:], 0)  // Option Size
				return buf
			}(),
			wantErr: true,
			errMsg:  "packet too short for NACKs",
		},
		{
			name: "no NACKs (NACKCount = 0)",
			data: func() []byte {
				buf := make([]byte, 22)
				binary.BigEndian.PutUint32(buf[0:], 1)   // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 2)   // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 100) // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 99) // AckThrough
				buf[16] = 0                              // NACKCount
				buf[17] = 0                              // ResendDelay
				binary.BigEndian.PutUint16(buf[18:], 0)  // No flags - ackThrough always valid per spec // Flags
				binary.BigEndian.PutUint16(buf[20:], 0)  // Option Size
				return buf
			}(),
			wantErr: false,
			check: func(t *testing.T, pkt *Packet) {
				assert.Nil(t, pkt.NACKs, "NACKs should be nil when count is 0")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &Packet{}
			err := pkt.Unmarshal(tt.data)

			if tt.wantErr {
				assert.Error(t, err, "Unmarshal should fail")
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg, "Error message")
				}
			} else {
				require.NoError(t, err, "Unmarshal should not fail")
				if tt.check != nil {
					tt.check(t, pkt)
				}
			}
		})
	}
}

// TestPacketNACKsRoundTrip verifies that NACKs survive marshal/unmarshal cycle.
func TestPacketNACKsRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		packet *Packet
	}{
		{
			name: "single NACK",
			packet: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  100,
				AckThrough:   99,
				Flags:        0, // No flags needed - ackThrough always valid per spec
				NACKs:        []uint32{50},
			},
		},
		{
			name: "multiple NACKs",
			packet: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  100,
				AckThrough:   99,
				Flags:        0, // No flags needed - ackThrough always valid per spec
				NACKs:        []uint32{10, 20, 30, 40, 50},
			},
		},
		{
			name: "SYN with 8 NACKs",
			packet: &Packet{
				SendStreamID: 0,
				RecvStreamID: 12345,
				SequenceNum:  0,
				AckThrough:   0,
				Flags:        FlagSYN,
				NACKs:        []uint32{1, 2, 3, 4, 5, 6, 7, 8},
			},
		},
		{
			name: "NACKs with payload and options",
			packet: &Packet{
				SendStreamID:  1,
				RecvStreamID:  2,
				SequenceNum:   100,
				AckThrough:    99,
				Flags:         FlagMaxPacketSizeIncluded,
				NACKs:         []uint32{50, 55, 60},
				MaxPacketSize: 1500,
				Payload:       []byte("test data"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := tt.packet.Marshal()
			require.NoError(t, err, "Marshal should not fail")

			// Unmarshal
			pkt := &Packet{}
			err = pkt.Unmarshal(data)
			require.NoError(t, err, "Unmarshal should not fail")

			// Compare
			assert.Equal(t, tt.packet.SendStreamID, pkt.SendStreamID, "SendStreamID")
			assert.Equal(t, tt.packet.RecvStreamID, pkt.RecvStreamID, "RecvStreamID")
			assert.Equal(t, tt.packet.SequenceNum, pkt.SequenceNum, "SequenceNum")
			assert.Equal(t, tt.packet.AckThrough, pkt.AckThrough, "AckThrough")
			assert.Equal(t, tt.packet.Flags, pkt.Flags, "Flags")
			assert.Equal(t, tt.packet.NACKs, pkt.NACKs, "NACKs")
			assert.Equal(t, tt.packet.ResendDelay, pkt.ResendDelay, "ResendDelay")
			assert.Equal(t, tt.packet.MaxPacketSize, pkt.MaxPacketSize, "MaxPacketSize")
			assert.Equal(t, tt.packet.Payload, pkt.Payload, "Payload")
		})
	}
}

// TestPacketMarshalTooManyNACKs verifies error handling for excessive NACKs.
func TestPacketMarshalTooManyNACKs(t *testing.T) {
	nacks := make([]uint32, 256)
	for i := range nacks {
		nacks[i] = uint32(i)
	}

	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   99,
		Flags:        0, // No flags needed - ackThrough always valid per spec
		NACKs:        nacks,
	}

	_, err := pkt.Marshal()
	require.Error(t, err, "Marshal should fail with too many NACKs")
	assert.Contains(t, err.Error(), "too many NACKs", "Error message should mention NACKs limit")
}

// TestPacketWithFromDestination tests marshalling/unmarshalling packets with FROM destination.
func TestPacketWithFromDestination(t *testing.T) {
	// Create a test destination
	crypto := go_i2cp.NewCrypto()

	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err, "Failed to create destination")

	t.Run("marshal packet with FROM destination", func(t *testing.T) {
		pkt := &Packet{
			SendStreamID:    1,
			RecvStreamID:    2,
			SequenceNum:     100,
			AckThrough:      99,
			Flags:           FlagSYN | FlagFromIncluded,
			FromDestination: dest,
		}

		data, err := pkt.Marshal()
		require.NoError(t, err, "Marshal should succeed with FROM destination")

		// Verify packet size includes destination (387+ bytes for EdDSA)
		// Header (22 bytes) + destination (387+ bytes) = 409+ bytes
		assert.GreaterOrEqual(t, len(data), 409, "Packet with FROM should be at least 409 bytes")

		// Verify FROM flag is set
		flags := binary.BigEndian.Uint16(data[18:20])
		assert.Equal(t, FlagSYN|FlagFromIncluded, flags, "FROM flag should be set")
	})

	t.Run("unmarshal packet with FROM destination", func(t *testing.T) {
		// First marshal a packet
		original := &Packet{
			SendStreamID:    10,
			RecvStreamID:    20,
			SequenceNum:     500,
			AckThrough:      499,
			Flags:           FlagFromIncluded,
			FromDestination: dest,
			Payload:         []byte("test"),
		}

		data, err := original.Marshal()
		require.NoError(t, err, "Marshal should succeed")

		// Now unmarshal it
		parsed := &Packet{}
		err = parsed.Unmarshal(data)
		require.NoError(t, err, "Unmarshal should succeed with FROM destination")

		// Verify fields
		assert.Equal(t, original.SendStreamID, parsed.SendStreamID)
		assert.Equal(t, original.RecvStreamID, parsed.RecvStreamID)
		assert.Equal(t, original.SequenceNum, parsed.SequenceNum)
		assert.Equal(t, original.AckThrough, parsed.AckThrough)
		assert.Equal(t, original.Flags, parsed.Flags)
		assert.Equal(t, original.Payload, parsed.Payload)
		assert.NotNil(t, parsed.FromDestination, "FROM destination should be parsed")
	})

	t.Run("marshal without FROM when flag not set", func(t *testing.T) {
		pkt := &Packet{
			SendStreamID:    1,
			RecvStreamID:    2,
			SequenceNum:     100,
			AckThrough:      99,
			Flags:           FlagSYN, // No FlagFromIncluded
			FromDestination: dest,    // Destination present but flag not set
		}

		data, err := pkt.Marshal()
		require.NoError(t, err, "Marshal should succeed")

		// Packet should be minimal size (no destination included)
		assert.Equal(t, 22, len(data), "Packet without FROM flag should be 22 bytes")
	})

	t.Run("error when FROM flag set but destination is nil", func(t *testing.T) {
		pkt := &Packet{
			SendStreamID:    1,
			RecvStreamID:    2,
			SequenceNum:     100,
			AckThrough:      99,
			Flags:           FlagSYN | FlagFromIncluded,
			FromDestination: nil, // Flag set but no destination
		}

		_, err := pkt.Marshal()
		require.Error(t, err, "Marshal should fail when FROM flag set but destination is nil")
		assert.Contains(t, err.Error(), "FromDestination is nil")
	})
}

// TestPacketWithSignature tests marshalling/unmarshalling packets with signatures.
func TestPacketWithSignature(t *testing.T) {
	// Create a test destination (needed for signature length calculation)
	crypto := go_i2cp.NewCrypto()

	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err, "Failed to create destination")

	// Ed25519 signature is 64 bytes
	testSignature := make([]byte, 64)
	for i := range testSignature {
		testSignature[i] = byte(i)
	}

	t.Run("marshal packet with signature", func(t *testing.T) {
		pkt := &Packet{
			SendStreamID:    1,
			RecvStreamID:    2,
			SequenceNum:     100,
			AckThrough:      99,
			Flags:           FlagSYN | FlagFromIncluded | FlagSignatureIncluded,
			FromDestination: dest,
			Signature:       testSignature,
		}

		data, err := pkt.Marshal()
		require.NoError(t, err, "Marshal should succeed with signature")

		// Verify packet size: header (22) + destination (387+) + signature (64) = 473+ bytes
		assert.GreaterOrEqual(t, len(data), 473, "Packet with FROM+SIG should be at least 473 bytes")

		// Verify flags
		flags := binary.BigEndian.Uint16(data[18:20])
		assert.Equal(t, FlagSYN|FlagFromIncluded|FlagSignatureIncluded, flags)
	})

	t.Run("marshal reserves space for signature when not provided", func(t *testing.T) {
		pkt := &Packet{
			SendStreamID:    1,
			RecvStreamID:    2,
			SequenceNum:     100,
			AckThrough:      99,
			Flags:           FlagSYN | FlagFromIncluded | FlagSignatureIncluded,
			FromDestination: dest,
			Signature:       nil, // No signature provided - should reserve space
		}

		data, err := pkt.Marshal()
		require.NoError(t, err, "Marshal should succeed and reserve signature space")

		// Should still include 64 bytes for signature (all zeros)
		assert.GreaterOrEqual(t, len(data), 473, "Packet should reserve signature space")
	})

	t.Run("unmarshal packet with signature", func(t *testing.T) {
		// First marshal a packet
		original := &Packet{
			SendStreamID:    10,
			RecvStreamID:    20,
			SequenceNum:     500,
			AckThrough:      499,
			Flags:           FlagFromIncluded | FlagSignatureIncluded,
			FromDestination: dest,
			Signature:       testSignature,
			Payload:         []byte("signed"),
		}

		data, err := original.Marshal()
		require.NoError(t, err, "Marshal should succeed")

		// Now unmarshal it
		parsed := &Packet{}
		err = parsed.Unmarshal(data)
		require.NoError(t, err, "Unmarshal should succeed with signature")

		// Verify fields
		assert.Equal(t, original.SendStreamID, parsed.SendStreamID)
		assert.Equal(t, original.Flags, parsed.Flags)
		assert.NotNil(t, parsed.FromDestination, "FROM destination should be parsed")
		assert.NotNil(t, parsed.Signature, "Signature should be parsed")
		assert.Equal(t, 64, len(parsed.Signature), "Signature should be 64 bytes (Ed25519)")
		assert.Equal(t, testSignature, parsed.Signature, "Signature should match")
		assert.Equal(t, original.Payload, parsed.Payload)
	})

	t.Run("error when signature flag set but no FROM destination", func(t *testing.T) {
		pkt := &Packet{
			SendStreamID:    1,
			RecvStreamID:    2,
			SequenceNum:     100,
			AckThrough:      99,
			Flags:           FlagSYN | FlagSignatureIncluded, // Signature flag but no FROM flag
			FromDestination: nil,
			Signature:       testSignature,
		}

		_, err := pkt.Marshal()
		require.Error(t, err, "Marshal should fail when signature flag set without FROM destination")
		assert.Contains(t, err.Error(), "cannot determine signature length")
	})

	t.Run("error when signature length mismatch", func(t *testing.T) {
		wrongSig := make([]byte, 40) // Wrong size (should be 64)

		pkt := &Packet{
			SendStreamID:    1,
			RecvStreamID:    2,
			SequenceNum:     100,
			AckThrough:      99,
			Flags:           FlagSYN | FlagFromIncluded | FlagSignatureIncluded,
			FromDestination: dest,
			Signature:       wrongSig, // Wrong size
		}

		_, err := pkt.Marshal()
		require.Error(t, err, "Marshal should fail with wrong signature length")
		assert.Contains(t, err.Error(), "signature length mismatch")
	})
}

// TestPacketRoundTripWithAuthFields tests full marshal/unmarshal cycle with FROM and signature.
func TestPacketRoundTripWithAuthFields(t *testing.T) {
	// Create a test destination
	crypto := go_i2cp.NewCrypto()

	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err, "Failed to create destination")

	testSignature := make([]byte, 64)
	for i := range testSignature {
		testSignature[i] = byte(i % 256)
	}

	tests := []struct {
		name   string
		packet *Packet
	}{
		{
			name: "SYN with FROM only",
			packet: &Packet{
				SendStreamID:    0,
				RecvStreamID:    12345,
				SequenceNum:     1000,
				AckThrough:      0,
				Flags:           FlagSYN | FlagFromIncluded,
				FromDestination: dest,
			},
		},
		{
			name: "SYN with FROM and signature",
			packet: &Packet{
				SendStreamID:    0,
				RecvStreamID:    12345,
				SequenceNum:     1000,
				AckThrough:      0,
				Flags:           FlagSYN | FlagFromIncluded | FlagSignatureIncluded,
				FromDestination: dest,
				Signature:       testSignature,
			},
		},
		{
			name: "ACK with FROM, signature, and payload",
			packet: &Packet{
				SendStreamID:    54321,
				RecvStreamID:    12345,
				SequenceNum:     2000,
				AckThrough:      1999,
				Flags:           FlagFromIncluded | FlagSignatureIncluded,
				FromDestination: dest,
				Signature:       testSignature,
				Payload:         []byte("authenticated data"),
			},
		},
		{
			name: "Complex packet with all fields",
			packet: &Packet{
				SendStreamID:    54321,
				RecvStreamID:    12345,
				SequenceNum:     3000,
				AckThrough:      2999,
				Flags:           FlagDelayRequested | FlagMaxPacketSizeIncluded | FlagFromIncluded | FlagSignatureIncluded,
				OptionalDelay:   500,
				MaxPacketSize:   1024,
				FromDestination: dest,
				Signature:       testSignature,
				Payload:         []byte("complex packet"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal the packet
			data, err := tt.packet.Marshal()
			require.NoError(t, err, "Marshal should succeed")

			// Unmarshal it
			parsed := &Packet{}
			err = parsed.Unmarshal(data)
			require.NoError(t, err, "Unmarshal should succeed")

			// Verify all fields match
			assert.Equal(t, tt.packet.SendStreamID, parsed.SendStreamID, "SendStreamID mismatch")
			assert.Equal(t, tt.packet.RecvStreamID, parsed.RecvStreamID, "RecvStreamID mismatch")
			assert.Equal(t, tt.packet.SequenceNum, parsed.SequenceNum, "SequenceNum mismatch")
			assert.Equal(t, tt.packet.AckThrough, parsed.AckThrough, "AckThrough mismatch")
			assert.Equal(t, tt.packet.Flags, parsed.Flags, "Flags mismatch")
			assert.Equal(t, tt.packet.OptionalDelay, parsed.OptionalDelay, "OptionalDelay mismatch")
			assert.Equal(t, tt.packet.MaxPacketSize, parsed.MaxPacketSize, "MaxPacketSize mismatch")
			assert.Equal(t, tt.packet.Payload, parsed.Payload, "Payload mismatch")

			// Verify FROM destination if present
			if tt.packet.Flags&FlagFromIncluded != 0 {
				assert.NotNil(t, parsed.FromDestination, "FROM destination should be present")
			} else {
				assert.Nil(t, parsed.FromDestination, "FROM destination should not be present")
			}

			// Verify signature if present
			if tt.packet.Flags&FlagSignatureIncluded != 0 {
				assert.NotNil(t, parsed.Signature, "Signature should be present")
				assert.Equal(t, len(tt.packet.Signature), len(parsed.Signature), "Signature length mismatch")
				if tt.packet.Signature != nil {
					assert.Equal(t, tt.packet.Signature, parsed.Signature, "Signature content mismatch")
				}
			} else {
				assert.Nil(t, parsed.Signature, "Signature should not be present")
			}
		})
	}
}

// TestGetSignatureLength tests the signature length calculation helper.
func TestGetSignatureLength(t *testing.T) {
	t.Run("nil destination returns 0", func(t *testing.T) {
		length := getSignatureLength(nil)
		assert.Equal(t, 0, length, "Nil destination should return 0")
	})

	t.Run("Ed25519 destination returns 64 bytes", func(t *testing.T) {
		crypto := go_i2cp.NewCrypto()

		dest, err := go_i2cp.NewDestination(crypto)
		require.NoError(t, err)

		length := getSignatureLength(dest)
		assert.Equal(t, 64, length, "Ed25519 should return 64 bytes")
	})
}
