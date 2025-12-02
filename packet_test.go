package streaming

import (
	"encoding/binary"
	"testing"

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
			wantLen: 23, // 4+4+4+4+1+2+2+2 = 23 bytes (added 2-byte Option Size)
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint32(1), binary.BigEndian.Uint32(data[0:4]), "SendStreamID")
				assert.Equal(t, uint32(2), binary.BigEndian.Uint32(data[4:8]), "RecvStreamID")
				assert.Equal(t, uint32(100), binary.BigEndian.Uint32(data[8:12]), "SequenceNum")
				assert.Equal(t, uint32(99), binary.BigEndian.Uint32(data[12:16]), "AckThrough")
				assert.Equal(t, uint8(0), data[16], "NACKCount")
				assert.Equal(t, FlagSYN, binary.BigEndian.Uint16(data[19:21]), "Flags")
				assert.Equal(t, uint16(0), binary.BigEndian.Uint16(data[21:23]), "Option Size")
			},
		},
		{
			name: "packet with payload",
			packet: &Packet{
				SendStreamID: 10,
				RecvStreamID: 20,
				SequenceNum:  1000,
				AckThrough:   999,
				Flags:        FlagACK,
				Payload:      []byte("hello"),
			},
			wantLen: 28, // 23 + 5 bytes payload
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, []byte("hello"), data[23:], "Payload")
			},
		},
		{
			name: "packet with optional delay",
			packet: &Packet{
				SendStreamID:  1,
				RecvStreamID:  2,
				SequenceNum:   1,
				AckThrough:    0,
				Flags:         FlagACK | FlagDelayRequested,
				OptionalDelay: 1000, // 1 second delay
			},
			wantLen: 25, // 23 + 2 bytes optional delay
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint16(2), binary.BigEndian.Uint16(data[21:23]), "Option Size")
				assert.Equal(t, uint16(1000), binary.BigEndian.Uint16(data[23:25]), "OptionalDelay")
			},
		},
		{
			name: "choked packet (optional delay > 60000)",
			packet: &Packet{
				SendStreamID:  1,
				RecvStreamID:  2,
				SequenceNum:   1,
				AckThrough:    0,
				Flags:         FlagACK | FlagDelayRequested,
				OptionalDelay: 60001, // Indicates choking
			},
			wantLen: 25,
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint16(2), binary.BigEndian.Uint16(data[21:23]), "Option Size")
				assert.Equal(t, uint16(60001), binary.BigEndian.Uint16(data[23:25]), "OptionalDelay (choked)")
			},
		},
		{
			name: "multiple flags",
			packet: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  1,
				AckThrough:   0,
				Flags:        FlagSYN | FlagACK,
			},
			wantLen: 23,
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, FlagSYN|FlagACK, binary.BigEndian.Uint16(data[19:21]), "Flags")
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
		Flags:        0xABCD,
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
		{"Flags", 19, []byte{0xAB, 0xCD}},
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
func TestPacketFlags(t *testing.T) {
	tests := []struct {
		name string
		flag uint16
		want uint16
	}{
		{"SYN", FlagSYN, 1 << 0},
		{"ACK", FlagACK, 1 << 1},
		{"FIN", FlagFIN, 1 << 2},
		{"RESET", FlagRESET, 1 << 3},
		{"CLOSE", FlagCLOSE, 1 << 4},
		{"ECHO", FlagECHO, 1 << 5},
		{"SignatureIncluded", FlagSignatureIncluded, 1 << 6},
		{"FromIncluded", FlagFromIncluded, 1 << 7},
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
		Flags:        FlagACK,
		Payload:      payload,
	}

	data, err := pkt.Marshal()
	require.NoError(t, err, "Marshal should not fail")

	expectedLen := 23 + DefaultMTU
	assert.Equal(t, expectedLen, len(data), "Marshal length")

	// Verify payload integrity
	assert.Equal(t, payload, data[23:], "Payload should not be corrupted")
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
				buf := make([]byte, 23)
				binary.BigEndian.PutUint32(buf[0:], 1)        // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 2)        // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 100)      // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 99)      // AckThrough
				buf[16] = 0                                   // NACKCount
				binary.BigEndian.PutUint16(buf[17:], 0)       // ResendDelay
				binary.BigEndian.PutUint16(buf[19:], FlagSYN) // Flags
				binary.BigEndian.PutUint16(buf[21:], 0)       // Option Size
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
				buf := make([]byte, 23)
				binary.BigEndian.PutUint32(buf[0:], 10)
				binary.BigEndian.PutUint32(buf[4:], 20)
				binary.BigEndian.PutUint32(buf[8:], 1000)
				binary.BigEndian.PutUint32(buf[12:], 999)
				buf[16] = 0
				binary.BigEndian.PutUint16(buf[17:], 0)
				binary.BigEndian.PutUint16(buf[19:], FlagACK)
				binary.BigEndian.PutUint16(buf[21:], 0) // Option Size
				buf = append(buf, []byte("hello")...)
				return buf
			}(),
			want: &Packet{
				SendStreamID: 10,
				RecvStreamID: 20,
				SequenceNum:  1000,
				AckThrough:   999,
				Flags:        FlagACK,
				Payload:      []byte("hello"),
			},
		},
		{
			name: "packet with optional delay",
			data: func() []byte {
				buf := make([]byte, 25)
				binary.BigEndian.PutUint32(buf[0:], 1)
				binary.BigEndian.PutUint32(buf[4:], 2)
				binary.BigEndian.PutUint32(buf[8:], 1)
				binary.BigEndian.PutUint32(buf[12:], 0)
				buf[16] = 0
				binary.BigEndian.PutUint16(buf[17:], 0)
				binary.BigEndian.PutUint16(buf[19:], FlagACK|FlagDelayRequested)
				binary.BigEndian.PutUint16(buf[21:], 2)    // Option Size
				binary.BigEndian.PutUint16(buf[23:], 1000) // OptionalDelay
				return buf
			}(),
			want: &Packet{
				SendStreamID:  1,
				RecvStreamID:  2,
				SequenceNum:   1,
				AckThrough:    0,
				Flags:         FlagACK | FlagDelayRequested,
				OptionalDelay: 1000,
			},
		},
		{
			name: "choked packet (optional delay > 60000)",
			data: func() []byte {
				buf := make([]byte, 25)
				binary.BigEndian.PutUint32(buf[0:], 1)
				binary.BigEndian.PutUint32(buf[4:], 2)
				binary.BigEndian.PutUint32(buf[8:], 1)
				binary.BigEndian.PutUint32(buf[12:], 0)
				buf[16] = 0
				binary.BigEndian.PutUint16(buf[17:], 0)
				binary.BigEndian.PutUint16(buf[19:], FlagACK|FlagDelayRequested)
				binary.BigEndian.PutUint16(buf[21:], 2)     // Option Size
				binary.BigEndian.PutUint16(buf[23:], 60001) // Choking indicator
				return buf
			}(),
			want: &Packet{
				SendStreamID:  1,
				RecvStreamID:  2,
				SequenceNum:   1,
				AckThrough:    0,
				Flags:         FlagACK | FlagDelayRequested,
				OptionalDelay: 60001,
			},
		},
		{
			name: "multiple flags",
			data: func() []byte {
				buf := make([]byte, 23)
				binary.BigEndian.PutUint32(buf[0:], 1)
				binary.BigEndian.PutUint32(buf[4:], 2)
				binary.BigEndian.PutUint32(buf[8:], 1)
				binary.BigEndian.PutUint32(buf[12:], 0)
				buf[16] = 0
				binary.BigEndian.PutUint16(buf[17:], 0)
				binary.BigEndian.PutUint16(buf[19:], FlagSYN|FlagACK)
				binary.BigEndian.PutUint16(buf[21:], 0) // Option Size
				return buf
			}(),
			want: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  1,
				AckThrough:   0,
				Flags:        FlagSYN | FlagACK,
			},
		},
		{
			name:    "packet too short (error case)",
			data:    make([]byte, 22), // Need at least 23 bytes
			wantErr: true,
		},
		{
			name: "packet with NACK count (error case - not supported)",
			data: func() []byte {
				buf := make([]byte, 23)
				binary.BigEndian.PutUint32(buf[0:], 1)
				binary.BigEndian.PutUint32(buf[4:], 2)
				binary.BigEndian.PutUint32(buf[8:], 1)
				binary.BigEndian.PutUint32(buf[12:], 0)
				buf[16] = 5 // Non-zero NACK count
				binary.BigEndian.PutUint16(buf[17:], 0)
				binary.BigEndian.PutUint16(buf[19:], FlagACK)
				binary.BigEndian.PutUint16(buf[21:], 0) // Option Size
				return buf
			}(),
			wantErr: true,
		},
		{
			name: "large payload (MTU size)",
			data: func() []byte {
				buf := make([]byte, 23)
				binary.BigEndian.PutUint32(buf[0:], 1)
				binary.BigEndian.PutUint32(buf[4:], 2)
				binary.BigEndian.PutUint32(buf[8:], 1)
				binary.BigEndian.PutUint32(buf[12:], 0)
				buf[16] = 0
				binary.BigEndian.PutUint16(buf[17:], 0)
				binary.BigEndian.PutUint16(buf[19:], FlagACK)
				binary.BigEndian.PutUint16(buf[21:], 0) // Option Size

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
				Flags:        FlagACK,
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
	data := make([]byte, 23)
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
	// ResendDelay: 0x1234
	data[17], data[18] = 0x12, 0x34
	// Flags: 0x00FF (lower 8 bits set, avoiding bits 8 and 9)
	data[19], data[20] = 0x00, 0xFF
	// Option Size: 0
	data[21], data[22] = 0x00, 0x00

	pkt := &Packet{}
	err := pkt.Unmarshal(data)
	require.NoError(t, err, "Unmarshal should not fail")

	assert.Equal(t, uint32(0x12345678), pkt.SendStreamID, "SendStreamID")
	assert.Equal(t, uint32(0x9ABCDEF0), pkt.RecvStreamID, "RecvStreamID")
	assert.Equal(t, uint32(0xFEDCBA98), pkt.SequenceNum, "SequenceNum")
	assert.Equal(t, uint32(0x76543210), pkt.AckThrough, "AckThrough")
	assert.Equal(t, uint16(0x1234), pkt.ResendDelay, "ResendDelay")
	assert.Equal(t, uint16(0x00FF), pkt.Flags, "Flags")
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
				Flags:        FlagACK,
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
				Flags:         FlagACK | FlagDelayRequested,
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
				Flags:         FlagACK | FlagDelayRequested,
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
				Flags:        FlagSYN | FlagACK | FlagFromIncluded,
				ResendDelay:  1500,
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
				Flags:        FlagACK,
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
			name:    "exactly 22 bytes (1 byte short)",
			data:    make([]byte, 22),
			wantErr: true,
			errMsg:  "packet too short",
		},
		{
			name: "exactly 23 bytes (minimal valid)",
			data: func() []byte {
				buf := make([]byte, 23)
				binary.BigEndian.PutUint16(buf[19:], FlagSYN)
				binary.BigEndian.PutUint16(buf[21:], 0) // Option Size
				return buf
			}(),
			wantErr: false,
		},
		{
			name: "24 bytes (23 + 1 byte payload)",
			data: func() []byte {
				buf := make([]byte, 24)
				binary.BigEndian.PutUint16(buf[19:], FlagACK)
				binary.BigEndian.PutUint16(buf[21:], 0) // Option Size
				buf[23] = 0x42                          // 1 byte payload
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
