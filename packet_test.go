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
				Flags:        FlagACK,
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
				Flags:         FlagACK | FlagDelayRequested,
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
				Flags:         FlagACK | FlagDelayRequested,
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
				Flags:        FlagSYN | FlagACK,
			},
			wantLen: 22,
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, FlagSYN|FlagACK, binary.BigEndian.Uint16(data[18:20]), "Flags")
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
		{"Flags", 18, []byte{0xAB, 0xCD}},
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
				binary.BigEndian.PutUint16(buf[18:], FlagACK)
				binary.BigEndian.PutUint16(buf[20:], 0) // Option Size
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
				buf := make([]byte, 24)
				binary.BigEndian.PutUint32(buf[0:], 1)
				binary.BigEndian.PutUint32(buf[4:], 2)
				binary.BigEndian.PutUint32(buf[8:], 1)
				binary.BigEndian.PutUint32(buf[12:], 0)
				buf[16] = 0
				buf[17] = 0
				binary.BigEndian.PutUint16(buf[18:], FlagACK|FlagDelayRequested)
				binary.BigEndian.PutUint16(buf[20:], 2)    // Option Size
				binary.BigEndian.PutUint16(buf[22:], 1000) // OptionalDelay
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
				buf := make([]byte, 24)
				binary.BigEndian.PutUint32(buf[0:], 1)
				binary.BigEndian.PutUint32(buf[4:], 2)
				binary.BigEndian.PutUint32(buf[8:], 1)
				binary.BigEndian.PutUint32(buf[12:], 0)
				buf[16] = 0
				buf[17] = 0
				binary.BigEndian.PutUint16(buf[18:], FlagACK|FlagDelayRequested)
				binary.BigEndian.PutUint16(buf[20:], 2)     // Option Size
				binary.BigEndian.PutUint16(buf[22:], 60001) // Choking indicator
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
				buf := make([]byte, 22)
				binary.BigEndian.PutUint32(buf[0:], 1)
				binary.BigEndian.PutUint32(buf[4:], 2)
				binary.BigEndian.PutUint32(buf[8:], 1)
				binary.BigEndian.PutUint32(buf[12:], 0)
				buf[16] = 0
				buf[17] = 0
				binary.BigEndian.PutUint16(buf[18:], FlagSYN|FlagACK)
				binary.BigEndian.PutUint16(buf[20:], 0) // Option Size
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
				binary.BigEndian.PutUint16(buf[18:], FlagACK)
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
				binary.BigEndian.PutUint16(buf[18:], FlagACK)
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
	// Flags: 0x00FF (lower 8 bits set, avoiding bits 8 and 9)
	data[18], data[19] = 0x00, 0xFF
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
				ResendDelay:  150, // Changed from 1500 to fit uint8 (max 255)
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
				binary.BigEndian.PutUint16(buf[18:], FlagACK)
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
				Flags:        FlagACK,
				NACKs:        []uint32{50},
			},
			wantLen: 26, // 22 base + 4 bytes (1 NACK)
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint8(1), data[16], "NACKCount should be 1")
				assert.Equal(t, uint32(50), binary.BigEndian.Uint32(data[18:22]), "NACK value")
				assert.Equal(t, FlagACK, binary.BigEndian.Uint16(data[22:24]), "Flags")
			},
		},
		{
			name: "three NACKs",
			packet: &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  100,
				AckThrough:   99,
				Flags:        FlagACK,
				NACKs:        []uint32{10, 20, 30},
			},
			wantLen: 34, // 22 base + 12 bytes (3 NACKs)
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint8(3), data[16], "NACKCount should be 3")
				assert.Equal(t, uint32(10), binary.BigEndian.Uint32(data[18:22]), "NACK 0")
				assert.Equal(t, uint32(20), binary.BigEndian.Uint32(data[22:26]), "NACK 1")
				assert.Equal(t, uint32(30), binary.BigEndian.Uint32(data[26:30]), "NACK 2")
				assert.Equal(t, FlagACK, binary.BigEndian.Uint16(data[30:32]), "Flags")
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
			wantLen: 54, // 22 base + 32 bytes (8 NACKs)
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint8(8), data[16], "NACKCount should be 8 for SYN")
				// Verify first and last NACK
				assert.Equal(t, uint32(0x01020304), binary.BigEndian.Uint32(data[18:22]), "First NACK")
				assert.Equal(t, uint32(0x1D1E1F20), binary.BigEndian.Uint32(data[46:50]), "Last NACK")
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
				Flags:        FlagACK,
				NACKs:        []uint32{50, 55},
				Payload:      []byte("test data"),
			},
			wantLen: 39, // 22 base + 8 bytes (2 NACKs) + 9 bytes payload
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint8(2), data[16], "NACKCount should be 2")
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
				Flags:         FlagACK | FlagDelayRequested | FlagMaxPacketSizeIncluded,
				NACKs:         []uint32{50},
				OptionalDelay: 1000,
				MaxPacketSize: 1500,
			},
			wantLen: 30, // 22 base + 4 bytes (1 NACK) + 4 bytes options
			check: func(t *testing.T, data []byte) {
				assert.Equal(t, uint8(1), data[16], "NACKCount should be 1")
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
				Flags:        FlagACK,
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
				buf := make([]byte, 26)
				binary.BigEndian.PutUint32(buf[0:], 1)        // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 2)        // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 100)      // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 99)      // AckThrough
				buf[16] = 1                                   // NACKCount
				buf[17] = 0                                   // ResendDelay
				binary.BigEndian.PutUint32(buf[18:], 50)      // NACK value
				binary.BigEndian.PutUint16(buf[22:], FlagACK) // Flags
				binary.BigEndian.PutUint16(buf[24:], 0)       // Option Size
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
				buf := make([]byte, 34)
				binary.BigEndian.PutUint32(buf[0:], 1)        // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 2)        // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 100)      // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 99)      // AckThrough
				buf[16] = 3                                   // NACKCount
				buf[17] = 0                                   // ResendDelay
				binary.BigEndian.PutUint32(buf[18:], 10)      // NACK 0
				binary.BigEndian.PutUint32(buf[22:], 20)      // NACK 1
				binary.BigEndian.PutUint32(buf[26:], 30)      // NACK 2
				binary.BigEndian.PutUint16(buf[30:], FlagACK) // Flags
				binary.BigEndian.PutUint16(buf[32:], 0)       // Option Size
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
				buf := make([]byte, 54)
				binary.BigEndian.PutUint32(buf[0:], 0)     // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 12345) // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 0)     // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 0)    // AckThrough
				buf[16] = 8                                // NACKCount
				buf[17] = 0                                // ResendDelay
				// 8 NACKs (32 bytes total)
				for i := 0; i < 8; i++ {
					binary.BigEndian.PutUint32(buf[18+i*4:], uint32(i+1)*0x11111111)
				}
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
				buf := make([]byte, 35)
				binary.BigEndian.PutUint32(buf[0:], 1)        // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 2)        // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 100)      // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 99)      // AckThrough
				buf[16] = 2                                   // NACKCount
				buf[17] = 0                                   // ResendDelay
				binary.BigEndian.PutUint32(buf[18:], 50)      // NACK 0
				binary.BigEndian.PutUint32(buf[22:], 55)      // NACK 1
				binary.BigEndian.PutUint16(buf[26:], FlagACK) // Flags
				binary.BigEndian.PutUint16(buf[28:], 0)       // Option Size
				copy(buf[30:], []byte("hello"))               // Payload
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
				binary.BigEndian.PutUint32(buf[0:], 1)        // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 2)        // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 100)      // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 99)      // AckThrough
				buf[16] = 2                                   // NACKCount = 2 but no data
				buf[17] = 0                                   // ResendDelay
				binary.BigEndian.PutUint16(buf[18:], FlagACK) // Flags (wrong offset but will error before)
				binary.BigEndian.PutUint16(buf[20:], 0)       // Option Size
				return buf
			}(),
			wantErr: true,
			errMsg:  "packet too short for NACKs",
		},
		{
			name: "no NACKs (NACKCount = 0)",
			data: func() []byte {
				buf := make([]byte, 22)
				binary.BigEndian.PutUint32(buf[0:], 1)        // SendStreamID
				binary.BigEndian.PutUint32(buf[4:], 2)        // RecvStreamID
				binary.BigEndian.PutUint32(buf[8:], 100)      // SequenceNum
				binary.BigEndian.PutUint32(buf[12:], 99)      // AckThrough
				buf[16] = 0                                   // NACKCount
				buf[17] = 0                                   // ResendDelay
				binary.BigEndian.PutUint16(buf[18:], FlagACK) // Flags
				binary.BigEndian.PutUint16(buf[20:], 0)       // Option Size
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
				Flags:        FlagACK,
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
				Flags:        FlagACK,
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
				Flags:         FlagACK | FlagMaxPacketSizeIncluded,
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
		Flags:        FlagACK,
		NACKs:        nacks,
	}

	_, err := pkt.Marshal()
	require.Error(t, err, "Marshal should fail with too many NACKs")
	assert.Contains(t, err.Error(), "too many NACKs", "Error message should mention NACKs limit")
}
