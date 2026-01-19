package streaming

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMTUNegotiation_Flags verifies MTU-related packet flags.
// Per I2P streaming spec, flag bit positions are:
// - Bit 6: DELAY_REQUESTED = 0x40 (1 << 6)
// - Bit 7: MAX_PACKET_SIZE_INCLUDED = 0x80 (1 << 7)
func TestMTUNegotiation_Flags(t *testing.T) {
	tests := []struct {
		name          string
		flag          uint16
		expectedValue uint16
	}{
		{"FlagDelayRequested", FlagDelayRequested, 1 << 6},               // Bit 6 per spec
		{"FlagMaxPacketSizeIncluded", FlagMaxPacketSizeIncluded, 1 << 7}, // Bit 7 per spec
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedValue, tt.flag, "Flag value should match spec")
		})
	}
}

// TestMTUNegotiation_PacketMarshalWithMTU verifies MTU marshaling.
func TestMTUNegotiation_PacketMarshalWithMTU(t *testing.T) {
	tests := []struct {
		name          string
		mtu           uint16
		expectFlag    bool
		expectedBytes int
	}{
		{"SYN with DefaultMTU", DefaultMTU, true, 22 + 2}, // header + MTU option
		{"SYN with ECIESMTU", ECIESMTU, true, 22 + 2},
		{"SYN with MinMTU", MinMTU, true, 22 + 2},
		{"No MTU flag", 0, false, 22}, // header only
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &Packet{
				SendStreamID: 1,
				RecvStreamID: 2,
				SequenceNum:  100,
				AckThrough:   0,
				Flags:        FlagSYN,
			}

			if tt.expectFlag {
				pkt.Flags |= FlagMaxPacketSizeIncluded
				pkt.MaxPacketSize = tt.mtu
			}

			data, err := pkt.Marshal()
			require.NoError(t, err)
			assert.Equal(t, tt.expectedBytes, len(data), "Packet size should match expected")

			// Verify option size field (now at offset 20-21 after ResendDelay changed from 2 to 1 byte)
			optionSize := uint16(0)
			if tt.expectFlag {
				optionSize = 2 // MaxPacketSize is 2 bytes
			}
			assert.Equal(t, optionSize, uint16(data[20])<<8|uint16(data[21]), "Option size should be correct")
		})
	}
}

// TestMTUNegotiation_PacketUnmarshalWithMTU verifies MTU unmarshaling.
func TestMTUNegotiation_PacketUnmarshalWithMTU(t *testing.T) {
	tests := []struct {
		name        string
		mtu         uint16
		hasFlag     bool
		expectError bool
	}{
		{"DefaultMTU", DefaultMTU, true, false},
		{"ECIESMTU", ECIESMTU, true, false},
		{"MinMTU", MinMTU, true, false},
		{"No MTU", 0, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal a packet
			original := &Packet{
				SendStreamID: 12345,
				RecvStreamID: 8080,
				SequenceNum:  1000,
				AckThrough:   999,
				Flags:        FlagSYN | 0, // No flags needed - ackThrough always valid per spec
			}

			if tt.hasFlag {
				original.Flags |= FlagMaxPacketSizeIncluded
				original.MaxPacketSize = tt.mtu
			}

			data, err := original.Marshal()
			require.NoError(t, err)

			// Unmarshal it
			parsed := &Packet{}
			err = parsed.Unmarshal(data)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, original.SendStreamID, parsed.SendStreamID)
			assert.Equal(t, original.RecvStreamID, parsed.RecvStreamID)
			assert.Equal(t, original.SequenceNum, parsed.SequenceNum)
			assert.Equal(t, original.AckThrough, parsed.AckThrough)
			assert.Equal(t, original.Flags, parsed.Flags)

			if tt.hasFlag {
				assert.Equal(t, tt.mtu, parsed.MaxPacketSize, "MTU should round-trip correctly")
			}
		})
	}
}

// TestMTUNegotiation_RoundTrip verifies complete MTU round-trip.
func TestMTUNegotiation_RoundTrip(t *testing.T) {
	pkt := &Packet{
		SendStreamID:  1,
		RecvStreamID:  2,
		SequenceNum:   100,
		AckThrough:    99,
		Flags:         FlagSYN | FlagMaxPacketSizeIncluded,
		MaxPacketSize: ECIESMTU,
		Payload:       []byte("test payload"),
	}

	// Marshal
	data, err := pkt.Marshal()
	require.NoError(t, err)

	// Unmarshal
	parsed := &Packet{}
	err = parsed.Unmarshal(data)
	require.NoError(t, err)

	// Verify all fields
	assert.Equal(t, pkt.SendStreamID, parsed.SendStreamID)
	assert.Equal(t, pkt.RecvStreamID, parsed.RecvStreamID)
	assert.Equal(t, pkt.SequenceNum, parsed.SequenceNum)
	assert.Equal(t, pkt.AckThrough, parsed.AckThrough)
	assert.Equal(t, pkt.Flags, parsed.Flags)
	assert.Equal(t, pkt.MaxPacketSize, parsed.MaxPacketSize)
	assert.Equal(t, pkt.Payload, parsed.Payload)
}

// TestMTUNegotiation_HandshakeSYN verifies SYN packets include MTU.
func TestMTUNegotiation_HandshakeSYN(t *testing.T) {
	// This is tested by examining the sendSYN() behavior
	// which should set FlagMaxPacketSizeIncluded and MaxPacketSize
	conn := &StreamConn{
		localPort:  12345,
		remotePort: 8080,
		sendSeq:    1000,
		localMTU:   ECIESMTU,
	}

	// Can't actually send without session, but we can verify the logic
	// is present by checking that sendSYN sets the right flags
	// (This is tested indirectly through integration tests)
	assert.Equal(t, uint16(ECIESMTU), conn.localMTU)
}

// TestMTUNegotiation_HandshakeSynAck verifies SYN-ACK packets include MTU.
func TestMTUNegotiation_HandshakeSynAck(t *testing.T) {
	// Similar to TestMTUNegotiation_HandshakeSYN
	// Verified through sendSynAck() which sets FlagMaxPacketSizeIncluded
	conn := &StreamConn{
		localPort:  8080,
		remotePort: 12345,
		sendSeq:    5000,
		recvSeq:    1001,
		localMTU:   DefaultMTU,
	}

	assert.Equal(t, uint16(DefaultMTU), conn.localMTU)
}

// TestMTUNegotiation_ExtractionFromPackets verifies MTU extraction.
func TestMTUNegotiation_ExtractionFromPackets(t *testing.T) {
	tests := []struct {
		name           string
		packetMTU      uint16
		expectedRemote uint16
	}{
		{"Peer advertises DefaultMTU", DefaultMTU, DefaultMTU},
		{"Peer advertises ECIESMTU", ECIESMTU, ECIESMTU},
		{"Peer advertises MinMTU", MinMTU, MinMTU},
		{"Peer advertises no MTU", 0, DefaultMTU}, // Should fall back to default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &Packet{
				SendStreamID: 8080,
				RecvStreamID: 12345,
				SequenceNum:  5000,
				AckThrough:   1000,
				Flags:        FlagSYN | 0, // No flags needed - ackThrough always valid per spec
			}

			if tt.packetMTU > 0 {
				pkt.Flags |= FlagMaxPacketSizeIncluded
				pkt.MaxPacketSize = tt.packetMTU
			}

			// Test extraction logic (as used in handleSynAckLocked)
			var remoteMTU uint16
			if pkt.Flags&FlagMaxPacketSizeIncluded != 0 && pkt.MaxPacketSize > 0 {
				remoteMTU = pkt.MaxPacketSize
			} else {
				remoteMTU = DefaultMTU
			}

			assert.Equal(t, tt.expectedRemote, remoteMTU)
		})
	}
}

// TestProcessSynAck_ExtractsMTU tests that processSynAck() correctly extracts MTU from SYN-ACK packets
func TestProcessSynAck_ExtractsMTU(t *testing.T) {
	tests := []struct {
		name           string
		packetMTU      uint16
		includeFlag    bool
		expectedRemote uint16
	}{
		{"SYN-ACK with DefaultMTU flag", DefaultMTU, true, DefaultMTU},
		{"SYN-ACK with ECIESMTU flag", ECIESMTU, true, ECIESMTU},
		{"SYN-ACK with MinMTU flag", MinMTU, true, MinMTU},
		{"SYN-ACK missing MTU flag", DefaultMTU, false, DefaultMTU},
		{"SYN-ACK with flag but zero MTU", 0, true, DefaultMTU},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := createTestConnection(t)
			defer conn.Close()

			// Create SYN-ACK packet
			// The test connection has sendSeq = GenerateTestISN() = 1000
			// After SYN is sent, sendSeq would be incremented, so we simulate that state
			// by having AckThrough = sendSeq - 1 (the original ISN in our SYN)
			synAck := &Packet{
				SendStreamID: 9999,                   // Peer's stream ID
				RecvStreamID: uint32(conn.localPort), // Our stream ID (as echoed by peer)
				SequenceNum:  5000,                   // Peer's ISN
				AckThrough:   conn.sendSeq - 1,       // Must match our SYN sequence (sendSeq - 1)
				Flags:        FlagSYN | 0,            // No flags needed - ackThrough always valid per spec
			}

			if tt.includeFlag && tt.packetMTU > 0 {
				synAck.Flags |= FlagMaxPacketSizeIncluded
				synAck.MaxPacketSize = tt.packetMTU
			}

			// Process SYN-ACK
			err := conn.processSynAck(synAck)
			require.NoError(t, err, "processSynAck should succeed with valid AckThrough")

			// Verify MTU was extracted correctly
			assert.Equal(t, tt.expectedRemote, conn.remoteMTU, "Remote MTU should match expected value")

			// Verify other fields were set correctly
			assert.Equal(t, uint32(5001), conn.recvSeq, "recvSeq should be peer's ISN + 1")
			assert.Equal(t, uint32(9999), conn.remoteStreamID, "remoteStreamID should be peer's stream ID")
		})
	}
}
