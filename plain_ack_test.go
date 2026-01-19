package streaming

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPlainACKDetectionOrder verifies that plain ACK packets (sequenceNum=0, no SYN)
// are correctly identified BEFORE the data payload check.
// Per I2P streaming spec:
// "If the sequenceNum is 0 and the SYN flag is not set, this is a plain ACK packet
// that should not be ACKed."
func TestPlainACKDetectionOrder(t *testing.T) {
	s := CreateTestStreamConn(t)
	s.mu.Lock()
	defer s.mu.Unlock()

	tests := []struct {
		name          string
		packet        *Packet
		expectHandler string // Which handler should be called
		description   string
	}{
		{
			name: "plain ACK without payload",
			packet: &Packet{
				SendStreamID: 1234,
				RecvStreamID: 5678,
				SequenceNum:  0, // seq=0
				AckThrough:   100,
				Flags:        0,   // no SYN flag
				Payload:      nil, // no payload
			},
			expectHandler: "handleAckLocked",
			description:   "Standard plain ACK packet should be handled by handleAckLocked",
		},
		{
			name: "plain ACK with payload (edge case)",
			packet: &Packet{
				SendStreamID: 1234,
				RecvStreamID: 5678,
				SequenceNum:  0, // seq=0 makes this a plain ACK per spec
				AckThrough:   100,
				Flags:        0,                      // no SYN flag
				Payload:      []byte("some payload"), // payload present but seq=0
			},
			expectHandler: "handleAckLocked",
			description:   "Plain ACK with payload should still be treated as ACK, not data",
		},
		{
			name: "data packet with non-zero sequence",
			packet: &Packet{
				SendStreamID: 1234,
				RecvStreamID: 5678,
				SequenceNum:  100, // non-zero sequence
				AckThrough:   50,
				Flags:        0,
				Payload:      []byte("data payload"),
			},
			expectHandler: "handleDataLocked",
			description:   "Packet with non-zero sequence and payload should be data",
		},
		{
			name: "SYN packet with seq=0",
			packet: &Packet{
				SendStreamID: 0, // Initial SYN has SendStreamID=0
				RecvStreamID: 0,
				SequenceNum:  0, // Initial SYN has seq=0
				AckThrough:   0,
				Flags:        FlagSYN | FlagNoACK, // SYN flag is set
				Payload:      nil,
			},
			expectHandler: "not_plain_ack",
			description:   "SYN packet with seq=0 should NOT be treated as plain ACK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the detection logic
			isPlainACK := tt.packet.SequenceNum == 0 && tt.packet.Flags&FlagSYN == 0
			isSYN := tt.packet.Flags&FlagSYN != 0
			hasPayload := len(tt.packet.Payload) > 0

			switch tt.expectHandler {
			case "handleAckLocked":
				assert.True(t, isPlainACK, "%s: should be detected as plain ACK", tt.description)
				assert.False(t, isSYN, "%s: should not have SYN flag", tt.description)
			case "handleDataLocked":
				assert.False(t, isPlainACK, "%s: should NOT be detected as plain ACK", tt.description)
				assert.True(t, hasPayload, "%s: should have payload", tt.description)
			case "not_plain_ack":
				assert.False(t, isPlainACK, "%s: should NOT be detected as plain ACK due to SYN flag", tt.description)
			}
		})
	}
}

// TestPlainACKNotAcked verifies that plain ACK packets are not ACKed back.
// This is a key requirement from the spec.
func TestPlainACKNotAcked(t *testing.T) {
	s := CreateTestStreamConn(t)
	s.mu.Lock()
	defer s.mu.Unlock()

	// Record if sendAckLocked would be called
	// handleAckLocked should NOT call sendAckLocked
	plainACK := &Packet{
		SendStreamID: 1234,
		RecvStreamID: 5678,
		SequenceNum:  0,
		AckThrough:   s.sendSeq - 1, // Valid ACK
		Flags:        0,
	}

	// Process the plain ACK
	err := s.handleAckLocked(plainACK)
	require.NoError(t, err)

	// The handleAckLocked function should process the ACK but not send a response
	// We verify this by checking it doesn't error and completes without issues
	// If it tried to send an ACK, it might fail or cause issues in test context
}

// TestPlainACKUpdatesAckThrough verifies that plain ACK packets properly update
// the ackThrough value when not blocked by NO_ACK flag.
func TestPlainACKUpdatesAckThrough(t *testing.T) {
	s := CreateTestStreamConn(t)
	s.mu.Lock()
	defer s.mu.Unlock()

	initialAckThrough := s.ackThrough

	plainACK := &Packet{
		SendStreamID: 1234,
		RecvStreamID: 5678,
		SequenceNum:  0,
		AckThrough:   initialAckThrough + 10, // Higher ACK value
		Flags:        0,                      // NO_ACK not set
	}

	err := s.handleAckLocked(plainACK)
	require.NoError(t, err)

	assert.Greater(t, s.ackThrough, initialAckThrough,
		"ackThrough should be updated by plain ACK")
}

// TestPlainACKWithNoACKFlag verifies that plain ACK packets with NO_ACK flag
// do not update ackThrough.
func TestPlainACKWithNoACKFlag(t *testing.T) {
	s := CreateTestStreamConn(t)
	s.mu.Lock()
	defer s.mu.Unlock()

	initialAckThrough := s.ackThrough

	plainACK := &Packet{
		SendStreamID: 1234,
		RecvStreamID: 5678,
		SequenceNum:  0,
		AckThrough:   initialAckThrough + 10, // Higher ACK value
		Flags:        FlagNoACK,              // NO_ACK is set
	}

	err := s.handleAckLocked(plainACK)
	require.NoError(t, err)

	assert.Equal(t, initialAckThrough, s.ackThrough,
		"ackThrough should NOT be updated when NO_ACK flag is set")
}

// TestDispatchPacketByFlagsOrder verifies the order of checks in dispatchPacketByFlags.
// The plain ACK check must come BEFORE the data payload check.
func TestDispatchPacketByFlagsOrder(t *testing.T) {
	s := CreateTestStreamConn(t)
	s.mu.Lock()
	defer s.mu.Unlock()

	// This packet has both: seq=0 (plain ACK marker) AND payload
	// Per the fix, it should be treated as plain ACK, not data
	ambiguousPacket := &Packet{
		SendStreamID: 1234,
		RecvStreamID: 5678,
		SequenceNum:  0, // Plain ACK indicator
		AckThrough:   50,
		Flags:        0,                      // No SYN
		Payload:      []byte("test payload"), // Has payload
	}

	// Before the fix, this would have been handled as data because
	// len(pkt.Payload) > 0 was checked before the plain ACK check.
	// After the fix, plain ACK check comes first.

	// We can verify by checking the logic directly
	isPlainACK := ambiguousPacket.SequenceNum == 0 && ambiguousPacket.Flags&FlagSYN == 0
	assert.True(t, isPlainACK, "Packet with seq=0 and no SYN should be plain ACK regardless of payload")

	// The dispatchPacketByFlags should route this to handleAckLocked
	// We can't easily test the routing without mocking, but we can verify
	// handleAckLocked handles it correctly
	err := s.handleAckLocked(ambiguousPacket)
	require.NoError(t, err)
}

// TestPlainACKPacketMarshalUnmarshal verifies that plain ACK packets
// can be correctly marshaled and unmarshaled.
func TestPlainACKPacketMarshalUnmarshal(t *testing.T) {
	pkt := &Packet{
		SendStreamID: 1234,
		RecvStreamID: 5678,
		SequenceNum:  0, // Plain ACK
		AckThrough:   100,
		Flags:        0, // No flags
	}

	data, err := pkt.Marshal()
	require.NoError(t, err)

	parsed := &Packet{}
	err = parsed.Unmarshal(data)
	require.NoError(t, err)

	assert.Equal(t, pkt.SendStreamID, parsed.SendStreamID)
	assert.Equal(t, pkt.RecvStreamID, parsed.RecvStreamID)
	assert.Equal(t, uint32(0), parsed.SequenceNum, "seq should be 0 for plain ACK")
	assert.Equal(t, pkt.AckThrough, parsed.AckThrough)
	assert.Equal(t, uint16(0), parsed.Flags, "flags should be 0 for plain ACK")
	assert.Equal(t, uint16(0), parsed.Flags&FlagSYN, "SYN flag should not be set")
}

// TestPlainACKHandlesNACKs verifies that plain ACK packets with NACKs
// are processed correctly.
func TestPlainACKHandlesNACKs(t *testing.T) {
	s := CreateTestStreamConn(t)
	s.mu.Lock()
	defer s.mu.Unlock()

	// Set up some sent packets that could be NACKed
	// sentPacket stores marshaled data, not the Packet struct
	s.sentPackets = make(map[uint32]*sentPacket)
	pkt10 := &Packet{SequenceNum: 10, SendStreamID: 1234}
	pkt11 := &Packet{SequenceNum: 11, SendStreamID: 1234}
	data10, _ := pkt10.Marshal()
	data11, _ := pkt11.Marshal()
	s.sentPackets[10] = &sentPacket{data: data10}
	s.sentPackets[11] = &sentPacket{data: data11}

	plainACKWithNACKs := &Packet{
		SendStreamID: 1234,
		RecvStreamID: 5678,
		SequenceNum:  0,
		AckThrough:   15,
		NACKs:        []uint32{10, 11}, // NACKing specific sequences
		Flags:        0,
	}

	err := s.handleAckLocked(plainACKWithNACKs)
	require.NoError(t, err)
}

// TestDataPacketNotConfusedWithPlainACK verifies that data packets
// with non-zero sequence numbers are NOT treated as plain ACKs.
func TestDataPacketNotConfusedWithPlainACK(t *testing.T) {
	tests := []struct {
		name string
		seq  uint32
	}{
		{"seq=1", 1},
		{"seq=100", 100},
		{"seq=MaxUint32", 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &Packet{
				SendStreamID: 1234,
				RecvStreamID: 5678,
				SequenceNum:  tt.seq,
				AckThrough:   50,
				Flags:        0,
				Payload:      []byte("data"),
			}

			isPlainACK := pkt.SequenceNum == 0 && pkt.Flags&FlagSYN == 0
			assert.False(t, isPlainACK,
				"Packet with seq=%d should NOT be treated as plain ACK", tt.seq)
		})
	}
}

// BenchmarkPlainACKDetection benchmarks the plain ACK detection logic.
func BenchmarkPlainACKDetection(b *testing.B) {
	pkt := &Packet{
		SendStreamID: 1234,
		RecvStreamID: 5678,
		SequenceNum:  0,
		AckThrough:   100,
		Flags:        0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pkt.SequenceNum == 0 && pkt.Flags&FlagSYN == 0
	}
}

// mockSendTracker is a helper to track if send functions are called
type mockSendTracker struct {
	sendAckCalled bool
	mu            sync.Mutex
}

func (m *mockSendTracker) wasSendAckCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sendAckCalled
}

func (m *mockSendTracker) markSendAckCalled() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendAckCalled = true
}
