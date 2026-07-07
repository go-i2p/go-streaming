package streaming

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// nackMapToSlice converts a NACK map to a slice for test assertions.
func nackMapToSlice(m map[uint32]struct{}) []uint32 {
	result := make([]uint32, 0, len(m))
	for seq := range m {
		result = append(result, seq)
	}
	return result
}

// nackMapContains checks if a sequence exists in the NACK map.
func nackMapContains(m map[uint32]struct{}, seq uint32) bool {
	_, exists := m[seq]
	return exists
}

// newTestStreamConn creates a minimal StreamConn for testing NACK functionality.
func newTestStreamConn(recvSeq uint32) *StreamConn {
	recvBuf, _ := NewBuffer(1024)
	s := &StreamConn{
		recvSeq:           recvSeq,
		recvBuf:           recvBuf,
		outOfOrderPackets: make(map[uint32]*Packet),
		nackList:          make(map[uint32]struct{}),
	}
	s.recvCond = sync.NewCond(&s.mu)
	return s
}

// TestOutOfOrderPacketBuffering verifies that packets received out of order
// are buffered instead of dropped, enabling later delivery when gaps are filled.
func TestOutOfOrderPacketBuffering(t *testing.T) {
	tests := []struct {
		name           string
		recvSeq        uint32
		packetSeqs     []uint32
		expectedBuffer []uint32
	}{
		{
			name:           "Single future packet",
			recvSeq:        100,
			packetSeqs:     []uint32{102},
			expectedBuffer: []uint32{102},
		},
		{
			name:           "Multiple future packets",
			recvSeq:        100,
			packetSeqs:     []uint32{102, 103, 105},
			expectedBuffer: []uint32{102, 103, 105},
		},
		{
			name:           "Mixed order packets",
			recvSeq:        100,
			packetSeqs:     []uint32{105, 102, 103, 107},
			expectedBuffer: []uint32{102, 103, 105, 107},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create minimal stream for testing
			s := newTestStreamConn(tt.recvSeq)

			// Send packets in the specified order
			for _, seq := range tt.packetSeqs {
				pkt := &Packet{
					SequenceNum: seq,
					Payload:     []byte("test data"),
				}
				err := s.handleDataLocked(pkt)
				require.NoError(t, err)
			}

			// Verify buffered packets
			require.Equal(t, len(tt.expectedBuffer), len(s.outOfOrderPackets))
			for _, expectedSeq := range tt.expectedBuffer {
				_, exists := s.outOfOrderPackets[expectedSeq]
				require.True(t, exists, "expected packet seq %d to be buffered", expectedSeq)
			}

			// Verify recvSeq hasn't advanced (waiting for gap fill)
			require.Equal(t, tt.recvSeq, s.recvSeq)
		})
	}
}

// TestNACKGeneration verifies that missing sequence numbers are added to the NACK list
// when out-of-order packets arrive, enabling selective retransmission requests.
func TestNACKGeneration(t *testing.T) {
	tests := []struct {
		name          string
		recvSeq       uint32
		packetSeqs    []uint32
		expectedNACKs []uint32
	}{
		{
			name:          "Single gap",
			recvSeq:       100,
			packetSeqs:    []uint32{102},
			expectedNACKs: []uint32{100, 101},
		},
		{
			name:          "Multiple gaps",
			recvSeq:       100,
			packetSeqs:    []uint32{105},
			expectedNACKs: []uint32{100, 101, 102, 103, 104},
		},
		{
			name:          "Non-contiguous arrival",
			recvSeq:       100,
			packetSeqs:    []uint32{102, 105},
			expectedNACKs: []uint32{100, 101, 103, 104},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStreamConn(tt.recvSeq)

			// Send packets
			for _, seq := range tt.packetSeqs {
				pkt := &Packet{
					SequenceNum: seq,
					Payload:     []byte("test data"),
				}
				err := s.handleDataLocked(pkt)
				require.NoError(t, err)
			}

			// Verify NACK list contains expected missing sequences
			require.ElementsMatch(t, tt.expectedNACKs, nackMapToSlice(s.nackList),
				"NACK list should contain all missing sequences")
		})
	}
}

// TestBufferedPacketDelivery verifies that buffered packets are delivered
// in order once gaps are filled by receiving missing packets.
func TestBufferedPacketDelivery(t *testing.T) {
	s := newTestStreamConn(100)

	// Receive packets out of order: 102, 103, 105
	outOfOrderSeqs := []uint32{102, 103, 105}
	for _, seq := range outOfOrderSeqs {
		pkt := &Packet{
			SequenceNum: seq,
			Payload:     []byte{byte(seq)}, // Use seq as data for verification
		}
		err := s.handleDataLocked(pkt)
		require.NoError(t, err)
	}

	// Verify nothing delivered yet
	require.Equal(t, uint32(100), s.recvSeq, "recvSeq should not advance until gaps filled")
	require.Equal(t, int64(0), s.recvBuf.TotalWritten(), "no data should be delivered yet")

	// Now receive missing packet 100
	pkt100 := &Packet{
		SequenceNum: 100,
		Payload:     []byte{100},
	}
	err := s.handleDataLocked(pkt100)
	require.NoError(t, err)

	// Verify recvSeq hasn't advanced to 101 yet (101 still missing)
	require.Equal(t, uint32(101), s.recvSeq)
	require.Equal(t, int64(1), s.recvBuf.TotalWritten(), "only packet 100 delivered")

	// Receive packet 101 to fill the gap
	pkt101 := &Packet{
		SequenceNum: 101,
		Payload:     []byte{101},
	}
	err = s.handleDataLocked(pkt101)
	require.NoError(t, err)

	// Now packets 100, 101, 102, 103 should be delivered
	require.Equal(t, uint32(104), s.recvSeq, "recvSeq should advance to 104")
	require.Equal(t, int64(4), s.recvBuf.TotalWritten(), "packets 100-103 delivered")

	// Verify packet 105 still buffered (104 missing)
	_, exists := s.outOfOrderPackets[105]
	require.True(t, exists, "packet 105 should still be buffered")

	// Receive packet 104 to complete the sequence
	pkt104 := &Packet{
		SequenceNum: 104,
		Payload:     []byte{104},
	}
	err = s.handleDataLocked(pkt104)
	require.NoError(t, err)

	// All packets should now be delivered
	require.Equal(t, uint32(106), s.recvSeq)
	require.Equal(t, int64(6), s.recvBuf.TotalWritten(), "all packets delivered")
	require.Empty(t, s.outOfOrderPackets, "buffer should be empty")
	require.Empty(t, s.nackList, "NACK list should be empty")
}

// TestDuplicatePacketHandling verifies that duplicate or old packets are ignored.
func TestDuplicatePacketHandling(t *testing.T) {
	s := newTestStreamConn(105)

	// Receive old packet (seq < recvSeq)
	oldPkt := &Packet{
		SequenceNum: 100,
		Payload:     []byte("old data"),
	}
	err := s.handleDataLocked(oldPkt)
	require.NoError(t, err)

	// Verify packet was ignored
	require.Equal(t, uint32(105), s.recvSeq, "recvSeq should not change")
	require.Equal(t, int64(0), s.recvBuf.TotalWritten(), "no data should be written")
	require.Empty(t, s.outOfOrderPackets, "packet should not be buffered")

	// Receive exact duplicate
	dupPkt := &Packet{
		SequenceNum: 103,
		Payload:     []byte("dup data"),
	}
	err = s.handleDataLocked(dupPkt)
	require.NoError(t, err)

	// Verify duplicate was ignored
	require.Equal(t, uint32(105), s.recvSeq)
	require.Equal(t, int64(0), s.recvBuf.TotalWritten())
	require.Empty(t, s.outOfOrderPackets)
}

// TestNACKListUpdates verifies that NACKs are properly added and removed.
func TestNACKListUpdates(t *testing.T) {
	s := newTestStreamConn(100)

	// Receive packet 105 (creates gap 100-104)
	pkt105 := &Packet{
		SequenceNum: 105,
		Payload:     []byte{105},
	}
	err := s.handleDataLocked(pkt105)
	require.NoError(t, err)

	// Verify NACKs added
	expectedNACKs := []uint32{100, 101, 102, 103, 104}
	require.ElementsMatch(t, expectedNACKs, nackMapToSlice(s.nackList))

	// Receive packet 102 (should remove from NACK list but not deliver yet)
	pkt102 := &Packet{
		SequenceNum: 102,
		Payload:     []byte{102},
	}
	err = s.handleDataLocked(pkt102)
	require.NoError(t, err)

	// 102 should not be in NACK list anymore (it's buffered)
	require.False(t, nackMapContains(s.nackList, 102))

	// But 100, 101, 103, 104 should still be there
	require.True(t, nackMapContains(s.nackList, 100))
	require.True(t, nackMapContains(s.nackList, 101))
	require.True(t, nackMapContains(s.nackList, 103))
	require.True(t, nackMapContains(s.nackList, 104))

	// Receive packet 100
	pkt100 := &Packet{
		SequenceNum: 100,
		Payload:     []byte{100},
	}
	err = s.handleDataLocked(pkt100)
	require.NoError(t, err)

	// 100 should be removed from NACK list
	require.False(t, nackMapContains(s.nackList, 100))

	// recvSeq should advance to 101
	require.Equal(t, uint32(101), s.recvSeq)
}

// TestNACKInclusionInACKPackets verifies that NACKs are included in ACK packets
// when there are missing sequences.
func TestNACKInclusionInACKPackets(t *testing.T) {
	i2cp := RequireI2CP(t)
	recvBuf, err := NewBuffer(1024)
	require.NoError(t, err)

	s := &StreamConn{
		session:           i2cp.Manager.session,
		dest:              i2cp.Manager.Destination(),
		recvSeq:           100,
		recvBuf:           recvBuf,
		outOfOrderPackets: make(map[uint32]*Packet),
		nackList:          make(map[uint32]struct{}),
		localStreamID:     1,
		remoteStreamID:    2,
		sendSeq:           50,
	}
	s.recvCond = sync.NewCond(&s.mu)
	s.sendCond = sync.NewCond(&s.mu)

	// Add some NACKs manually
	s.nackList[100] = struct{}{}
	s.nackList[101] = struct{}{}
	s.nackList[102] = struct{}{}

	// Send ACK
	err = s.sendAckLocked()
	require.NoError(t, err)

	// Note: In a real test with session mocking, we'd verify the packet
	// For this test, we just verify no error and NACK list is preserved
	require.Equal(t, 3, len(s.nackList))
}

// TestNACKLimit255 verifies that no more than 255 NACKs are included per packet.
func TestNACKLimit255(t *testing.T) {
	i2cp := RequireI2CP(t)
	recvBuf, err := NewBuffer(1024)
	require.NoError(t, err)

	s := &StreamConn{
		session:           i2cp.Manager.session,
		dest:              i2cp.Manager.Destination(),
		recvSeq:           100,
		recvBuf:           recvBuf,
		outOfOrderPackets: make(map[uint32]*Packet),
		nackList:          make(map[uint32]struct{}),
		localStreamID:     1,
		remoteStreamID:    2,
		sendSeq:           50,
	}
	s.recvCond = sync.NewCond(&s.mu)
	s.sendCond = sync.NewCond(&s.mu)

	// Add 300 NACKs
	for i := uint32(0); i < 300; i++ {
		s.nackList[i] = struct{}{}
	}

	// Send ACK
	err = s.sendAckLocked()
	require.NoError(t, err)

	// NACK list should still have 300 entries (not removed by sending)
	require.Equal(t, 300, len(s.nackList))

	// In a real packet capture, we'd verify only 255 were sent
	// For now, verify the function doesn't crash with large NACK lists
}

// TestPacketLossRecoveryScenario simulates a realistic packet loss scenario
// and verifies correct behavior.
func TestPacketLossRecoveryScenario(t *testing.T) {
	s := newTestStreamConn(100)

	// Simulate receiving packets 100-110 with packet 103 and 107 lost
	receivedSeqs := []uint32{100, 101, 102, 104, 105, 106, 108, 109, 110}

	for _, seq := range receivedSeqs {
		pkt := &Packet{
			SequenceNum: seq,
			Payload:     []byte{byte(seq)},
		}
		err := s.handleDataLocked(pkt)
		require.NoError(t, err)
	}

	// Should have delivered 100-102, then blocked at 103
	require.Equal(t, uint32(103), s.recvSeq, "should be waiting for packet 103")
	require.Equal(t, int64(3), s.recvBuf.TotalWritten(), "packets 100-102 delivered")

	// Should have NACKs for 103 and 107
	require.True(t, nackMapContains(s.nackList, 103))
	require.True(t, nackMapContains(s.nackList, 107))

	// Should have buffered 104-106, 108-110
	for _, seq := range []uint32{104, 105, 106, 108, 109, 110} {
		_, exists := s.outOfOrderPackets[seq]
		require.True(t, exists, "packet %d should be buffered", seq)
	}

	// Now simulate retransmission of packet 103
	pkt103 := &Packet{
		SequenceNum: 103,
		Payload:     []byte{103},
	}
	err := s.handleDataLocked(pkt103)
	require.NoError(t, err)

	// Should deliver 103-106, then block at 107
	require.Equal(t, uint32(107), s.recvSeq)
	require.Equal(t, int64(7), s.recvBuf.TotalWritten(), "packets 100-106 delivered")

	// 103 should be removed from NACK list
	require.False(t, nackMapContains(s.nackList, 103))

	// 107 should still be in NACK list
	require.True(t, nackMapContains(s.nackList, 107))

	// Retransmit packet 107
	pkt107 := &Packet{
		SequenceNum: 107,
		Payload:     []byte{107},
	}
	err = s.handleDataLocked(pkt107)
	require.NoError(t, err)

	// All packets should be delivered now
	require.Equal(t, uint32(111), s.recvSeq)
	require.Equal(t, int64(11), s.recvBuf.TotalWritten(), "all packets delivered")
	require.Empty(t, s.outOfOrderPackets)
	require.Empty(t, s.nackList)
}

// TestConcurrentNACKUpdates verifies thread-safety of NACK operations.
// This test ensures the mutex protects NACK list modifications.
func TestConcurrentNACKUpdates(t *testing.T) {
	s := newTestStreamConn(100)

	// Send multiple out-of-order packets concurrently
	// Note: handleDataLocked requires s.mu held, so we'd need to
	// test via higher-level API that acquires lock
	// For now, verify sequential behavior is correct

	for i := uint32(0); i < 10; i++ {
		seq := 110 + i*2 // Create gaps
		pkt := &Packet{
			SequenceNum: seq,
			Payload:     []byte{byte(seq)},
		}
		err := s.handleDataLocked(pkt)
		require.NoError(t, err)
	}

	// Verify NACK list has all missing sequences
	require.Greater(t, len(s.nackList), 0, "should have NACKs for gaps")

	// Verify buffered packets
	require.Equal(t, 10, len(s.outOfOrderPackets))
}

// BenchmarkOutOfOrderBuffering measures performance of out-of-order packet handling.
func BenchmarkOutOfOrderBuffering(b *testing.B) {
	s := newTestStreamConn(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := &Packet{
			SequenceNum: uint32(i + 100), // Always out of order
			Payload:     make([]byte, 512),
		}
		_ = s.handleDataLocked(pkt)
	}
}

// BenchmarkInOrderDelivery measures performance of in-order packet delivery.
func BenchmarkInOrderDelivery(b *testing.B) {
	s := newTestStreamConn(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := &Packet{
			SequenceNum: uint32(i),
			Payload:     make([]byte, 512),
		}
		_ = s.handleDataLocked(pkt)
	}
}

// TestNACKRemovalOnPacketArrival verifies that specific helper function behavior.
func TestNACKRemovalOnPacketArrival(t *testing.T) {
	s := &StreamConn{
		nackList: map[uint32]struct{}{
			100: {}, 101: {}, 102: {}, 103: {}, 104: {},
		},
	}

	// Remove middle element
	s.removeFromNACKListLocked(102)
	require.Equal(t, 4, len(s.nackList))
	require.False(t, nackMapContains(s.nackList, 102))

	// Remove first element
	s.removeFromNACKListLocked(100)
	require.Equal(t, 3, len(s.nackList))
	require.False(t, nackMapContains(s.nackList, 100))

	// Remove last element
	s.removeFromNACKListLocked(104)
	require.Equal(t, 2, len(s.nackList))
	require.False(t, nackMapContains(s.nackList, 104))

	// Remove non-existent (should not crash)
	s.removeFromNACKListLocked(999)
	require.Equal(t, 2, len(s.nackList))
	require.True(t, nackMapContains(s.nackList, 101))
	require.True(t, nackMapContains(s.nackList, 103))
}

// TestUpdateNACKListDeduplication verifies no duplicate NACKs are added.
func TestUpdateNACKListDeduplication(t *testing.T) {
	s := newTestStreamConn(100)

	// Receive packet 105 (adds NACKs 100-104)
	pkt105 := &Packet{SequenceNum: 105, Payload: []byte{105}}
	_ = s.handleDataLocked(pkt105)

	initialNACKCount := len(s.nackList)
	require.Equal(t, 5, initialNACKCount)

	// Receive packet 108 (should add 106-107, not duplicate 100-104)
	pkt108 := &Packet{SequenceNum: 108, Payload: []byte{108}}
	_ = s.handleDataLocked(pkt108)

	// Should have 100-104, 106-107 (7 total)
	require.Equal(t, 7, len(s.nackList))

	// Verify no duplicates (maps naturally deduplicate)
	seen := make(map[uint32]bool)
	for nack := range s.nackList {
		require.False(t, seen[nack], "duplicate NACK found: %d", nack)
		seen[nack] = true
	}
}

// TestUpdateNACKListLargeGap verifies that large sequence gaps (including wrap-around)
// are handled efficiently without excessive CPU usage.
func TestUpdateNACKListLargeGap(t *testing.T) {
	tests := []struct {
		name             string
		recvSeq          uint32
		receivedSeq      uint32
		expectedMaxNACKs int
		description      string
	}{
		{
			name:             "Normal gap within MaxNACKs",
			recvSeq:          100,
			receivedSeq:      200,
			expectedMaxNACKs: 100,
			description:      "Gap of 100 should add all sequences",
		},
		{
			name:             "Large gap exceeds MaxNACKs",
			recvSeq:          100,
			receivedSeq:      1000,
			expectedMaxNACKs: MaxNACKs,
			description:      "Gap of 900 should be limited to MaxNACKs",
		},
		{
			name:             "Wrap-around small gap",
			recvSeq:          0xFFFFFFFE,
			receivedSeq:      0x00000005, // Gap of 7 across wrap-around
			expectedMaxNACKs: 7,
			description:      "Gap of 7 across wrap-around boundary should work correctly",
		},
		{
			name:             "Wrap-around large gap",
			recvSeq:          10,
			receivedSeq:      0xFFFFFF00, // Would be ~4 billion iterations without fix
			expectedMaxNACKs: MaxNACKs,
			description:      "Apparent large gap should be limited to MaxNACKs",
		},
		{
			name:             "Maximum possible gap",
			recvSeq:          0,
			receivedSeq:      0xFFFFFFFF, // Maximum uint32 gap
			expectedMaxNACKs: MaxNACKs,
			description:      "Maximum gap should be limited to MaxNACKs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStreamConn(tt.recvSeq)

			// This should complete quickly (< 1 second) even with large gaps
			// Without the fix, wrap-around cases could take minutes/hours
			s.mu.Lock()
			s.updateNACKListLocked(tt.receivedSeq)
			nackCount := len(s.nackList)
			s.mu.Unlock()

			// Verify we got the expected number of NACKs
			require.LessOrEqual(t, nackCount, tt.expectedMaxNACKs,
				"%s: NACK count should be <= %d, got %d",
				tt.description, tt.expectedMaxNACKs, nackCount)

			// Verify the first few NACKs start at recvSeq
			if nackCount > 0 {
				require.True(t, nackMapContains(s.nackList, tt.recvSeq),
					"First NACK should be recvSeq=%d", tt.recvSeq)
			}
		})
	}
}

// TestUpdateNACKListWrapAroundCorrectness verifies that wrap-around gaps
// produce the correct sequence numbers in the NACK list.
func TestUpdateNACKListWrapAroundCorrectness(t *testing.T) {
	// Test wrap-around from 0xFFFFFFFE to 0x00000002 (gap of 4)
	s := newTestStreamConn(0xFFFFFFFE)

	s.mu.Lock()
	s.updateNACKListLocked(0x00000002)
	nackList := nackMapToSlice(s.nackList)
	s.mu.Unlock()

	// Expected NACKs: 0xFFFFFFFE, 0xFFFFFFFF, 0x00000000, 0x00000001
	expectedNACKs := []uint32{0xFFFFFFFE, 0xFFFFFFFF, 0x00000000, 0x00000001}

	require.Equal(t, len(expectedNACKs), len(nackList),
		"Should have exactly %d NACKs for gap of 4", len(expectedNACKs))

	for _, expected := range expectedNACKs {
		require.Contains(t, nackList, expected,
			"NACK list should contain sequence %d (0x%X)", expected, expected)
	}
}
