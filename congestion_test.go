package streaming

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCongestionDetectionOnNACK verifies that receiving NACKs triggers congestion response
// when the fast retransmit threshold (2 NACKs) is met.
func TestCongestionDetectionOnNACK(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       16, // Start at 16 packets
		ssthresh:   128,
		windowSize: 16,
	}
	s.sentPackets = make(map[uint32]*sentPacket)
	// Pre-populate nackCounts so the incoming NACKs reach threshold of 2
	s.nackCounts = map[uint32]int{3: 1, 4: 1}

	// Create ACK packet with NACKs indicating packet loss
	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   5,
		NACKs:        []uint32{3, 4}, // Lost packets (second NACK for each)
		Flags:        0,              // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)

	cwnd := s.cwnd
	ssthresh := s.ssthresh
	windowSize := s.windowSize
	s.mu.Unlock()

	require.NoError(t, err)

	// Verify congestion response
	// Processing order: ACK first (slow start doubles 16 -> 32), then NACKs (halve 32 -> 16)
	// Final: ssthresh = max(32/2, 2) = 16, cwnd = 16
	require.Equal(t, uint32(16), ssthresh, "ssthresh should be half of cwnd after slow start")
	require.Equal(t, uint32(16), cwnd, "cwnd should equal new ssthresh")
	require.Equal(t, uint32(16), windowSize, "windowSize should equal new cwnd")
}

// TestCongestionDetectionMultipleNACKs verifies handling of multiple lost packets
// when fast retransmit threshold is met.
func TestCongestionDetectionMultipleNACKs(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       64, // Start at 64 packets
		ssthresh:   128,
		windowSize: 64,
	}
	s.sentPackets = make(map[uint32]*sentPacket)
	// Pre-populate nackCounts so the incoming NACKs reach threshold of 2
	s.nackCounts = map[uint32]int{5: 1, 6: 1, 7: 1, 8: 1, 9: 1}

	// Multiple NACKs indicating significant packet loss
	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   10,
		NACKs:        []uint32{5, 6, 7, 8, 9}, // 5 lost packets (second NACK for each)
		Flags:        0,                       // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)

	cwnd := s.cwnd
	ssthresh := s.ssthresh
	s.mu.Unlock()

	require.NoError(t, err)

	// ACK first (slow start 64 -> 128), then NACKs (halve 128 -> 64)
	// Verify: ssthresh = max(128/2, 2) = 64, cwnd = 64
	require.Equal(t, uint32(64), ssthresh, "ssthresh should be half of cwnd after slow start")
	require.Equal(t, uint32(64), cwnd, "cwnd should equal new ssthresh")
}

// TestCongestionDetectionMinimumWindow verifies minimum window size of 2 packets
// when fast retransmit threshold is met.
func TestCongestionDetectionMinimumWindow(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       2, // Start at minimum
		ssthresh:   128,
		windowSize: 2,
	}
	s.sentPackets = make(map[uint32]*sentPacket)
	// Pre-populate nackCounts so the incoming NACK reaches threshold of 2
	s.nackCounts = map[uint32]int{3: 1}

	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   5,
		NACKs:        []uint32{3}, // Single lost packet (second NACK)
		Flags:        0,           // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)

	cwnd := s.cwnd
	ssthresh := s.ssthresh
	s.mu.Unlock()

	require.NoError(t, err)

	// Verify minimum: ssthresh = max(2/2, 2) = max(1, 2) = 2
	require.Equal(t, uint32(2), ssthresh, "ssthresh should not go below 2")
	require.Equal(t, uint32(2), cwnd, "cwnd should not go below 2")
}

// TestCongestionDetectionWithSlowStart verifies interaction with slow start
// when fast retransmit threshold is met.
func TestCongestionDetectionWithSlowStart(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       4, // In slow start phase
		ssthresh:   128,
		windowSize: 4,
	}
	s.sentPackets = make(map[uint32]*sentPacket)
	s.nackCounts = make(map[uint32]int)

	// Track packets for ACK processing
	for i := uint32(1); i <= 10; i++ {
		s.sentPackets[i] = &sentPacket{}
	}

	// First ACK: slow start continues (no NACKs)
	pkt1 := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   5,
		Flags:        0, // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt1)
	cwndAfterAck := s.cwnd
	s.mu.Unlock()

	require.NoError(t, err)
	require.Equal(t, uint32(8), cwndAfterAck, "slow start should double cwnd")

	// Pre-populate nackCounts so the incoming NACKs reach threshold of 2
	s.mu.Lock()
	s.nackCounts[6] = 1
	s.nackCounts[7] = 1
	s.mu.Unlock()

	// Second ACK: congestion detected (NACKs present, threshold reached)
	pkt2 := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  101,
		AckThrough:   8,
		NACKs:        []uint32{6, 7}, // Packet loss (second NACK for each)
		Flags:        0,              // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err = s.handleAckLocked(pkt2)

	cwnd := s.cwnd
	ssthresh := s.ssthresh
	s.mu.Unlock()

	require.NoError(t, err)

	// ACK first (slow start 8 -> 16), then NACKs (halve 16 -> 8)
	// Verify congestion response halts slow start
	// ssthresh = max(16/2, 2) = 8, cwnd = 8
	require.Equal(t, uint32(8), ssthresh, "ssthresh should be half of cwnd after slow start")
	require.Equal(t, uint32(8), cwnd, "cwnd should be reduced on congestion")
}

// TestCongestionDetectionRecovery verifies recovery after congestion
// when fast retransmit threshold is met.
func TestCongestionDetectionRecovery(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       32,
		ssthresh:   128,
		windowSize: 32,
	}
	s.sentPackets = make(map[uint32]*sentPacket)
	// Pre-populate nackCounts so the incoming NACKs reach threshold of 2
	s.nackCounts = map[uint32]int{8: 1, 9: 1}

	// Add tracked packets
	for i := uint32(1); i <= 20; i++ {
		s.sentPackets[i] = &sentPacket{}
	}

	// Step 1: Congestion detected
	pkt1 := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   10,
		NACKs:        []uint32{8, 9}, // Packet loss (second NACK for each)
		Flags:        0,              // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt1)
	cwndAfterLoss := s.cwnd
	ssthreshAfterLoss := s.ssthresh
	s.mu.Unlock()

	require.NoError(t, err)
	// ACK first (slow start 32 -> 64), then NACKs (halve 64 -> 32)
	require.Equal(t, uint32(32), ssthreshAfterLoss, "ssthresh = max(64/2, 2) = 32")
	require.Equal(t, uint32(32), cwndAfterLoss, "cwnd should equal ssthresh")

	// Step 2: Recovery - ACKs without NACKs should trigger congestion avoidance
	pkt2 := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  101,
		AckThrough:   15,
		Flags:        0, // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err = s.handleAckLocked(pkt2)
	cwndAfterRecovery := s.cwnd
	s.mu.Unlock()

	require.NoError(t, err)
	// Since cwnd (32) >= ssthresh (32), we're in congestion avoidance
	// cwnd should increment by 1: 32 + 1 = 33
	require.Equal(t, uint32(33), cwndAfterRecovery, "congestion avoidance should increment cwnd by 1")
}

// TestCongestionDetectionHighWindow verifies behavior at high window sizes
// when fast retransmit threshold is met.
func TestCongestionDetectionHighWindow(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       120, // Near maximum
		ssthresh:   128,
		windowSize: 120,
	}
	s.sentPackets = make(map[uint32]*sentPacket)
	// Pre-populate nackCounts so the incoming NACKs reach threshold of 2
	s.nackCounts = map[uint32]int{45: 1, 46: 1, 47: 1}

	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   50,
		NACKs:        []uint32{45, 46, 47}, // Packet loss at high window (second NACK for each)
		Flags:        0,                    // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)

	cwnd := s.cwnd
	ssthresh := s.ssthresh
	s.mu.Unlock()

	require.NoError(t, err)

	// ACK first (slow start 120 -> 128 capped), then NACKs (halve 128 -> 64)
	// Verify: ssthresh = max(128/2, 2) = 64, cwnd = 64
	require.Equal(t, uint32(64), ssthresh, "ssthresh should be half of cwnd after slow start")
	require.Equal(t, uint32(64), cwnd, "cwnd should be reduced significantly")
}

// TestNoCongestionDetectionWithoutNACKs verifies normal ACK processing continues
func TestNoCongestionDetectionWithoutNACKs(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       16,
		ssthresh:   64,
		windowSize: 16,
	}
	s.sentPackets = make(map[uint32]*sentPacket)
	s.nackCounts = make(map[uint32]int)

	// Add tracked packets
	for i := uint32(1); i <= 10; i++ {
		s.sentPackets[i] = &sentPacket{}
	}

	// ACK without NACKs - should trigger congestion avoidance (cwnd >= ssthresh is false)
	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   5,
		NACKs:        nil, // No packet loss
		Flags:        0,   // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	oldCwnd := s.cwnd
	oldSsthresh := s.ssthresh

	err := s.handleAckLocked(pkt)

	cwnd := s.cwnd
	ssthresh := s.ssthresh
	s.mu.Unlock()

	require.NoError(t, err)

	// Without NACKs, slow start should continue (cwnd < ssthresh)
	require.Equal(t, oldSsthresh, ssthresh, "ssthresh should not change without NACKs")
	require.Equal(t, oldCwnd*2, cwnd, "slow start should double cwnd without NACKs")
}

// TestCongestionDetectionSingleNACK verifies response to single packet loss
// when fast retransmit threshold is met.
func TestCongestionDetectionSingleNACK(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       50,
		ssthresh:   128,
		windowSize: 50,
	}
	s.sentPackets = make(map[uint32]*sentPacket)
	// Pre-populate nackCounts so the incoming NACK reaches threshold of 2
	s.nackCounts = map[uint32]int{20: 1}

	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   25,
		NACKs:        []uint32{20}, // Single lost packet (second NACK)
		Flags:        0,            // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)

	cwnd := s.cwnd
	ssthresh := s.ssthresh
	s.mu.Unlock()

	require.NoError(t, err)

	// ACK first (slow start 50 -> 100), then NACKs (halve 100 -> 50)
	// Even single NACK triggers congestion response
	require.Equal(t, uint32(50), ssthresh, "ssthresh = max(100/2, 2) = 50")
	require.Equal(t, uint32(50), cwnd, "cwnd should equal ssthresh")
}

// TestCongestionDetectionEdgeCaseThree verifies cwnd=3 edge case
// when fast retransmit threshold is met.
func TestCongestionDetectionEdgeCaseThree(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       3,
		ssthresh:   128,
		windowSize: 3,
	}
	s.sentPackets = make(map[uint32]*sentPacket)
	// Pre-populate nackCounts so the incoming NACK reaches threshold of 2
	s.nackCounts = map[uint32]int{4: 1}

	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   5,
		NACKs:        []uint32{4}, // Second NACK for sequence 4
		Flags:        0,           // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)

	cwnd := s.cwnd
	ssthresh := s.ssthresh
	s.mu.Unlock()

	require.NoError(t, err)

	// ACK first (slow start 3 -> 6), then NACKs (halve 6 -> 3)
	// ssthresh = max(6/2, 2) = 3, cwnd = 3
	require.Equal(t, uint32(3), ssthresh, "ssthresh = max(6/2, 2) = 3")
	require.Equal(t, uint32(3), cwnd, "cwnd should equal ssthresh")
}
