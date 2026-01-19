package streaming

import (
	"sync"
	"testing"

	"github.com/armon/circbuf"
	"github.com/stretchr/testify/require"
)

// newTestStreamConnForFastRetransmit creates a StreamConn for testing fast retransmit.
// It sets up the necessary fields for NACK handling including nackCounts tracking.
func newTestStreamConnForFastRetransmit(t *testing.T) *StreamConn {
	i2cp := RequireI2CP(t)
	recvBuf, _ := circbuf.NewBuffer(1024)
	s := &StreamConn{
		session:           i2cp.Manager.session,
		dest:              i2cp.Manager.Destination(),
		sendSeq:           100,
		windowSize:        DefaultWindowSize,
		cwnd:              DefaultWindowSize,
		ssthresh:          MaxWindowSize,
		recvBuf:           recvBuf,
		sentPackets:       make(map[uint32]*sentPacket),
		nackCounts:        make(map[uint32]int),
		outOfOrderPackets: make(map[uint32]*Packet),
		nackList:          make(map[uint32]struct{}),
	}
	s.recvCond = sync.NewCond(&s.mu)
	s.sendCond = sync.NewCond(&s.mu)
	return s
}

// TestFastRetransmitThreshold verifies that the threshold constant is correct.
func TestFastRetransmitThreshold(t *testing.T) {
	require.Equal(t, 2, FastRetransmitThreshold,
		"Per I2P spec: 'Two NACKs of a packet is a request for fast retransmit'")
}

// TestFirstNACKDoesNotRetransmit verifies that a single NACK does not trigger retransmission.
func TestFirstNACKDoesNotRetransmit(t *testing.T) {
	s := newTestStreamConnForFastRetransmit(t)

	// Send a packet that will be tracked for retransmission
	pkt := &Packet{
		SequenceNum: 50,
		Payload:     []byte("test data"),
	}

	s.mu.Lock()
	err := s.sendPacketLocked(pkt)
	require.NoError(t, err)

	// Verify packet is tracked
	require.NotNil(t, s.sentPackets[50], "packet should be tracked in sentPackets")
	initialRetryCount := s.sentPackets[50].retryCount

	// Send first NACK
	s.handleNACKsLocked([]uint32{50})

	// Verify NACK count was incremented
	require.Equal(t, 1, s.nackCounts[50], "NACK count should be 1 after first NACK")

	// Verify packet was NOT retransmitted (retryCount unchanged)
	require.Equal(t, initialRetryCount, s.sentPackets[50].retryCount,
		"packet should NOT be retransmitted after first NACK")
	s.mu.Unlock()
}

// TestSecondNACKTriggersRetransmit verifies that two NACKs trigger fast retransmit.
func TestSecondNACKTriggersRetransmit(t *testing.T) {
	s := newTestStreamConnForFastRetransmit(t)

	// Send a packet that will be tracked for retransmission
	pkt := &Packet{
		SequenceNum: 50,
		Payload:     []byte("test data"),
	}

	s.mu.Lock()
	err := s.sendPacketLocked(pkt)
	require.NoError(t, err)

	initialRetryCount := s.sentPackets[50].retryCount

	// Send first NACK - should NOT retransmit
	s.handleNACKsLocked([]uint32{50})
	require.Equal(t, 1, s.nackCounts[50], "NACK count should be 1")
	require.Equal(t, initialRetryCount, s.sentPackets[50].retryCount,
		"should NOT retransmit after first NACK")

	// Send second NACK - SHOULD retransmit
	s.handleNACKsLocked([]uint32{50})

	// NACK count should be cleared after retransmit
	require.Equal(t, 0, s.nackCounts[50], "NACK count should be cleared after retransmit")

	// Verify retransmission occurred
	require.Equal(t, initialRetryCount+1, s.sentPackets[50].retryCount,
		"packet SHOULD be retransmitted after second NACK")
	s.mu.Unlock()
}

// TestMultipleNACKsInSingleBatch verifies that receiving threshold NACKs in one batch works.
func TestMultipleNACKsInSingleBatch(t *testing.T) {
	s := newTestStreamConnForFastRetransmit(t)

	// Send two packets
	for seq := uint32(50); seq <= 51; seq++ {
		pkt := &Packet{
			SequenceNum: seq,
			Payload:     []byte("test data"),
		}
		s.mu.Lock()
		err := s.sendPacketLocked(pkt)
		s.mu.Unlock()
		require.NoError(t, err)
	}

	s.mu.Lock()
	// Pre-increment NACK count for seq 50 to simulate previous NACK
	s.nackCounts[50] = 1

	// Send NACKs for both packets in one batch
	// Seq 50 now has 2 NACKs total (1 pre-existing + 1 new) -> should retransmit
	// Seq 51 has 1 NACK -> should NOT retransmit
	s.handleNACKsLocked([]uint32{50, 51})

	// Verify seq 50 was retransmitted (NACK count cleared)
	require.Equal(t, 0, s.nackCounts[50], "seq 50 NACK count should be cleared after retransmit")
	require.Equal(t, 1, s.sentPackets[50].retryCount, "seq 50 should be retransmitted")

	// Verify seq 51 was NOT retransmitted (only 1 NACK)
	require.Equal(t, 1, s.nackCounts[51], "seq 51 should have NACK count of 1")
	require.Equal(t, 0, s.sentPackets[51].retryCount, "seq 51 should NOT be retransmitted")
	s.mu.Unlock()
}

// TestNACKCountsClearedOnACK verifies that NACK counts are cleared when packets are acknowledged.
func TestNACKCountsClearedOnACK(t *testing.T) {
	s := newTestStreamConnForFastRetransmit(t)

	// Send multiple packets
	for seq := uint32(10); seq <= 15; seq++ {
		pkt := &Packet{
			SequenceNum: seq,
			Payload:     []byte("test data"),
		}
		s.mu.Lock()
		err := s.sendPacketLocked(pkt)
		s.mu.Unlock()
		require.NoError(t, err)
	}

	s.mu.Lock()
	// Simulate receiving NACKs (count=1 for each, not yet triggering retransmit)
	s.nackCounts[10] = 1
	s.nackCounts[11] = 1
	s.nackCounts[12] = 1
	s.nackCounts[13] = 1
	s.nackCounts[14] = 1
	s.nackCounts[15] = 1

	// Simulate ACK through seq 12 (packets 10, 11, 12 are acknowledged)
	s.cleanupAckedPacketsLocked(0, 12, nil)

	// Verify NACK counts are cleared for ACKed packets
	require.Equal(t, 0, s.nackCounts[10], "seq 10 NACK count should be cleared")
	require.Equal(t, 0, s.nackCounts[11], "seq 11 NACK count should be cleared")
	require.Equal(t, 0, s.nackCounts[12], "seq 12 NACK count should be cleared")

	// Verify NACK counts remain for non-ACKed packets
	require.Equal(t, 1, s.nackCounts[13], "seq 13 NACK count should remain")
	require.Equal(t, 1, s.nackCounts[14], "seq 14 NACK count should remain")
	require.Equal(t, 1, s.nackCounts[15], "seq 15 NACK count should remain")
	s.mu.Unlock()
}

// TestCongestionWindowReductionOnFastRetransmit verifies that congestion window
// is reduced when fast retransmit is triggered, but only once per NACK batch.
func TestCongestionWindowReductionOnFastRetransmit(t *testing.T) {
	s := newTestStreamConnForFastRetransmit(t)

	// Set known window values
	s.mu.Lock()
	s.cwnd = 64
	s.ssthresh = 128
	s.windowSize = 64
	initialCwnd := s.cwnd

	// Send multiple packets
	for seq := uint32(50); seq <= 52; seq++ {
		pkt := &Packet{
			SequenceNum: seq,
			Payload:     []byte("test data"),
		}
		err := s.sendPacketLocked(pkt)
		require.NoError(t, err)
	}

	// Pre-increment NACK counts to trigger retransmit for all packets
	s.nackCounts[50] = 1
	s.nackCounts[51] = 1
	s.nackCounts[52] = 1

	// Send NACKs in one batch - all three packets should retransmit
	// but window reduction should only happen once
	s.handleNACKsLocked([]uint32{50, 51, 52})

	// Window should be reduced once: ssthresh = cwnd/2 = 32, cwnd = ssthresh = 32
	expectedCwnd := max(initialCwnd/2, 2) // max(32, 2) = 32
	require.Equal(t, expectedCwnd, s.cwnd, "cwnd should be reduced by half")
	require.Equal(t, expectedCwnd, s.ssthresh, "ssthresh should equal cwnd/2")
	require.Equal(t, expectedCwnd, s.windowSize, "windowSize should match cwnd")
	s.mu.Unlock()
}

// TestNoRetransmitForMissingPacket verifies that retransmit skips packets
// that are already ACKed (not in sentPackets).
func TestNoRetransmitForMissingPacket(t *testing.T) {
	s := newTestStreamConnForFastRetransmit(t)

	s.mu.Lock()
	// Pre-increment NACK count for a packet that doesn't exist in sentPackets
	s.nackCounts[999] = 1

	// This should not panic or error
	s.handleNACKsLocked([]uint32{999})

	// NACK count should still reach threshold and be cleared
	// even though no actual retransmit happened
	require.Equal(t, 0, s.nackCounts[999], "NACK count should be cleared")
	s.mu.Unlock()
}

// TestNACKCountsMapInitialization verifies that handleNACKsLocked initializes
// the nackCounts map if it's nil (backward compatibility).
func TestNACKCountsMapInitialization(t *testing.T) {
	recvBuf, _ := circbuf.NewBuffer(1024)
	s := &StreamConn{
		recvBuf:     recvBuf,
		nackCounts:  nil, // Explicitly nil
		sentPackets: make(map[uint32]*sentPacket),
	}
	s.recvCond = sync.NewCond(&s.mu)
	s.sendCond = sync.NewCond(&s.mu)

	s.mu.Lock()
	// This should not panic even with nil nackCounts
	s.handleNACKsLocked([]uint32{1, 2, 3})

	// nackCounts should be initialized
	require.NotNil(t, s.nackCounts, "nackCounts should be initialized")
	require.Equal(t, 1, s.nackCounts[1], "NACK count should be tracked")
	require.Equal(t, 1, s.nackCounts[2], "NACK count should be tracked")
	require.Equal(t, 1, s.nackCounts[3], "NACK count should be tracked")
	s.mu.Unlock()
}

// TestEmptyNACKsHandling verifies that empty NACK list is handled gracefully.
func TestEmptyNACKsHandling(t *testing.T) {
	s := newTestStreamConnForFastRetransmit(t)

	s.mu.Lock()
	initialCwnd := s.cwnd

	// Empty NACK list should do nothing
	s.handleNACKsLocked([]uint32{})

	// Window should not change
	require.Equal(t, initialCwnd, s.cwnd, "cwnd should not change with empty NACKs")
	s.mu.Unlock()
}

// TestNilNACKsHandling verifies that nil NACK list is handled gracefully.
func TestNilNACKsHandling(t *testing.T) {
	s := newTestStreamConnForFastRetransmit(t)

	s.mu.Lock()
	initialCwnd := s.cwnd

	// Nil NACK list should do nothing
	s.handleNACKsLocked(nil)

	// Window should not change
	require.Equal(t, initialCwnd, s.cwnd, "cwnd should not change with nil NACKs")
	s.mu.Unlock()
}

// TestFastRetransmitClearsNACKCountAfterRetransmit verifies that the NACK count
// is reset after retransmission so subsequent NACKs require threshold again.
func TestFastRetransmitClearsNACKCountAfterRetransmit(t *testing.T) {
	s := newTestStreamConnForFastRetransmit(t)

	pkt := &Packet{
		SequenceNum: 50,
		Payload:     []byte("test data"),
	}

	s.mu.Lock()
	err := s.sendPacketLocked(pkt)
	require.NoError(t, err)

	// First NACK
	s.handleNACKsLocked([]uint32{50})
	require.Equal(t, 1, s.nackCounts[50])

	// Second NACK - triggers retransmit
	s.handleNACKsLocked([]uint32{50})
	require.Equal(t, 0, s.nackCounts[50], "NACK count should be cleared after retransmit")
	require.Equal(t, 1, s.sentPackets[50].retryCount)

	// Third NACK - should NOT trigger immediate retransmit (count resets)
	s.handleNACKsLocked([]uint32{50})
	require.Equal(t, 1, s.nackCounts[50], "NACK count should start fresh")
	require.Equal(t, 1, s.sentPackets[50].retryCount, "should not retransmit yet")

	// Fourth NACK - SHOULD trigger retransmit again
	s.handleNACKsLocked([]uint32{50})
	require.Equal(t, 0, s.nackCounts[50], "NACK count should be cleared again")
	require.Equal(t, 2, s.sentPackets[50].retryCount, "should retransmit again")
	s.mu.Unlock()
}
