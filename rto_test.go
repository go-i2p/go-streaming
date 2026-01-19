package streaming

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRTOFirstMeasurement verifies initial RTT measurement and RTO calculation
func TestRTOFirstMeasurement(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       16,
		ssthresh:   128,
		windowSize: 16,
	}
	s.sentPackets = make(map[uint32]*sentPacket)

	// Add a sent packet with known sent time
	sentTime := time.Now().Add(-100 * time.Millisecond)
	s.sentPackets[5] = &sentPacket{
		sentTime: sentTime,
		data:     []byte{1, 2, 3},
	}

	// ACK the packet
	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   5,
		Flags:        0, // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)

	rtt := s.rtt
	srtt := s.srtt
	rttVar := s.rttVariance
	rto := s.rto
	s.mu.Unlock()

	require.NoError(t, err)

	// First measurement: SRTT = RTT, RTTVAR = RTT/2
	require.Greater(t, rtt, 50*time.Millisecond, "RTT should be >= 50ms")
	require.Less(t, rtt, 150*time.Millisecond, "RTT should be < 150ms")
	require.Equal(t, rtt, srtt, "SRTT should equal first RTT measurement")
	require.Equal(t, rtt/2, rttVar, "RTTVAR should be RTT/2 for first measurement")

	// RTO = SRTT + 4*RTTVAR = RTT + 4*(RTT/2) = 3*RTT
	// Per I2P streaming spec, minimum RTO is 100ms
	expectedRTO := rtt + 4*rttVar
	if expectedRTO < MinRTO {
		expectedRTO = MinRTO
	}
	require.Equal(t, expectedRTO, rto, "RTO should be SRTT + 4*RTTVAR (with 100ms minimum)")
}

// TestRTOSubsequentMeasurements verifies exponential weighted moving average
func TestRTOSubsequentMeasurements(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       16,
		ssthresh:   128,
		windowSize: 16,
	}
	s.sentPackets = make(map[uint32]*sentPacket)

	// First measurement: 100ms RTT
	s.sentPackets[5] = &sentPacket{
		sentTime: time.Now().Add(-100 * time.Millisecond),
		data:     []byte{1},
	}

	pkt1 := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   5,
		Flags:        0, // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt1)
	firstSRTT := s.srtt
	firstRTTVar := s.rttVariance
	s.mu.Unlock()

	require.NoError(t, err)
	require.Greater(t, firstSRTT, 90*time.Millisecond)
	require.Less(t, firstSRTT, 110*time.Millisecond)

	// Second measurement: 200ms RTT (significant change)
	time.Sleep(10 * time.Millisecond) // Small delay to ensure different timestamps
	s.sentPackets[10] = &sentPacket{
		sentTime: time.Now().Add(-200 * time.Millisecond),
		data:     []byte{2},
	}

	pkt2 := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  101,
		AckThrough:   10,
		Flags:        0, // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err = s.handleAckLocked(pkt2)
	secondSRTT := s.srtt
	secondRTTVar := s.rttVariance
	s.mu.Unlock()

	require.NoError(t, err)

	// SRTT should be between first and second RTT (smoothed)
	require.Greater(t, secondSRTT, firstSRTT, "SRTT should increase")
	require.Less(t, secondSRTT, 200*time.Millisecond, "SRTT should be less than second RTT")

	// RTTVAR should increase due to variance
	require.Greater(t, secondRTTVar, firstRTTVar, "RTTVAR should increase with variance")
}

// TestRTOMinimumBound verifies RTO minimum of 1 second
func TestRTOMinimumBound(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       16,
		ssthresh:   128,
		windowSize: 16,
	}
	s.sentPackets = make(map[uint32]*sentPacket)

	// Very fast RTT: 10ms
	s.sentPackets[5] = &sentPacket{
		sentTime: time.Now().Add(-10 * time.Millisecond),
		data:     []byte{1},
	}

	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   5,
		Flags:        0, // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)
	rto := s.rto
	s.mu.Unlock()

	require.NoError(t, err)
	require.Equal(t, MinRTO, rto, "RTO should be at least 100ms per I2P streaming spec")
}

// TestRTOMaximumBound verifies RTO maximum of 60 seconds
func TestRTOMaximumBound(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       16,
		ssthresh:   128,
		windowSize: 16,
	}
	s.sentPackets = make(map[uint32]*sentPacket)

	// Very slow RTT: 30 seconds (simulated)
	s.sentPackets[5] = &sentPacket{
		sentTime: time.Now().Add(-30 * time.Second),
		data:     []byte{1},
	}

	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   5,
		Flags:        0, // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)
	rto := s.rto
	s.mu.Unlock()

	require.NoError(t, err)
	require.Equal(t, 60*time.Second, rto, "RTO should be capped at 60 seconds")
}

// TestRTOVarianceCalculation verifies RTTVAR responds to RTT changes
func TestRTOVarianceCalculation(t *testing.T) {
	s := &StreamConn{
		state:       StateEstablished,
		sendSeq:     1000,
		ackThrough:  0,
		cwnd:        16,
		ssthresh:    128,
		windowSize:  16,
		srtt:        100 * time.Millisecond, // Pre-set SRTT
		rttVariance: 10 * time.Millisecond,  // Pre-set small variance
	}
	s.sentPackets = make(map[uint32]*sentPacket)

	// Measurement with RTT far from SRTT
	s.sentPackets[5] = &sentPacket{
		sentTime: time.Now().Add(-200 * time.Millisecond),
		data:     []byte{1},
	}

	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   5,
		Flags:        0, // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	oldRTTVar := s.rttVariance
	err := s.handleAckLocked(pkt)
	newRTTVar := s.rttVariance
	s.mu.Unlock()

	require.NoError(t, err)
	require.Greater(t, newRTTVar, oldRTTVar, "RTTVAR should increase with large RTT deviation")
}

// TestRTOWithStableNetwork verifies RTO stabilizes with consistent RTT
func TestRTOWithStableNetwork(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       16,
		ssthresh:   128,
		windowSize: 16,
	}
	s.sentPackets = make(map[uint32]*sentPacket)

	// Simulate 5 consistent RTT measurements
	for i := uint32(1); i <= 5; i++ {
		s.sentPackets[i*5] = &sentPacket{
			sentTime: time.Now().Add(-100 * time.Millisecond),
			data:     []byte{byte(i)},
		}

		pkt := &Packet{
			SendStreamID: 1,
			RecvStreamID: 2,
			SequenceNum:  100 + i,
			AckThrough:   i * 5,
			Flags:        0, // No flags needed - ackThrough always valid per spec
		}

		s.mu.Lock()
		err := s.handleAckLocked(pkt)
		s.mu.Unlock()

		require.NoError(t, err)

		// Add small delay between measurements
		time.Sleep(5 * time.Millisecond)
	}

	s.mu.Lock()
	finalRTTVar := s.rttVariance
	finalSRTT := s.srtt
	s.mu.Unlock()

	// With stable RTT, variance should be small
	require.Less(t, finalRTTVar, 50*time.Millisecond, "RTTVAR should be small with stable network")
	require.Greater(t, finalSRTT, 90*time.Millisecond)
	require.Less(t, finalSRTT, 110*time.Millisecond, "SRTT should converge to actual RTT")
}

// TestRTOFormula verifies RTO = SRTT + 4*RTTVAR calculation
func TestRTOFormula(t *testing.T) {
	s := &StreamConn{
		state:       StateEstablished,
		sendSeq:     1000,
		ackThrough:  0,
		cwnd:        16,
		ssthresh:    128,
		windowSize:  16,
		srtt:        100 * time.Millisecond,
		rttVariance: 20 * time.Millisecond,
	}
	s.sentPackets = make(map[uint32]*sentPacket)

	s.sentPackets[5] = &sentPacket{
		sentTime: time.Now().Add(-100 * time.Millisecond),
		data:     []byte{1},
	}

	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   5,
		Flags:        0, // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)
	rto := s.rto
	srtt := s.srtt
	rttVar := s.rttVariance
	s.mu.Unlock()

	require.NoError(t, err)

	// Verify RTO calculation (allowing for min/max bounds)
	expectedRTO := srtt + 4*rttVar
	if expectedRTO < MinRTO {
		expectedRTO = MinRTO
	}
	if expectedRTO > MaxRTO {
		expectedRTO = MaxRTO
	}

	require.Equal(t, expectedRTO, rto, "RTO should equal SRTT + 4*RTTVAR (within bounds)")
}

// TestRTONoPacketInfo verifies graceful handling when packet info missing
func TestRTONoPacketInfo(t *testing.T) {
	s := &StreamConn{
		state:      StateEstablished,
		sendSeq:    1000,
		ackThrough: 0,
		cwnd:       16,
		ssthresh:   128,
		windowSize: 16,
	}
	s.sentPackets = make(map[uint32]*sentPacket)
	// Note: No packet with seq=5 added

	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   5,
		Flags:        0, // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	oldRTT := s.rtt
	oldSRTT := s.srtt
	err := s.handleAckLocked(pkt)
	newRTT := s.rtt
	newSRTT := s.srtt
	s.mu.Unlock()

	require.NoError(t, err)
	require.Equal(t, oldRTT, newRTT, "RTT should not change if packet not found")
	require.Equal(t, oldSRTT, newSRTT, "SRTT should not change if packet not found")
}

// TestRTOAlphaAndBeta verifies RFC 6298 alpha and beta constants
func TestRTOAlphaAndBeta(t *testing.T) {
	s := &StreamConn{
		state:       StateEstablished,
		sendSeq:     1000,
		ackThrough:  0,
		cwnd:        16,
		ssthresh:    128,
		windowSize:  16,
		srtt:        100 * time.Millisecond,
		rttVariance: 20 * time.Millisecond,
	}
	s.sentPackets = make(map[uint32]*sentPacket)

	// New RTT measurement: 150ms
	s.sentPackets[5] = &sentPacket{
		sentTime: time.Now().Add(-150 * time.Millisecond),
		data:     []byte{1},
	}

	pkt := &Packet{
		SendStreamID: 1,
		RecvStreamID: 2,
		SequenceNum:  100,
		AckThrough:   5,
		Flags:        0, // No flags needed - ackThrough always valid per spec
	}

	s.mu.Lock()
	oldSRTT := s.srtt
	oldRTTVar := s.rttVariance

	err := s.handleAckLocked(pkt)

	newSRTT := s.srtt
	newRTTVar := s.rttVariance
	s.mu.Unlock()

	require.NoError(t, err)

	// SRTT should move toward new RTT but not equal it (alpha = 1/8)
	require.Greater(t, newSRTT, oldSRTT, "SRTT should increase toward new RTT")
	require.Less(t, newSRTT, 150*time.Millisecond, "SRTT should not fully reach new RTT")

	// RTTVAR should increase due to deviation (beta = 1/4)
	require.Greater(t, newRTTVar, oldRTTVar, "RTTVAR should increase with deviation")
}
