package streaming

import (
	"testing"
	"time"

	"github.com/armon/circbuf"
	"github.com/stretchr/testify/require"
)

// newTestStreamConnForSlowStart creates a StreamConn for testing slow start behavior.
func newTestStreamConnForSlowStart() *StreamConn {
	recvBuf, _ := circbuf.NewBuffer(1024)
	s := &StreamConn{
		localStreamID:  100,
		remoteStreamID: 200,
		sendSeq:        1,
		recvSeq:        100,
		ackThrough:     0,
		state:          StateEstablished,
		recvBuf:        recvBuf,
		sendBuf:        []byte{},
		sentPackets:    make(map[uint32]*sentPacket),
		windowSize:     1,             // Start with slow start
		cwnd:           1,             // Initial congestion window
		ssthresh:       MaxWindowSize, // Slow start threshold
	}
	return s
}

// TestSlowStartInitialization verifies initial slow start values.
func TestSlowStartInitialization(t *testing.T) {
	s := newTestStreamConnForSlowStart()

	require.Equal(t, uint32(1), s.cwnd, "cwnd should start at 1")
	require.Equal(t, uint32(1), s.windowSize, "windowSize should start at 1")
	require.Equal(t, uint32(MaxWindowSize), s.ssthresh, "ssthresh should be MaxWindowSize")
}

// TestSlowStartExponentialGrowth verifies window doubles during slow start.
func TestSlowStartExponentialGrowth(t *testing.T) {
	s := newTestStreamConnForSlowStart()

	// Track sent packets for cleanup
	s.sentPackets[1] = &sentPacket{data: []byte{}, sentTime: time.Now()}
	s.sentPackets[2] = &sentPacket{data: []byte{}, sentTime: time.Now()}
	s.sentPackets[4] = &sentPacket{data: []byte{}, sentTime: time.Now()}

	tests := []struct {
		name                string
		ackThrough          uint32
		expectedCwnd        uint32
		expectedWindow      uint32
		expectedInSlowStart bool
	}{
		{
			name:                "first ACK: 1 -> 2",
			ackThrough:          1,
			expectedCwnd:        2,
			expectedWindow:      2,
			expectedInSlowStart: true,
		},
		{
			name:                "second ACK: 2 -> 4",
			ackThrough:          2,
			expectedCwnd:        4,
			expectedWindow:      4,
			expectedInSlowStart: true,
		},
		{
			name:                "third ACK: 4 -> 8",
			ackThrough:          4,
			expectedCwnd:        8,
			expectedWindow:      8,
			expectedInSlowStart: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &Packet{
				Flags:      FlagACK,
				AckThrough: tt.ackThrough,
			}

			s.mu.Lock()
			err := s.handleAckLocked(pkt)
			cwnd := s.cwnd
			windowSize := s.windowSize
			inSlowStart := s.cwnd < s.ssthresh
			s.mu.Unlock()

			require.NoError(t, err)
			require.Equal(t, tt.expectedCwnd, cwnd, "cwnd should double")
			require.Equal(t, tt.expectedWindow, windowSize, "windowSize should match cwnd")
			require.Equal(t, tt.expectedInSlowStart, inSlowStart, "slow start state check")
		})
	}
}

// TestSlowStartReachesThreshold verifies transition to congestion avoidance.
func TestSlowStartReachesThreshold(t *testing.T) {
	s := newTestStreamConnForSlowStart()
	s.ssthresh = 8 // Set low threshold for testing

	// Track sent packets
	for i := uint32(1); i <= 10; i++ {
		s.sentPackets[i] = &sentPacket{data: []byte{}, sentTime: time.Now()}
	}

	// Grow from 1 -> 2 -> 4 -> 8 (reaches threshold)
	acks := []uint32{1, 2, 4}
	for _, ack := range acks {
		pkt := &Packet{
			Flags:      FlagACK,
			AckThrough: ack,
		}
		s.mu.Lock()
		err := s.handleAckLocked(pkt)
		s.mu.Unlock()
		require.NoError(t, err)
	}

	s.mu.Lock()
	cwnd := s.cwnd
	ssthresh := s.ssthresh
	s.mu.Unlock()

	require.Equal(t, ssthresh, cwnd, "cwnd should equal ssthresh")
}

// TestCongestionAvoidanceLinearGrowth verifies linear growth after threshold.
func TestCongestionAvoidanceLinearGrowth(t *testing.T) {
	s := newTestStreamConnForSlowStart()
	s.cwnd = 10
	s.ssthresh = 10
	s.windowSize = 10

	// Track sent packets
	for i := uint32(1); i <= 15; i++ {
		s.sentPackets[i] = &sentPacket{data: []byte{}, sentTime: time.Now()}
	}

	// In congestion avoidance, window grows by 1 per ACK
	tests := []struct {
		name           string
		ackThrough     uint32
		expectedCwnd   uint32
		expectedWindow uint32
	}{
		{
			name:           "first ACK: 10 -> 11",
			ackThrough:     11,
			expectedCwnd:   11,
			expectedWindow: 11,
		},
		{
			name:           "second ACK: 11 -> 12",
			ackThrough:     12,
			expectedCwnd:   12,
			expectedWindow: 12,
		},
		{
			name:           "third ACK: 12 -> 13",
			ackThrough:     13,
			expectedCwnd:   13,
			expectedWindow: 13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &Packet{
				Flags:      FlagACK,
				AckThrough: tt.ackThrough,
			}

			s.mu.Lock()
			err := s.handleAckLocked(pkt)
			cwnd := s.cwnd
			windowSize := s.windowSize
			s.mu.Unlock()

			require.NoError(t, err)
			require.Equal(t, tt.expectedCwnd, cwnd, "cwnd should increment by 1")
			require.Equal(t, tt.expectedWindow, windowSize, "windowSize should match cwnd")
		})
	}
}

// TestWindowSizeMaximum verifies window doesn't exceed MaxWindowSize.
func TestWindowSizeMaximum(t *testing.T) {
	s := newTestStreamConnForSlowStart()
	s.cwnd = MaxWindowSize - 1
	s.ssthresh = MaxWindowSize
	s.windowSize = MaxWindowSize - 1

	// Track sent packet
	s.sentPackets[1] = &sentPacket{data: []byte{}, sentTime: time.Now()}

	pkt := &Packet{
		Flags:      FlagACK,
		AckThrough: 1,
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)
	cwnd := s.cwnd
	windowSize := s.windowSize
	s.mu.Unlock()

	require.NoError(t, err)
	require.Equal(t, uint32(MaxWindowSize), cwnd, "cwnd should not exceed MaxWindowSize")
	require.Equal(t, uint32(MaxWindowSize), windowSize, "windowSize should not exceed MaxWindowSize")
}

// TestSlowStartWithMultipleAcks verifies behavior with rapid ACKs.
func TestSlowStartWithMultipleAcks(t *testing.T) {
	s := newTestStreamConnForSlowStart()

	// Track multiple sent packets
	for i := uint32(1); i <= 20; i++ {
		s.sentPackets[i] = &sentPacket{data: []byte{}, sentTime: time.Now()}
	}

	// Simulate rapid ACKs during slow start
	// Window should grow: 1 -> 2 -> 4 -> 8 -> 16
	ackSequence := []uint32{1, 2, 4, 8, 16}
	expectedWindows := []uint32{2, 4, 8, 16, 32}

	for i, ack := range ackSequence {
		pkt := &Packet{
			Flags:      FlagACK,
			AckThrough: ack,
		}

		s.mu.Lock()
		err := s.handleAckLocked(pkt)
		cwnd := s.cwnd
		s.mu.Unlock()

		require.NoError(t, err, "ACK %d should succeed", i+1)
		require.Equal(t, expectedWindows[i], cwnd, "ACK %d: window mismatch", i+1)
	}
}

// TestSlowStartNoAckIncrease verifies window stays same without new ACKs.
func TestSlowStartNoAckIncrease(t *testing.T) {
	s := newTestStreamConnForSlowStart()
	s.ackThrough = 5
	s.cwnd = 4
	s.windowSize = 4

	// Send ACK with same ackThrough - no window growth
	pkt := &Packet{
		Flags:      FlagACK,
		AckThrough: 5,
	}

	s.mu.Lock()
	oldCwnd := s.cwnd
	err := s.handleAckLocked(pkt)
	newCwnd := s.cwnd
	s.mu.Unlock()

	require.NoError(t, err)
	require.Equal(t, oldCwnd, newCwnd, "cwnd should not change without new ACK")
}

// TestSlowStartWithNACKs verifies slow start works alongside NACK processing.
func TestSlowStartWithNACKs(t *testing.T) {
	s := newTestStreamConnForSlowStart()

	// Track sent packets including one that will be NACKed
	s.sentPackets[1] = &sentPacket{data: []byte("packet1"), sentTime: time.Now()}
	s.sentPackets[2] = &sentPacket{data: []byte("packet2"), sentTime: time.Now()}
	s.sentPackets[3] = &sentPacket{data: []byte("packet3"), sentTime: time.Now()}

	// ACK packet 3 with NACK for packet 2
	pkt := &Packet{
		Flags:      FlagACK,
		AckThrough: 3,
		NACKs:      []uint32{2}, // Request retransmission of packet 2
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)
	cwnd := s.cwnd
	s.mu.Unlock()

	require.NoError(t, err)
	require.Equal(t, uint32(2), cwnd, "cwnd should still grow despite NACKs")
}

// TestCongestionAvoidanceAtMaxWindow verifies behavior at maximum window.
func TestCongestionAvoidanceAtMaxWindow(t *testing.T) {
	s := newTestStreamConnForSlowStart()
	s.cwnd = MaxWindowSize
	s.ssthresh = MaxWindowSize / 2
	s.windowSize = MaxWindowSize

	// Track sent packet
	s.sentPackets[1] = &sentPacket{data: []byte{}, sentTime: time.Now()}

	pkt := &Packet{
		Flags:      FlagACK,
		AckThrough: 1,
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)
	cwnd := s.cwnd
	windowSize := s.windowSize
	s.mu.Unlock()

	require.NoError(t, err)
	require.Equal(t, uint32(MaxWindowSize), cwnd, "cwnd should stay at max")
	require.Equal(t, uint32(MaxWindowSize), windowSize, "windowSize should stay at max")
}

// TestSlowStartThresholdBoundary verifies exact threshold behavior.
func TestSlowStartThresholdBoundary(t *testing.T) {
	s := newTestStreamConnForSlowStart()
	s.cwnd = 32
	s.ssthresh = 64
	s.windowSize = 32

	// Track sent packets
	for i := uint32(1); i <= 100; i++ {
		s.sentPackets[i] = &sentPacket{data: []byte{}, sentTime: time.Now()}
	}

	// One more ACK should reach threshold: 32 -> 64
	pkt := &Packet{
		Flags:      FlagACK,
		AckThrough: 33,
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)
	cwnd := s.cwnd
	ssthresh := s.ssthresh
	inSlowStart := s.cwnd < s.ssthresh
	s.mu.Unlock()

	require.NoError(t, err)
	require.Equal(t, uint32(64), cwnd, "cwnd should reach threshold")
	require.Equal(t, ssthresh, cwnd, "cwnd should equal ssthresh")
	require.False(t, inSlowStart, "should transition to congestion avoidance")

	// Next ACK should use linear growth: 64 -> 65
	pkt2 := &Packet{
		Flags:      FlagACK,
		AckThrough: 34,
	}

	s.mu.Lock()
	err2 := s.handleAckLocked(pkt2)
	cwnd2 := s.cwnd
	s.mu.Unlock()

	require.NoError(t, err2)
	require.Equal(t, uint32(65), cwnd2, "should use linear growth after threshold")
}
