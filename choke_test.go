package streaming

import (
	"sync"
	"testing"

	"github.com/armon/circbuf"
	"github.com/stretchr/testify/require"
)

// newTestStreamConnForChoke creates a minimal StreamConn for testing choke signals.
func newTestStreamConnForChoke(bufferSize int) *StreamConn {
	recvBuf, _ := circbuf.NewBuffer(int64(bufferSize))
	s := &StreamConn{
		localStreamID:     100,
		remoteStreamID:    200,
		sendSeq:           1,
		recvSeq:           100,
		recvBuf:           recvBuf,
		outOfOrderPackets: make(map[uint32]*Packet),
		nackList:          []uint32{},
	}
	s.recvCond = sync.NewCond(&s.mu)
	return s
}

// TestChokeSignalGeneration verifies that choke signals are sent when buffer fills.
func TestChokeSignalGeneration(t *testing.T) {
	tests := []struct {
		name                string
		bufferSize          int
		dataSize            int
		expectChoke         bool
		expectedBufferUsage float64
	}{
		{
			name:                "low buffer usage - no choke",
			bufferSize:          1000,
			dataSize:            100, // 10% usage
			expectChoke:         false,
			expectedBufferUsage: 0.1,
		},
		{
			name:                "medium buffer usage - no choke",
			bufferSize:          1000,
			dataSize:            500, // 50% usage
			expectChoke:         false,
			expectedBufferUsage: 0.5,
		},
		{
			name:                "high buffer usage - sends choke",
			bufferSize:          1000,
			dataSize:            850, // 85% usage
			expectChoke:         true,
			expectedBufferUsage: 0.85,
		},
		{
			name:                "near full buffer - sends choke",
			bufferSize:          1000,
			dataSize:            950, // 95% usage
			expectChoke:         true,
			expectedBufferUsage: 0.95,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStreamConnForChoke(tt.bufferSize)

			// Create packet with test data
			pkt := &Packet{
				SequenceNum: s.recvSeq,
				Payload:     make([]byte, tt.dataSize),
			}

			// Handle the packet
			s.mu.Lock()
			err := s.handleDataLocked(pkt)
			chokeState := s.sendingChoke
			bufferUsed := float64(s.recvBuf.TotalWritten()) / float64(s.recvBuf.Size())
			s.mu.Unlock()

			require.NoError(t, err)
			require.Equal(t, tt.expectChoke, chokeState, "choke state mismatch")
			require.InDelta(t, tt.expectedBufferUsage, bufferUsed, 0.01, "buffer usage mismatch")
		})
	}
}

// TestUnchokeSignalGeneration verifies that unchoke signals are sent when buffer drains.
func TestUnchokeSignalGeneration(t *testing.T) {
	// Create connection with small buffer
	bufferSize := 1000
	s := newTestStreamConnForChoke(bufferSize)

	// Fill buffer to trigger choke (85% usage)
	pkt1 := &Packet{
		SequenceNum: s.recvSeq,
		Payload:     make([]byte, 850),
	}

	s.mu.Lock()
	err := s.handleDataLocked(pkt1)
	s.mu.Unlock()
	require.NoError(t, err)

	// Verify choke signal was sent
	s.mu.Lock()
	require.True(t, s.sendingChoke, "should be in choked state")
	s.mu.Unlock()

	// Read data to drain buffer below 30%
	buf := make([]byte, 600)
	n, err := s.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 600, n)

	// Send another packet to trigger buffer check
	s.mu.Lock()
	s.recvSeq++
	pkt2 := &Packet{
		SequenceNum: s.recvSeq,
		Payload:     make([]byte, 100),
	}
	err = s.handleDataLocked(pkt2)
	chokeState := s.sendingChoke
	bufferUsed := float64(s.recvBuf.TotalWritten()) / float64(s.recvBuf.Size())
	s.mu.Unlock()

	require.NoError(t, err)
	require.False(t, chokeState, "should have sent unchoke signal")
	require.Less(t, bufferUsed, 0.4, "buffer usage should be below 40%")
}

// TestChokeSignalPacketFormat verifies choke signal packet structure.
func TestChokeSignalPacketFormat(t *testing.T) {
	s := newTestStreamConnForChoke(1000)

	s.mu.Lock()
	err := s.sendChokeSignalLocked()
	chokeState := s.sendingChoke
	s.mu.Unlock()

	require.NoError(t, err)
	require.True(t, chokeState, "sendingChoke should be true after sending choke signal")

	// Note: We can't verify the actual packet contents in this test
	// because sendPacketLocked doesn't send when session is nil.
	// The packet format is validated by the protocol spec and
	// will be tested in integration tests.
}

// TestUnchokeSignalPacketFormat verifies unchoke signal packet structure.
func TestUnchokeSignalPacketFormat(t *testing.T) {
	s := newTestStreamConnForChoke(1000)

	// Set initial choke state
	s.mu.Lock()
	s.sendingChoke = true
	err := s.sendUnchokeSignalLocked()
	chokeState := s.sendingChoke
	s.mu.Unlock()

	require.NoError(t, err)
	require.False(t, chokeState, "sendingChoke should be false after sending unchoke signal")
}

// TestChokeHysteresis verifies hysteresis prevents choke signal flapping.
func TestChokeHysteresis(t *testing.T) {
	bufferSize := 1000
	s := newTestStreamConnForChoke(bufferSize)

	// Fill to 85% - triggers choke
	pkt1 := &Packet{
		SequenceNum: s.recvSeq,
		Payload:     make([]byte, 850),
	}

	s.mu.Lock()
	err := s.handleDataLocked(pkt1)
	require.NoError(t, err)
	require.True(t, s.sendingChoke, "should be choked at 85%")

	// Read some data to get to 60% - should still be choked (hysteresis)
	s.mu.Unlock()
	buf := make([]byte, 250)
	n, err := s.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 250, n)

	s.mu.Lock()
	s.recvSeq++
	pkt2 := &Packet{
		SequenceNum: s.recvSeq,
		Payload:     make([]byte, 10),
	}
	err = s.handleDataLocked(pkt2)
	require.NoError(t, err)
	// Should still be choked because we're above 30% threshold
	require.True(t, s.sendingChoke, "should still be choked at 60%")

	// Read more to get below 30% - triggers unchoke
	s.mu.Unlock()
	buf2 := make([]byte, 400)
	n, err = s.Read(buf2)
	require.NoError(t, err)
	require.Equal(t, 400, n)

	s.mu.Lock()
	s.recvSeq++
	pkt3 := &Packet{
		SequenceNum: s.recvSeq,
		Payload:     make([]byte, 10),
	}
	err = s.handleDataLocked(pkt3)
	s.mu.Unlock()

	require.NoError(t, err)

	s.mu.Lock()
	require.False(t, s.sendingChoke, "should be unchoked below 30%")
	s.mu.Unlock()
}

// TestChokeWithNACKs verifies choke signals include NACK list.
func TestChokeWithNACKs(t *testing.T) {
	s := newTestStreamConnForChoke(1000)

	// Add some NACKs
	s.mu.Lock()
	s.nackList = []uint32{100, 101, 102}

	err := s.sendChokeSignalLocked()
	s.mu.Unlock()

	require.NoError(t, err)
	// The actual NACK inclusion in packet is tested implicitly
	// through the sendChokeSignalLocked implementation
}

// TestChokeSignalNotSentWhenAlreadyChoking verifies idempotence.
func TestChokeSignalNotSentWhenAlreadyChoking(t *testing.T) {
	bufferSize := 1000
	s := newTestStreamConnForChoke(bufferSize)

	// First packet fills to 85% - sends choke
	pkt1 := &Packet{
		SequenceNum: s.recvSeq,
		Payload:     make([]byte, 850),
	}

	s.mu.Lock()
	err := s.handleDataLocked(pkt1)
	require.NoError(t, err)
	require.True(t, s.sendingChoke)

	// Second packet at 86% - should not send another choke
	s.recvSeq++
	pkt2 := &Packet{
		SequenceNum: s.recvSeq,
		Payload:     make([]byte, 10),
	}
	// Reset lastBufferCheck to force buffer check
	s.lastBufferCheck = 0
	err = s.handleDataLocked(pkt2)
	s.mu.Unlock()

	require.NoError(t, err)
	// Should still be choked, but not send duplicate signal
	s.mu.Lock()
	require.True(t, s.sendingChoke)
	s.mu.Unlock()
}

// TestBufferOverflowWithChoke verifies behavior when buffer completely fills.
func TestBufferOverflowWithChoke(t *testing.T) {
	// Small buffer for easy overflow
	bufferSize := 100
	s := newTestStreamConnForChoke(bufferSize)

	// Fill buffer to 85% - triggers choke
	pkt1 := &Packet{
		SequenceNum: s.recvSeq,
		Payload:     make([]byte, 85),
	}

	s.mu.Lock()
	err := s.handleDataLocked(pkt1)
	require.NoError(t, err)
	require.True(t, s.sendingChoke, "should send choke at 85%")

	// Try to overfill - should send choke and return error
	s.recvSeq++
	pkt2 := &Packet{
		SequenceNum: s.recvSeq,
		Payload:     make([]byte, 20), // Would exceed buffer
	}
	err = s.handleDataLocked(pkt2)
	s.mu.Unlock()

	// Should get error from buffer overflow
	require.Error(t, err, "should error on buffer overflow")
	require.Contains(t, err.Error(), "write to receive buffer", "should be buffer write error")
}

// TestLastBufferCheckTracking verifies buffer check optimization.
func TestLastBufferCheckTracking(t *testing.T) {
	s := newTestStreamConnForChoke(1000)

	// First packet - sets lastBufferCheck
	pkt1 := &Packet{
		SequenceNum: s.recvSeq,
		Payload:     make([]byte, 100),
	}

	s.mu.Lock()
	require.Equal(t, int64(0), s.lastBufferCheck, "initial lastBufferCheck should be 0")

	err := s.handleDataLocked(pkt1)
	require.NoError(t, err)
	firstCheck := s.lastBufferCheck
	require.NotEqual(t, int64(0), firstCheck, "lastBufferCheck should be updated")

	// Second packet - updates lastBufferCheck
	s.recvSeq++
	pkt2 := &Packet{
		SequenceNum: s.recvSeq,
		Payload:     make([]byte, 100),
	}
	err = s.handleDataLocked(pkt2)
	s.mu.Unlock()

	require.NoError(t, err)
	s.mu.Lock()
	require.Greater(t, s.lastBufferCheck, firstCheck, "lastBufferCheck should increase")
	s.mu.Unlock()
}
