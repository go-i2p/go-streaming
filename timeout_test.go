package streaming

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/armon/circbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStreamConnForTimeout creates a StreamConn for timeout testing
func newTestStreamConnForTimeout() *StreamConn {
	ctx, cancel := context.WithCancel(context.Background())
	recvBuf, _ := circbuf.NewBuffer(4096)

	conn := &StreamConn{
		state:             StateEstablished,
		sendSeq:           1000,
		recvSeq:           100,
		ackThrough:        0,
		sentPackets:       make(map[uint32]*sentPacket),
		outOfOrderPackets: make(map[uint32]*Packet),
		nackList:          make([]uint32, 0),
		recvBuf:           recvBuf,
		recvChan:          make(chan *Packet, 10),
		errChan:           make(chan error, 1),
		ctx:               ctx,
		cancel:            cancel,
		windowSize:        16,
		cwnd:              16,
		ssthresh:          128,
		localMTU:          1730,
		remoteMTU:         1730,
	}
	conn.recvCond = sync.NewCond(&conn.mu)
	return conn
}

// TestTimeoutDetection verifies that packets timing out are detected
func TestTimeoutDetection(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set a short RTO for testing
	s.rto = 50 * time.Millisecond

	// Add a sent packet
	s.sentPackets[5] = &sentPacket{
		data:       []byte{1, 2, 3, 4},
		sentTime:   time.Now().Add(-100 * time.Millisecond), // Sent 100ms ago
		retryCount: 0,
	}

	// Check retransmissions - should detect timeout
	err := s.checkRetransmissions()
	require.NoError(t, err)

	// Verify packet was marked for retransmission
	require.Contains(t, s.sentPackets, uint32(5))
	assert.Equal(t, 1, s.sentPackets[5].retryCount, "Retry count should be incremented")

	// Verify RTO was doubled (exponential backoff)
	assert.Equal(t, 100*time.Millisecond, s.rto, "RTO should be doubled")
}

// TestNoTimeoutForRecentPackets verifies that recently sent packets don't timeout
func TestNoTimeoutForRecentPackets(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set RTO
	s.rto = 100 * time.Millisecond

	// Add a recently sent packet
	s.sentPackets[5] = &sentPacket{
		data:       []byte{1, 2, 3, 4},
		sentTime:   time.Now().Add(-50 * time.Millisecond), // Sent 50ms ago
		retryCount: 0,
	}

	// Check retransmissions - should not timeout
	err := s.checkRetransmissions()
	require.NoError(t, err)

	// Verify packet was NOT marked for retransmission
	assert.Equal(t, 0, s.sentPackets[5].retryCount, "Retry count should not change")
}

// TestExponentialBackoff verifies RTO doubles on timeout
func TestExponentialBackoff(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set initial RTO
	s.rto = 1 * time.Second

	// Add a timed-out packet
	s.sentPackets[5] = &sentPacket{
		data:       []byte{1, 2, 3, 4},
		sentTime:   time.Now().Add(-2 * time.Second),
		retryCount: 0,
	}

	// First timeout
	err := s.checkRetransmissions()
	require.NoError(t, err)
	assert.Equal(t, 2*time.Second, s.rto, "RTO should double after first timeout")

	// Simulate another timeout
	s.sentPackets[6] = &sentPacket{
		data:       []byte{5, 6, 7, 8},
		sentTime:   time.Now().Add(-3 * time.Second),
		retryCount: 0,
	}

	err = s.checkRetransmissions()
	require.NoError(t, err)
	assert.Equal(t, 4*time.Second, s.rto, "RTO should double again after second timeout")
}

// TestMaxRTOBound verifies RTO is capped at 60 seconds
func TestMaxRTOBound(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set RTO to 40 seconds
	s.rto = 40 * time.Second

	// Add a timed-out packet
	s.sentPackets[5] = &sentPacket{
		data:       []byte{1, 2, 3, 4},
		sentTime:   time.Now().Add(-50 * time.Second),
		retryCount: 0,
	}

	// Check retransmissions - RTO should be capped at 60s
	err := s.checkRetransmissions()
	require.NoError(t, err)
	assert.Equal(t, 60*time.Second, s.rto, "RTO should be capped at 60 seconds")
}

// TestMaxRetriesExceeded verifies connection closes after max retries
func TestMaxRetriesExceeded(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set a short RTO
	s.rto = 10 * time.Millisecond

	// Add a packet that has already been retried 10 times
	s.sentPackets[5] = &sentPacket{
		data:       []byte{1, 2, 3, 4},
		sentTime:   time.Now().Add(-20 * time.Millisecond),
		retryCount: 10, // Already at max
	}

	// Check retransmissions - should return error
	err := s.checkRetransmissions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max retransmissions exceeded")
}

// TestMultipleTimeouts verifies multiple packets timing out simultaneously
func TestMultipleTimeouts(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set RTO
	s.rto = 50 * time.Millisecond

	// Add multiple timed-out packets
	s.sentPackets[5] = &sentPacket{
		data:       []byte{1, 2, 3, 4},
		sentTime:   time.Now().Add(-100 * time.Millisecond),
		retryCount: 0,
	}
	s.sentPackets[6] = &sentPacket{
		data:       []byte{5, 6, 7, 8},
		sentTime:   time.Now().Add(-100 * time.Millisecond),
		retryCount: 0,
	}
	s.sentPackets[7] = &sentPacket{
		data:       []byte{9, 10, 11, 12},
		sentTime:   time.Now().Add(-100 * time.Millisecond),
		retryCount: 0,
	}

	// Check retransmissions - all should timeout
	err := s.checkRetransmissions()
	require.NoError(t, err)

	// Verify all packets were marked for retransmission
	assert.Equal(t, 1, s.sentPackets[5].retryCount)
	assert.Equal(t, 1, s.sentPackets[6].retryCount)
	assert.Equal(t, 1, s.sentPackets[7].retryCount)

	// Verify RTO was doubled (only once even with multiple timeouts)
	assert.Equal(t, 100*time.Millisecond, s.rto)
}

// TestNoRTOSkipsCheck verifies that checkRetransmissions skips when RTO is zero
func TestNoRTOSkipsCheck(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// RTO is zero (no RTT measurement yet)
	s.rto = 0

	// Add a packet
	s.sentPackets[5] = &sentPacket{
		data:       []byte{1, 2, 3, 4},
		sentTime:   time.Now().Add(-1 * time.Hour), // Very old
		retryCount: 0,
	}

	// Check retransmissions - should skip due to zero RTO
	err := s.checkRetransmissions()
	require.NoError(t, err)

	// Verify packet was not retransmitted
	assert.Equal(t, 0, s.sentPackets[5].retryCount)
}

// TestSentTimeUpdate verifies that sentTime is updated after retransmission
func TestSentTimeUpdate(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set RTO
	s.rto = 50 * time.Millisecond

	// Record initial time
	initialTime := time.Now().Add(-100 * time.Millisecond)
	s.sentPackets[5] = &sentPacket{
		data:       []byte{1, 2, 3, 4},
		sentTime:   initialTime,
		retryCount: 0,
	}

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Check retransmissions
	err := s.checkRetransmissions()
	require.NoError(t, err)

	// Verify sentTime was updated (should be more recent than initial)
	assert.True(t, s.sentPackets[5].sentTime.After(initialTime),
		"sentTime should be updated after retransmission")
}

// TestRetransmissionWithPartialFailure verifies that one failed retransmission doesn't stop others
func TestRetransmissionWithPartialFailure(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set RTO
	s.rto = 50 * time.Millisecond

	// Add multiple timed-out packets
	// Note: retransmitPacketLocked will fail for all since there's no session,
	// but we verify the function continues processing all packets
	s.sentPackets[5] = &sentPacket{
		data:       []byte{1, 2, 3, 4},
		sentTime:   time.Now().Add(-100 * time.Millisecond),
		retryCount: 0,
	}
	s.sentPackets[6] = &sentPacket{
		data:       []byte{5, 6, 7, 8},
		sentTime:   time.Now().Add(-100 * time.Millisecond),
		retryCount: 0,
	}

	// Check retransmissions - should not return error even if retransmits fail
	err := s.checkRetransmissions()
	require.NoError(t, err, "Should continue even if individual retransmissions fail")

	// Verify both packets had retry counts incremented
	assert.Equal(t, 1, s.sentPackets[5].retryCount)
	assert.Equal(t, 1, s.sentPackets[6].retryCount)
}

// TestRetransmitTimerIntegration tests the full timer goroutine (integration test)
func TestRetransmitTimerIntegration(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set a short RTO for fast testing
	s.rto = 50 * time.Millisecond

	// Add a packet that will timeout
	s.sentPackets[5] = &sentPacket{
		data:       []byte{1, 2, 3, 4},
		sentTime:   time.Now(),
		retryCount: 0,
	}

	// Start the retransmit timer
	go s.retransmitTimer()

	// Wait for timeout to occur (RTO + check interval + margin)
	time.Sleep(200 * time.Millisecond)

	// Verify packet was retransmitted
	s.mu.Lock()
	retryCount := s.sentPackets[5].retryCount
	s.mu.Unlock()

	assert.Greater(t, retryCount, 0, "Packet should have been retransmitted")
}

// TestRetransmitTimerStopsOnClose verifies timer goroutine exits when connection closes
func TestRetransmitTimerStopsOnClose(t *testing.T) {
	s := newTestStreamConnForTimeout()

	// Start the retransmit timer
	done := make(chan bool)
	go func() {
		s.retransmitTimer()
		done <- true
	}()

	// Close the connection
	s.Close()

	// Wait for timer to exit (with timeout to prevent test hanging)
	select {
	case <-done:
		// Success - timer exited
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Retransmit timer did not stop after connection close")
	}
}

// TestRetryCountProgression verifies retry count increases correctly over multiple timeouts
func TestRetryCountProgression(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set a short RTO
	s.rto = 10 * time.Millisecond

	// Add a packet
	s.sentPackets[5] = &sentPacket{
		data:       []byte{1, 2, 3, 4},
		sentTime:   time.Now().Add(-20 * time.Millisecond),
		retryCount: 0,
	}

	// First timeout
	err := s.checkRetransmissions()
	require.NoError(t, err)
	assert.Equal(t, 1, s.sentPackets[5].retryCount)

	// Update sent time and check again
	s.sentPackets[5].sentTime = time.Now().Add(-30 * time.Millisecond)
	err = s.checkRetransmissions()
	require.NoError(t, err)
	assert.Equal(t, 2, s.sentPackets[5].retryCount)

	// Update sent time and check again
	s.sentPackets[5].sentTime = time.Now().Add(-50 * time.Millisecond)
	err = s.checkRetransmissions()
	require.NoError(t, err)
	assert.Equal(t, 3, s.sentPackets[5].retryCount)
}
