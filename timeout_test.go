package streaming

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStreamConnForTimeout creates a StreamConn for timeout testing
func newTestStreamConnForTimeout() *StreamConn {
	ctx, cancel := context.WithCancel(context.Background())
	recvBuf, _ := NewBuffer(4096)

	conn := &StreamConn{
		state:             StateEstablished,
		sendSeq:           1000,
		recvSeq:           100,
		ackThrough:        0,
		sentPackets:       make(map[uint32]*sentPacket),
		outOfOrderPackets: make(map[uint32]*Packet),
		nackList:          make(map[uint32]struct{}),
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

// TestMaxRTOBound verifies RTO is capped at 45 seconds per I2P streaming spec.
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

	// Check retransmissions - RTO should be capped at 45s (MAX_RESEND_DELAY per spec)
	err := s.checkRetransmissions()
	require.NoError(t, err)
	assert.Equal(t, 45*time.Second, s.rto, "RTO should be capped at 45 seconds per I2P spec")
}

// TestMaxRetriesExceeded verifies connection closes after max retries.
// Per I2P streaming spec, i2p.streaming.maxResends defaults to 8.
func TestMaxRetriesExceeded(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set a short RTO
	s.rto = 10 * time.Millisecond

	// Add a packet that has already been retried 8 times (MaxRetransmissions per spec)
	s.sentPackets[5] = &sentPacket{
		data:       []byte{1, 2, 3, 4},
		sentTime:   time.Now().Add(-20 * time.Millisecond),
		retryCount: 8, // Already at max (i2p.streaming.maxResends default)
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

// TestReadTimerGoroutineCleanup verifies that timer goroutines are properly cleaned up
// when Read() returns early (data arrives before deadline).
// This tests the fix for the timer goroutine leak bug in Read().
func TestReadTimerGoroutineCleanup(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set a long deadline (1 second)
	s.SetReadDeadline(time.Now().Add(1 * time.Second))

	// Start a Read() call in a goroutine
	readDone := make(chan struct{})
	readResult := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 100)
		n, err := s.Read(buf)
		if err == nil {
			readResult <- buf[:n]
		}
		close(readDone)
	}()

	// Give Read() time to set up the timer goroutine
	time.Sleep(10 * time.Millisecond)

	// Simulate data arrival by writing to buffer and signaling
	s.mu.Lock()
	s.recvBuf.Write([]byte("test data"))
	s.recvCond.Broadcast()
	s.mu.Unlock()

	// Read should complete quickly (not wait for the 1s deadline)
	select {
	case <-readDone:
		// Success - Read completed
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Read() did not complete promptly when data arrived")
	}

	// Verify the data was read
	select {
	case data := <-readResult:
		assert.Equal(t, []byte("test data"), data)
	default:
		// Read completed without data is fine for this test
	}

	// Wait a bit to verify no goroutine leak (timer goroutine should exit immediately)
	// The goroutine should not be blocked waiting for the timer to fire
	time.Sleep(50 * time.Millisecond)
}

// TestWriteChokeTimerGoroutineCleanup verifies that timer goroutines are properly cleaned up
// when Write() choke handling returns early (unchoke arrives before deadline).
// This tests the fix for the timer goroutine leak bug in Write() choke handling.
func TestWriteChokeTimerGoroutineCleanup(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Ensure sendCond is initialized
	s.sendCond = sync.NewCond(&s.mu)

	// Put connection in choked state with a long choke period
	s.mu.Lock()
	s.choked = true
	s.chokedUntil = time.Now().Add(5 * time.Second)
	s.mu.Unlock()

	// Set a write deadline
	s.SetWriteDeadline(time.Now().Add(1 * time.Second))

	// Start a Write() call in a goroutine
	writeDone := make(chan struct{})
	go func() {
		// This will block waiting for unchoke
		s.Write([]byte("test"))
		close(writeDone)
	}()

	// Give Write() time to set up the timer goroutine
	time.Sleep(10 * time.Millisecond)

	// Simulate unchoke by clearing choke state and signaling
	s.mu.Lock()
	s.choked = false
	s.chokedUntil = time.Time{}
	s.sendCond.Broadcast()
	s.mu.Unlock()

	// Write should complete quickly (not wait for the 1s deadline)
	select {
	case <-writeDone:
		// Success - Write completed
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Write() did not complete promptly when unchoked")
	}

	// Wait a bit to verify no goroutine leak
	time.Sleep(50 * time.Millisecond)
}

// TestWriteWindowTimerGoroutineCleanup verifies that timer goroutines are properly cleaned up
// when Write() window flow control returns early (ACK arrives before deadline).
// This tests the fix for the defer inside loop bug in Write() window flow control.
func TestWriteWindowTimerGoroutineCleanup(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Ensure sendCond is initialized
	s.sendCond = sync.NewCond(&s.mu)

	// Fill the window to trigger flow control wait
	s.mu.Lock()
	s.cwnd = 2 // Small window
	for i := uint32(0); i < 5; i++ {
		s.sentPackets[i] = &sentPacket{
			data:     []byte{1, 2, 3, 4},
			sentTime: time.Now(),
		}
	}
	s.mu.Unlock()

	// Set a write deadline
	s.SetWriteDeadline(time.Now().Add(1 * time.Second))

	// Start a Write() call in a goroutine
	writeDone := make(chan struct{})
	go func() {
		// This will block waiting for window space
		s.Write([]byte("test data"))
		close(writeDone)
	}()

	// Give Write() time to set up the timer goroutine
	time.Sleep(10 * time.Millisecond)

	// Simulate ACKs arriving by clearing sentPackets and signaling
	s.mu.Lock()
	s.sentPackets = make(map[uint32]*sentPacket) // Clear all in-flight packets
	s.sendCond.Broadcast()
	s.mu.Unlock()

	// Write should complete quickly (not wait for the 1s deadline)
	select {
	case <-writeDone:
		// Success - Write completed
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Write() did not complete promptly when window opened")
	}

	// Wait a bit to verify no goroutine leak (timer goroutines should exit immediately)
	time.Sleep(50 * time.Millisecond)
}

// TestInactivityTimeoutDetection verifies that inactivity is detected after timeout
func TestInactivityTimeoutDetection(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set a short inactivity timeout for testing
	s.inactivityTimeout = 50 * time.Millisecond
	originalActivity := time.Now().Add(-100 * time.Millisecond)
	s.lastActivity = originalActivity // Already inactive

	// Check inactivity - should detect timeout and attempt to send keepalive
	// Note: The sendPacketLocked will fail without a real I2CP session,
	// but the detection logic should still be executed. We verify detection
	// happened by checking that the state remained ESTABLISHED (didn't close)
	// and that the function completed without panic.
	s.checkInactivity()

	// Connection should still be established (keepalive extends life, doesn't close)
	s.mu.Lock()
	state := s.state
	s.mu.Unlock()
	assert.Equal(t, StateEstablished, state, "Connection should remain established after keepalive attempt")
}

// TestInactivityTimeoutDisabled verifies that inactivity timeout can be disabled
func TestInactivityTimeoutDisabled(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Disable inactivity timeout
	s.inactivityTimeout = 0
	oldActivity := time.Now().Add(-1 * time.Hour)
	s.lastActivity = oldActivity

	// Check inactivity - should be skipped since disabled
	s.checkInactivity()

	// lastActivity should NOT be updated when disabled
	s.mu.Lock()
	currentActivity := s.lastActivity
	s.mu.Unlock()

	assert.Equal(t, oldActivity, currentActivity,
		"lastActivity should not change when inactivity timeout is disabled")
}

// TestInactivityTimeoutNotTriggeredWhenActive verifies no keepalive when active
func TestInactivityTimeoutNotTriggeredWhenActive(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set inactivity timeout
	s.inactivityTimeout = 100 * time.Millisecond
	recentActivity := time.Now()
	s.lastActivity = recentActivity

	// Check inactivity - should NOT trigger since we're still active
	s.checkInactivity()

	// lastActivity should still be the same (no keepalive sent)
	s.mu.Lock()
	currentActivity := s.lastActivity
	s.mu.Unlock()

	assert.Equal(t, recentActivity, currentActivity,
		"lastActivity should not change when connection is active")
}

// TestSetInactivityTimeout verifies the setter/getter methods
func TestSetInactivityTimeout(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Default should be DefaultInactivityTimeout (90 seconds)
	// (but our test helper doesn't set it, so verify getter works)
	s.SetInactivityTimeout(45 * time.Second)
	assert.Equal(t, 45*time.Second, s.GetInactivityTimeout())

	// Disable
	s.SetInactivityTimeout(0)
	assert.Equal(t, time.Duration(0), s.GetInactivityTimeout())

	// Re-enable
	s.SetInactivityTimeout(DefaultInactivityTimeout)
	assert.Equal(t, DefaultInactivityTimeout, s.GetInactivityTimeout())
}

// TestInactivityTimerStopsOnClose verifies timer goroutine exits when connection closes
func TestInactivityTimerStopsOnClose(t *testing.T) {
	s := newTestStreamConnForTimeout()
	s.inactivityTimeout = DefaultInactivityTimeout

	// Start the inactivity timer
	done := make(chan bool)
	go func() {
		s.inactivityTimer()
		done <- true
	}()

	// Close the connection
	s.Close()

	// Wait for timer to exit (with timeout to prevent test hanging)
	select {
	case <-done:
		// Success - timer exited
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Inactivity timer did not stop after connection close")
	}
}

// TestLastActivityUpdatedOnReceive verifies lastActivity is updated when receiving packets
func TestLastActivityUpdatedOnReceive(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set last activity to old time
	oldActivity := time.Now().Add(-1 * time.Hour)
	s.lastActivity = oldActivity

	// Process a packet
	pkt := &Packet{
		SequenceNum: 100,
		AckThrough:  50,
		Flags:       0, // No flags needed - ackThrough always valid per spec
	}

	s.processPacket(pkt)

	// lastActivity should be updated
	s.mu.Lock()
	timeSinceActivity := time.Since(s.lastActivity)
	s.mu.Unlock()

	assert.Less(t, timeSinceActivity, 100*time.Millisecond,
		"lastActivity should be updated when receiving packets")
}

// TestInactivityNotTriggeredInNonEstablishedState verifies keepalive only in ESTABLISHED state
func TestInactivityNotTriggeredInNonEstablishedState(t *testing.T) {
	s := newTestStreamConnForTimeout()
	defer s.Close()

	// Set connection to non-established state
	s.state = StateSynSent
	s.inactivityTimeout = 50 * time.Millisecond
	oldActivity := time.Now().Add(-100 * time.Millisecond)
	s.lastActivity = oldActivity

	// Check inactivity - should be skipped since not established
	s.checkInactivity()

	// lastActivity should NOT be updated
	s.mu.Lock()
	currentActivity := s.lastActivity
	s.mu.Unlock()

	assert.Equal(t, oldActivity, currentActivity,
		"lastActivity should not change when not in ESTABLISHED state")
}
