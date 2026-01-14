package streaming

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestWrite_SinglePacket tests writing data that fits in one packet
func TestWrite_SinglePacket(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	data := []byte("hello world")
	n, err := conn.Write(data)

	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	// Sequence number should increment by 1 (one packet sent)
	assert.Equal(t, uint32(1), conn.sendSeq-generateTestISN())
	// Byte tracking should match data length
	assert.Equal(t, uint64(len(data)), conn.totalBytesSent)
}

// TestWrite_MultiplePackets tests writing data that requires chunking
func TestWrite_MultiplePackets(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Create data larger than MTU
	mtu := int(conn.getNegotiatedMTULocked())
	data := bytes.Repeat([]byte("x"), mtu*2+100)

	n, err := conn.Write(data)

	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	// Sequence number should increment by 3 (three packets sent: mtu, mtu, 100)
	assert.Equal(t, uint32(3), conn.sendSeq-generateTestISN())
	// Byte tracking should match data length
	assert.Equal(t, uint64(len(data)), conn.totalBytesSent)
}

// TestWrite_EmptyData tests writing empty data
func TestWrite_EmptyData(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	data := []byte{}
	n, err := conn.Write(data)

	assert.NoError(t, err)
	assert.Equal(t, 0, n)
}

// TestWrite_ClosedConnection tests writing to a closed connection
func TestWrite_ClosedConnection(t *testing.T) {
	conn := createTestConnection(t)
	conn.Close()

	data := []byte("test")
	n, err := conn.Write(data)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection closed")
	assert.Equal(t, 0, n)
}

// TestWrite_NotEstablished tests writing when connection is not established
func TestWrite_NotEstablished(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Set state to non-established
	conn.mu.Lock()
	conn.state = StateSynSent
	conn.mu.Unlock()

	data := []byte("test")
	n, err := conn.Write(data)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection not established")
	assert.Equal(t, 0, n)
}

// TestRead_BlocksUntilDataAvailable tests that Read blocks when no data
func TestRead_BlocksUntilDataAvailable(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	buf := make([]byte, 100)
	done := make(chan bool)

	// Start read in goroutine
	go func() {
		n, err := conn.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, "hello", string(buf[:n]))
		done <- true
	}()

	// Give it time to block
	time.Sleep(50 * time.Millisecond)

	// Now add data to the receive buffer
	conn.mu.Lock()
	conn.recvBuf.Write([]byte("hello"))
	conn.recvCond.Broadcast()
	conn.mu.Unlock()

	// Wait for read to complete
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Read did not complete after data was added")
	}
}

// TestRead_MultipleReads tests reading data in chunks
func TestRead_MultipleReads(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Add data to receive buffer
	testData := []byte("hello world this is a test")
	conn.mu.Lock()
	conn.recvBuf.Write(testData)
	conn.mu.Unlock()

	// First read - partial
	buf1 := make([]byte, 5)
	n1, err := conn.Read(buf1)
	assert.NoError(t, err)
	assert.Equal(t, 5, n1)
	assert.Equal(t, "hello", string(buf1))

	// Second read - rest
	buf2 := make([]byte, 100)
	n2, err := conn.Read(buf2)
	assert.NoError(t, err)
	assert.Equal(t, len(testData)-5, n2)
	assert.Equal(t, " world this is a test", string(buf2[:n2]))
}

// TestRead_ClosedConnection tests reading from a closed connection
func TestRead_ClosedConnection(t *testing.T) {
	conn := createTestConnection(t)
	conn.Close()

	buf := make([]byte, 100)
	n, err := conn.Read(buf)

	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, 0, n)
}

// TestHandleIncomingPacket_ValidSequence tests processing a valid packet
func TestHandleIncomingPacket_ValidSequence(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	conn.mu.Lock()
	expectedSeq := conn.recvSeq
	conn.mu.Unlock()

	pkt := &Packet{
		SendStreamID: uint32(conn.remotePort),
		RecvStreamID: uint32(conn.localPort),
		SequenceNum:  expectedSeq,
		AckThrough:   0,
		Flags:        FlagACK,
		Payload:      []byte("test data"),
	}

	// Call processPacket directly (unit test - no receiveLoop)
	err := conn.processPacket(pkt)
	assert.NoError(t, err)

	// Verify data is in receive buffer
	conn.mu.Lock()
	data := conn.recvBuf.Bytes()
	recvSeq := conn.recvSeq
	totalBytesReceived := conn.totalBytesReceived
	conn.mu.Unlock()

	assert.Equal(t, "test data", string(data))
	// Sequence number should increment by 1 (one packet received)
	assert.Equal(t, expectedSeq+1, recvSeq)
	// Byte tracking should match payload length
	assert.Equal(t, uint64(len(pkt.Payload)), totalBytesReceived)
}

// TestHandleIncomingPacket_InvalidSequence tests buffering out-of-order packets
func TestHandleIncomingPacket_InvalidSequence(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	conn.mu.Lock()
	expectedSeq := conn.recvSeq
	conn.mu.Unlock()

	// Send packet with wrong sequence number (future packet)
	pkt := &Packet{
		SendStreamID: uint32(conn.remotePort),
		RecvStreamID: uint32(conn.localPort),
		SequenceNum:  expectedSeq + 5, // Future packet
		AckThrough:   0,
		Flags:        FlagACK,
		Payload:      []byte("test data"),
	}

	// Call processPacket directly (unit test - no receiveLoop)
	err := conn.processPacket(pkt)
	// No error expected - packet should be buffered
	assert.NoError(t, err)

	// Verify packet was buffered (not delivered yet)
	conn.mu.Lock()
	assert.Equal(t, int64(0), conn.recvBuf.TotalWritten(), "no data delivered until gap filled")
	assert.Equal(t, expectedSeq, conn.recvSeq, "sequence unchanged until gap filled")
	assert.Equal(t, 1, len(conn.outOfOrderPackets), "packet should be buffered")
	_, buffered := conn.outOfOrderPackets[expectedSeq+5]
	assert.True(t, buffered, "future packet should be in buffer")

	// Verify NACK list contains missing sequences
	assert.Greater(t, len(conn.nackList), 0, "should have NACKs for missing packets")
	conn.mu.Unlock()
}

// TestHandleIncomingPacket_UpdatesAckThrough tests ACK processing
func TestHandleIncomingPacket_UpdatesAckThrough(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	conn.mu.Lock()
	expectedSeq := conn.recvSeq
	oldAckThrough := conn.ackThrough
	conn.mu.Unlock()

	pkt := &Packet{
		SendStreamID: uint32(conn.remotePort),
		RecvStreamID: uint32(conn.localPort),
		SequenceNum:  expectedSeq,
		AckThrough:   42, // Remote acknowledges our seq 42
		Flags:        FlagACK,
		Payload:      nil,
	}

	// Call processPacket directly (unit test - no receiveLoop)
	err := conn.processPacket(pkt)
	assert.NoError(t, err)

	conn.mu.Lock()
	assert.Equal(t, uint32(42), conn.ackThrough)
	assert.NotEqual(t, oldAckThrough, conn.ackThrough)
	conn.mu.Unlock()
}

// TestSendPacketLocked_ValidPacket tests sending a packet
func TestSendPacketLocked_ValidPacket(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	pkt := &Packet{
		SendStreamID: uint32(conn.localPort),
		RecvStreamID: uint32(conn.remotePort),
		SequenceNum:  100,
		AckThrough:   50,
		Flags:        FlagACK,
		Payload:      []byte("test"),
	}

	conn.mu.Lock()
	err := conn.sendPacketLocked(pkt)
	conn.mu.Unlock()

	// MVP: With nil session, send is skipped (returns nil)
	assert.NoError(t, err)
}

// TestGetNegotiatedMTULocked tests MTU negotiation logic
func TestGetNegotiatedMTULocked(t *testing.T) {
	tests := []struct {
		name      string
		localMTU  uint16
		remoteMTU uint16
		expected  uint16
	}{
		{"local smaller", 1000, 1500, 1000},
		{"remote smaller", 1500, 1000, 1000},
		{"equal", 1730, 1730, 1730},
		{"remote not set", 1730, 0, 1730},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := createTestConnection(t)
			defer conn.Close()

			conn.mu.Lock()
			conn.localMTU = tt.localMTU
			conn.remoteMTU = tt.remoteMTU
			result := conn.getNegotiatedMTULocked()
			conn.mu.Unlock()

			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestClose_Idempotent tests that calling Close multiple times is safe
func TestClose_Idempotent(t *testing.T) {
	conn := createTestConnection(t)

	err1 := conn.Close()
	assert.NoError(t, err1)

	err2 := conn.Close()
	assert.NoError(t, err2)

	assert.True(t, conn.closed)
}

// TestClose_WakesBlockedReaders tests that Close wakes up blocked Read calls
func TestClose_WakesBlockedReaders(t *testing.T) {
	conn := createTestConnection(t)

	done := make(chan bool)
	buf := make([]byte, 100)

	// Start blocked read
	go func() {
		_, err := conn.Read(buf)
		assert.ErrorIs(t, err, io.EOF)
		done <- true
	}()

	// Give it time to block
	time.Sleep(50 * time.Millisecond)

	// Close connection
	conn.Close()

	// Wait for read to complete
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Read did not unblock after Close")
	}
}

// TestWrite_RespectsWriteDeadline tests that Write respects write deadline
func TestWrite_RespectsWriteDeadline(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Set a write deadline in the past
	conn.SetWriteDeadline(time.Now().Add(-1 * time.Second))

	data := []byte("test")
	n, err := conn.Write(data)

	// Should return timeout error
	assert.Error(t, err)
	assert.Equal(t, 0, n)
	// Check it's a timeout error
	var timeoutErr *timeoutError
	assert.ErrorAs(t, err, &timeoutErr)
}

// TestWrite_DeadlineExpiresDuringChoke tests that Write respects deadline while waiting for choke to expire
func TestWrite_DeadlineExpiresDuringChoke(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Set connection to choked state
	conn.mu.Lock()
	conn.choked = true
	conn.chokedUntil = time.Now().Add(2 * time.Second)
	conn.mu.Unlock()

	// Set write deadline to expire before choke expires
	conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))

	data := []byte("test")
	start := time.Now()
	n, err := conn.Write(data)
	elapsed := time.Since(start)

	// Should return timeout error quickly (not wait 2 seconds for choke)
	assert.Error(t, err)
	assert.Equal(t, 0, n)
	var timeoutErr *timeoutError
	assert.ErrorAs(t, err, &timeoutErr)

	// Verify it returned quickly (less than 500ms, not 2 seconds)
	assert.Less(t, elapsed, 500*time.Millisecond)
}

// TestWrite_DeadlineExpiresDuringFlowControl tests that Write respects deadline during flow control wait
func TestWrite_DeadlineExpiresDuringFlowControl(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Set up flow control scenario: fill the congestion window
	conn.mu.Lock()
	// Create a full congestion window of packets
	conn.sentPackets = make(map[uint32]*sentPacket)
	for i := 0; i < int(conn.cwnd); i++ {
		conn.sentPackets[uint32(i)] = &sentPacket{
			data:       []byte{1, 2, 3},
			sentTime:   time.Now(),
			retryCount: 0,
		}
	}
	conn.mu.Unlock()

	// Set write deadline to expire very soon
	conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))

	data := make([]byte, 1000)
	start := time.Now()
	_, err := conn.Write(data)
	elapsed := time.Since(start)

	// Should return timeout error
	assert.Error(t, err)
	var timeoutErr *timeoutError
	assert.ErrorAs(t, err, &timeoutErr)

	// Should return quickly (within 200ms tolerance)
	assert.Less(t, elapsed, 200*time.Millisecond)
}

// TestWrite_ZeroDeadlineNeverExpires tests that zero deadline means no timeout
func TestWrite_ZeroDeadlineNeverExpires(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Set zero deadline (no timeout)
	conn.SetWriteDeadline(time.Time{})

	// This should not timeout even though we're writing to a non-drained connection
	data := []byte("test")
	n, err := conn.Write(data)

	// Should succeed
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
}

// TestWrite_ChokeTimerCleanup verifies that timers are properly cleaned up
// when Write() exits due to unchoke or connection close, preventing goroutine leaks
func TestWrite_ChokeTimerCleanup(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Set up choke that will expire very soon
	conn.mu.Lock()
	conn.choked = true
	conn.chokedUntil = time.Now().Add(50 * time.Millisecond)
	conn.mu.Unlock()

	// Write should block briefly during choke, then succeed
	data := []byte("test")
	start := time.Now()
	n, err := conn.Write(data)
	elapsed := time.Since(start)

	// Should succeed after choke period
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)

	// Verify we actually waited (but not too long)
	assert.Greater(t, elapsed, 40*time.Millisecond)
	assert.Less(t, elapsed, 500*time.Millisecond)

	// Give time for any lingering goroutines to finish
	time.Sleep(100 * time.Millisecond)
}

// TestRead_TimerCleanupMultipleWaits verifies that Read() timers are properly
// cleaned up on each Wait() call, preventing timer accumulation
func TestRead_TimerCleanupMultipleWaits(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Set a read deadline
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

	// Start a goroutine to write data after a delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		conn.mu.Lock()
		_, _ = conn.recvBuf.Write([]byte("first"))
		conn.recvCond.Broadcast()
		conn.mu.Unlock()

		time.Sleep(50 * time.Millisecond)
		conn.mu.Lock()
		_, _ = conn.recvBuf.Write([]byte("second"))
		conn.recvCond.Broadcast()
		conn.mu.Unlock()

		time.Sleep(50 * time.Millisecond)
		conn.mu.Lock()
		_, _ = conn.recvBuf.Write([]byte("third"))
		conn.recvCond.Broadcast()
		conn.mu.Unlock()
	}()

	// Multiple reads should succeed with proper timer cleanup
	buf1 := make([]byte, 10)
	n1, err1 := conn.Read(buf1)
	assert.NoError(t, err1)
	assert.Equal(t, 5, n1)
	assert.Equal(t, "first", string(buf1[:n1]))

	buf2 := make([]byte, 10)
	n2, err2 := conn.Read(buf2)
	assert.NoError(t, err2)
	assert.Equal(t, 6, n2)
	assert.Equal(t, "second", string(buf2[:n2]))

	buf3 := make([]byte, 10)
	n3, err3 := conn.Read(buf3)
	assert.NoError(t, err3)
	assert.Equal(t, 5, n3)
	assert.Equal(t, "third", string(buf3[:n3]))
}

// TestRead_DeadlineExpiresDuringFirstWait verifies that deadlines work correctly
// even when the Read() method needs to wait for data
func TestRead_DeadlineExpiresDuringFirstWait(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Set a very short read deadline
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	// Read should timeout waiting for data
	buf := make([]byte, 10)
	n, err := conn.Read(buf)

	// Should timeout
	assert.Error(t, err)
	assert.Equal(t, 0, n)
	if netErr, ok := err.(net.Error); ok {
		assert.True(t, netErr.Timeout(), "error should be a timeout error")
	}
}

// TestWrite_ChokeWithoutDeadlineTimerCleanup verifies that Write() correctly
// handles the choke expiration timer (non-deadline case) and cleans up properly
func TestWrite_ChokeWithoutDeadlineTimerCleanup(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Choke for a short period with no write deadline
	conn.mu.Lock()
	conn.choked = true
	conn.chokedUntil = time.Now().Add(75 * time.Millisecond)
	conn.mu.Unlock()

	data := []byte("data")
	start := time.Now()
	n, err := conn.Write(data)
	elapsed := time.Since(start)

	// Should succeed after choke expires
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)

	// Verify we waited for the choke period
	assert.Greater(t, elapsed, 60*time.Millisecond)
	assert.Less(t, elapsed, 500*time.Millisecond)

	// Give goroutines time to finish
	time.Sleep(100 * time.Millisecond)
}

// Helper functions

// createTestConnection creates a StreamConn for testing with real I2CP
func createTestConnection(t *testing.T) *StreamConn {
	return CreateTestStreamConn(t)
}

// generateTestISN generates a fixed ISN for testing
func generateTestISN() uint32 {
	return GenerateTestISN()
}
