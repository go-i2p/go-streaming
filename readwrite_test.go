package streaming

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/armon/circbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestHandleIncomingPacket_InvalidSequence tests dropping out-of-order packets
func TestHandleIncomingPacket_InvalidSequence(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	conn.mu.Lock()
	expectedSeq := conn.recvSeq
	conn.mu.Unlock()

	// Send packet with wrong sequence number
	pkt := &Packet{
		SendStreamID: uint32(conn.remotePort),
		RecvStreamID: uint32(conn.localPort),
		SequenceNum:  expectedSeq + 100, // Wrong sequence
		AckThrough:   0,
		Flags:        FlagACK,
		Payload:      []byte("test data"),
	}

	// Call processPacket directly (unit test - no receiveLoop)
	err := conn.processPacket(pkt)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sequence mismatch")

	// Verify no data in receive buffer
	conn.mu.Lock()
	assert.Equal(t, int64(0), conn.recvBuf.TotalWritten())
	assert.Equal(t, expectedSeq, conn.recvSeq) // Sequence unchanged
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

// Helper functions

// createTestConnection creates a StreamConn for testing
func createTestConnection(t *testing.T) *StreamConn {
	recvBuf, err := circbuf.NewBuffer(64 * 1024)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	conn := &StreamConn{
		session:    nil, // MVP: No mock session for basic tests
		dest:       nil,
		localPort:  12345,
		remotePort: 80,
		sendSeq:    generateTestISN(),
		recvSeq:    100,
		windowSize: DefaultWindowSize,
		rtt:        8 * time.Second,
		rto:        9 * time.Second,
		recvBuf:    recvBuf,
		recvChan:   make(chan *Packet, 32),
		errChan:    make(chan error, 1),
		ctx:        ctx,
		cancel:     cancel,
		state:      StateEstablished,
		localMTU:   DefaultMTU,
		remoteMTU:  DefaultMTU,
	}
	conn.recvCond = sync.NewCond(&conn.mu)

	return conn
}

// generateTestISN generates a fixed ISN for testing
func generateTestISN() uint32 {
	return 1000
}
