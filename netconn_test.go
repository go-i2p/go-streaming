package streaming

import (
	"io"
	"net"
	"testing"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createMockSession creates a minimal mock session for testing.
// This is needed because Listen() requires a non-nil session.
// For unit tests, we don't actually use the session, we just need it to exist.
func createMockSession() *go_i2cp.Session {
	// Create a client with empty callbacks
	client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})

	// Create session with empty callbacks
	callbacks := go_i2cp.SessionCallbacks{}
	session := go_i2cp.NewSession(client, callbacks)

	return session
}

// TestI2PAddr_Network tests I2PAddr.Network() method
func TestI2PAddr_Network(t *testing.T) {
	addr := &I2PAddr{port: 8080}
	assert.Equal(t, "i2p", addr.Network())
}

// TestI2PAddr_String tests I2PAddr.String() method
func TestI2PAddr_String(t *testing.T) {
	tests := []struct {
		name     string
		addr     *I2PAddr
		expected string
	}{
		{
			name:     "nil destination",
			addr:     &I2PAddr{dest: nil, port: 8080},
			expected: "*:8080",
		},
		{
			name:     "with destination",
			addr:     &I2PAddr{dest: &go_i2cp.Destination{}, port: 443},
			expected: "i2p:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.addr.String())
		})
	}
}

// TestI2PAddr_ImplementsNetAddr verifies I2PAddr implements net.Addr
func TestI2PAddr_ImplementsNetAddr(t *testing.T) {
	var _ net.Addr = &I2PAddr{}
}

// TestStreamConn_LocalAddr tests LocalAddr() method
func TestStreamConn_LocalAddr(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	addr := conn.LocalAddr()
	require.NotNil(t, addr)

	i2pAddr, ok := addr.(*I2PAddr)
	require.True(t, ok, "LocalAddr should return *I2PAddr")
	assert.Equal(t, conn.localPort, i2pAddr.port)
	assert.Equal(t, "i2p", i2pAddr.Network())
}

// TestStreamConn_RemoteAddr tests RemoteAddr() method
func TestStreamConn_RemoteAddr(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	addr := conn.RemoteAddr()
	require.NotNil(t, addr)

	i2pAddr, ok := addr.(*I2PAddr)
	require.True(t, ok, "RemoteAddr should return *I2PAddr")
	assert.Equal(t, conn.remotePort, i2pAddr.port)
	assert.Equal(t, "i2p", i2pAddr.Network())
}

// TestStreamConn_ImplementsNetConn verifies StreamConn implements net.Conn
func TestStreamConn_ImplementsNetConn(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	var _ net.Conn = conn
	var _ io.Reader = conn
	var _ io.Writer = conn
	var _ io.Closer = conn
}

// TestStreamConn_SetDeadline tests SetDeadline() method
func TestStreamConn_SetDeadline(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	err := conn.SetDeadline(deadline)
	assert.NoError(t, err)

	conn.mu.Lock()
	assert.Equal(t, deadline, conn.readDeadline)
	assert.Equal(t, deadline, conn.writeDeadline)
	conn.mu.Unlock()
}

// TestStreamConn_SetReadDeadline tests SetReadDeadline() method
func TestStreamConn_SetReadDeadline(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	err := conn.SetReadDeadline(deadline)
	assert.NoError(t, err)

	conn.mu.Lock()
	assert.Equal(t, deadline, conn.readDeadline)
	// Write deadline should not be affected
	assert.True(t, conn.writeDeadline.IsZero())
	conn.mu.Unlock()
}

// TestStreamConn_SetWriteDeadline tests SetWriteDeadline() method
func TestStreamConn_SetWriteDeadline(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	err := conn.SetWriteDeadline(deadline)
	assert.NoError(t, err)

	conn.mu.Lock()
	assert.Equal(t, deadline, conn.writeDeadline)
	// Read deadline should not be affected
	assert.True(t, conn.readDeadline.IsZero())
	conn.mu.Unlock()
}

// TestStreamConn_ReadDeadlineTimeout tests that Read times out when deadline expires
func TestStreamConn_ReadDeadlineTimeout(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Set deadline to past (immediate timeout)
	err := conn.SetReadDeadline(time.Now().Add(-1 * time.Second))
	assert.NoError(t, err)

	buf := make([]byte, 100)
	n, readErr := conn.Read(buf)

	assert.Equal(t, 0, n)
	assert.Error(t, readErr)

	// Check that error is a timeout error
	if netErr, ok := readErr.(net.Error); ok {
		assert.True(t, netErr.Timeout(), "error should be a timeout")
	} else {
		t.Error("error should implement net.Error interface")
	}
}

// TestStreamConn_ReadDeadlineFutureTimeout tests Read with future deadline
func TestStreamConn_ReadDeadlineFutureTimeout(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Set deadline to 100ms in future
	err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	assert.NoError(t, err)

	start := time.Now()
	buf := make([]byte, 100)
	n, readErr := conn.Read(buf)
	elapsed := time.Since(start)

	assert.Equal(t, 0, n)
	assert.Error(t, readErr)
	assert.True(t, elapsed >= 100*time.Millisecond, "should wait for deadline")
	assert.True(t, elapsed < 200*time.Millisecond, "should not wait too long")

	// Check that error is a timeout error
	if netErr, ok := readErr.(net.Error); ok {
		assert.True(t, netErr.Timeout())
	}
}

// TestStreamConn_ReadDeadlineZeroNoTimeout tests that zero deadline means no timeout
func TestStreamConn_ReadDeadlineZeroNoTimeout(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Set deadline to zero (no timeout)
	err := conn.SetReadDeadline(time.Time{})
	assert.NoError(t, err)

	// Add data in background after small delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		conn.mu.Lock()
		conn.recvBuf.Write([]byte("test"))
		conn.recvCond.Broadcast()
		conn.mu.Unlock()
	}()

	buf := make([]byte, 100)
	n, readErr := conn.Read(buf)

	assert.NoError(t, readErr)
	assert.Equal(t, 4, n)
	assert.Equal(t, "test", string(buf[:n]))
}

// TestStreamConn_ReadReturnsEOFOnClose tests that Read returns io.EOF when closed
func TestStreamConn_ReadReturnsEOFOnClose(t *testing.T) {
	conn := createTestConnection(t)
	conn.Close()

	buf := make([]byte, 100)
	n, err := conn.Read(buf)

	assert.Equal(t, 0, n)
	assert.Equal(t, io.EOF, err, "should return io.EOF on closed connection")
}

// TestStreamConn_CloseWakesBlockedReaders tests that Close wakes blocked Read
func TestStreamConn_CloseWakesBlockedReaders(t *testing.T) {
	conn := createTestConnection(t)

	done := make(chan error, 1)

	// Start blocked read
	go func() {
		buf := make([]byte, 100)
		_, err := conn.Read(buf)
		done <- err
	}()

	// Give it time to block
	time.Sleep(50 * time.Millisecond)

	// Close connection
	conn.Close()

	// Wait for read to complete
	select {
	case err := <-done:
		assert.Equal(t, io.EOF, err, "should return io.EOF when closed during read")
	case <-time.After(1 * time.Second):
		t.Fatal("Read did not unblock after Close")
	}
}

// TestStreamConn_CloseSendsCLOSEPacket tests that Close sends CLOSE packet
func TestStreamConn_CloseSendsCLOSEPacket(t *testing.T) {
	conn := createTestConnection(t)

	// Ensure connection is in ESTABLISHED state
	conn.mu.Lock()
	conn.state = StateEstablished
	conn.mu.Unlock()

	err := conn.Close()
	assert.NoError(t, err)

	// Verify state transition
	conn.mu.Lock()
	assert.True(t, conn.closed)
	// State should be Closing after sending CLOSE
	assert.Equal(t, StateClosing, conn.state)
	conn.mu.Unlock()
}

// TestStreamListener_Addr tests Addr() method
func TestStreamListener_Addr(t *testing.T) {
	session := createMockSession()
	listener, err := Listen(session, 8080)
	require.NoError(t, err)
	defer listener.Close()

	addr := listener.Addr()
	require.NotNil(t, addr)

	i2pAddr, ok := addr.(*I2PAddr)
	require.True(t, ok, "Addr should return *I2PAddr")
	assert.Equal(t, uint16(8080), i2pAddr.port)
	assert.Equal(t, "i2p", i2pAddr.Network())
}

// TestStreamListener_ImplementsNetListener verifies StreamListener implements net.Listener
func TestStreamListener_ImplementsNetListener(t *testing.T) {
	session := createMockSession()
	listener, err := Listen(session, 8080)
	require.NoError(t, err)
	defer listener.Close()

	var _ net.Listener = listener
}

// TestTimeoutError_ImplementsNetError verifies timeoutError implements net.Error
func TestTimeoutError_ImplementsNetError(t *testing.T) {
	var err error = &timeoutError{}

	// Should implement net.Error
	netErr, ok := err.(net.Error)
	require.True(t, ok, "timeoutError should implement net.Error")

	assert.True(t, netErr.Timeout(), "Timeout() should return true")
	assert.True(t, netErr.Temporary(), "Temporary() should return true")
	assert.Equal(t, "i/o timeout", err.Error())
}

// TestStreamConn_io_Copy tests that connection works with io.Copy
func TestStreamConn_io_Copy(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	// Add data to receive buffer
	testData := []byte("hello world from io.Copy test")
	conn.mu.Lock()
	conn.recvBuf.Write(testData)
	conn.mu.Unlock()

	// Create a buffer to copy into
	var dest []byte
	buf := make([]byte, 1024)

	// Read using io.Copy-like pattern
	n, err := conn.Read(buf)
	assert.NoError(t, err)
	dest = append(dest, buf[:n]...)

	assert.Equal(t, testData, dest)
}

// TestStreamConn_ConcurrentReadWrite tests concurrent Read and Write
func TestStreamConn_ConcurrentReadWrite(t *testing.T) {
	conn := createTestConnection(t)
	defer conn.Close()

	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 10; i++ {
			data := []byte("test message")
			_, err := conn.Write(data)
			assert.NoError(t, err)
			time.Sleep(10 * time.Millisecond)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		conn.mu.Lock()
		conn.recvBuf.Write([]byte("response"))
		conn.recvCond.Broadcast()
		conn.mu.Unlock()

		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, "response", string(buf[:n]))
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done
}
