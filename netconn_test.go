package streaming

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// TestI2PAddr_DestinationAccessors tests destination accessor methods.
func TestI2PAddr_DestinationAccessors(t *testing.T) {
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err)

	t.Run("nil receiver", func(t *testing.T) {
		var addr *I2PAddr
		assert.Nil(t, addr.Destination())
		assert.Equal(t, "", addr.Base64())
		assert.Equal(t, "", addr.Base32())
	})

	t.Run("nil destination", func(t *testing.T) {
		addr := &I2PAddr{dest: nil, port: 1234}
		assert.Nil(t, addr.Destination())
		assert.Equal(t, "", addr.Base64())
		assert.Equal(t, "", addr.Base32())
	})

	t.Run("with destination", func(t *testing.T) {
		addr := &I2PAddr{dest: dest, port: 1234}
		assert.Same(t, dest, addr.Destination())
		assert.Equal(t, dest.Base64(), addr.Base64())
		assert.Equal(t, dest.Base32(), addr.Base32())
	})
}

// TestPeerDestinationHelpers tests extracting peer destination from net.Addr values.
func TestPeerDestinationHelpers(t *testing.T) {
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err)

	t.Run("non I2P address", func(t *testing.T) {
		peerDest, ok := PeerDestination(&net.TCPAddr{Port: 80})
		assert.False(t, ok)
		assert.Nil(t, peerDest)

		b64, ok := PeerDestinationBase64(&net.TCPAddr{Port: 80})
		assert.False(t, ok)
		assert.Equal(t, "", b64)
	})

	t.Run("I2P address without destination", func(t *testing.T) {
		peerDest, ok := PeerDestination(&I2PAddr{dest: nil, port: 1234})
		assert.False(t, ok)
		assert.Nil(t, peerDest)

		b64, ok := PeerDestinationBase64(&I2PAddr{dest: nil, port: 1234})
		assert.False(t, ok)
		assert.Equal(t, "", b64)
	})

	t.Run("I2P address with destination", func(t *testing.T) {
		addr := &I2PAddr{dest: dest, port: 1234}

		peerDest, ok := PeerDestination(addr)
		assert.True(t, ok)
		assert.Same(t, dest, peerDest)

		b64, ok := PeerDestinationBase64(addr)
		assert.True(t, ok)
		assert.Equal(t, dest.Base64(), b64)
	})
}

// TestAcceptConnRemoteAddrPeerDestination verifies accepted inbound connections expose peer destination.
func TestAcceptConnRemoteAddrPeerDestination(t *testing.T) {
	crypto := go_i2cp.NewCrypto()
	peerDest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err)

	listener := &StreamListener{
		acceptChan: make(chan *StreamConn, 1),
	}
	inboundConn := &StreamConn{
		dest:       peerDest,
		remotePort: 9999,
	}

	err = listener.queueConnectionForAccept(inboundConn, inboundConn.remotePort)
	require.NoError(t, err)

	accepted, err := listener.Accept()
	require.NoError(t, err)
	require.NotNil(t, accepted)

	b64, ok := PeerDestinationBase64(accepted.RemoteAddr())
	assert.True(t, ok)
	assert.Equal(t, peerDest.Base64(), b64)
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

// TestStreamListener_Addr tests Addr() method with a real I2CP connection
func TestStreamListener_Addr(t *testing.T) {
	i2cp := RequireI2CP(t)
	listener, err := ListenWithManager(i2cp.Manager, 8080, DefaultMTU)
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
	i2cp := RequireI2CP(t)
	listener, err := ListenWithManager(i2cp.Manager, 8081, DefaultMTU)
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

// TestStreamConn_RealRoundTrip tests actual I2P communication with a listener and client.
// This creates a real listener on one session and a client on another, then measures round-trip time.
// Uses two separate I2CP sessions to avoid loopback issues.
func TestStreamConn_RealRoundTrip(t *testing.T) {
	// Server session
	serverI2CP := RequireI2CP(t)

	// Client session (separate destination)
	clientManager := CreateSecondI2CPSession(t)

	// Create a listener on the server session
	listener, err := ListenWithManager(serverI2CP.Manager, 9999, DefaultMTU)
	require.NoError(t, err)
	defer listener.Close()

	serverDest := serverI2CP.Manager.Destination()
	t.Logf("Server listening on %s:9999", serverDest.Base32()[:16])
	t.Logf("Client dest: %s", clientManager.Destination().Base32()[:16])

	var serverConn net.Conn
	serverReady := make(chan struct{})
	serverDone := make(chan struct{})
	var serverErr error

	// Server goroutine - accepts connection, echoes data back
	go func() {
		defer close(serverDone)

		// Accept blocks until connection arrives or listener closes
		conn, err := listener.Accept()
		if err != nil {
			serverErr = fmt.Errorf("accept failed: %w", err)
			close(serverReady)
			return
		}
		serverConn = conn
		close(serverReady)

		t.Log("Server: connection accepted")

		// Echo server - read data and send it back
		buf := make([]byte, 1024)
		for {
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				if err == io.EOF {
					t.Log("Server: client closed connection")
				} else {
					t.Logf("Server: read error: %v", err)
				}
				return
			}
			t.Logf("Server: received %d bytes: %q", n, string(buf[:n]))

			// Echo back
			conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_, err = conn.Write(buf[:n])
			if err != nil {
				t.Logf("Server: write error: %v", err)
				return
			}
			t.Logf("Server: echoed %d bytes", n)
		}
	}()

	// Client - dial the server from a different session
	// Use localPort 12345, remotePort 9999 (the listener port)
	t.Log("Client: dialing server...")
	clientConn, err := DialWithManager(clientManager, serverDest, 12345, 9999)
	require.NoError(t, err)
	defer clientConn.Close()

	t.Log("Client: connected, waiting for server to accept...")

	// Wait for server to be ready
	select {
	case <-serverReady:
		if serverErr != nil {
			t.Fatalf("Server error: %v", serverErr)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Timeout waiting for server to accept connection")
	}

	// Test messages with timing
	messages := []string{
		"Hello I2P!",
		"This is a round-trip test",
		"Measuring latency over the I2P network",
	}

	var totalRTT time.Duration
	var rttSamples int

	for i, msg := range messages {
		t.Logf("Client: sending message %d: %q", i+1, msg)

		start := time.Now()

		// Send message
		clientConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, err := clientConn.Write([]byte(msg))
		require.NoError(t, err, "write failed for message %d", i+1)

		// Read echo response
		buf := make([]byte, len(msg))
		clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := io.ReadFull(clientConn, buf)
		require.NoError(t, err, "read failed for message %d", i+1)

		rtt := time.Since(start)
		totalRTT += rtt
		rttSamples++

		assert.Equal(t, msg, string(buf[:n]), "echo mismatch for message %d", i+1)
		t.Logf("Client: received echo, RTT: %v", rtt)
	}

	avgRTT := totalRTT / time.Duration(rttSamples)
	t.Logf("=== Round-Trip Results ===")
	t.Logf("Messages sent: %d", rttSamples)
	t.Logf("Total time: %v", totalRTT)
	t.Logf("Average RTT: %v", avgRTT)

	// Close client connection
	clientConn.Close()

	// Wait for server to finish
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Log("Server goroutine timed out (may still be running)")
	}

	if serverConn != nil {
		serverConn.Close()
	}
}

// TestStreamConn_ConcurrentReadWrite tests concurrent Read and Write with real I2P.
// Sets up an echo server and has multiple goroutines reading/writing simultaneously.
// Uses two separate I2CP sessions to avoid loopback issues.
func TestStreamConn_ConcurrentReadWrite(t *testing.T) {
	// Server session
	serverI2CP := RequireI2CP(t)

	// Client session (separate destination)
	clientManager := CreateSecondI2CPSession(t)

	// Create a listener on the server
	listener, err := ListenWithManager(serverI2CP.Manager, 9998, DefaultMTU)
	require.NoError(t, err)
	defer listener.Close()

	serverDest := serverI2CP.Manager.Destination()
	serverReady := make(chan struct{})
	serverDone := make(chan struct{})

	// Echo server
	go func() {
		defer close(serverDone)

		// Accept blocks until connection arrives
		conn, err := listener.Accept()
		if err != nil {
			t.Logf("Server accept error: %v", err)
			close(serverReady)
			return
		}
		defer conn.Close()
		close(serverReady)

		// Simple echo loop
		buf := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			conn.Write(buf[:n])
		}
	}()

	// Client connects from second session
	clientConn, err := DialWithManager(clientManager, serverDest, 12346, 9998)
	require.NoError(t, err)
	defer clientConn.Close()

	select {
	case <-serverReady:
	case <-time.After(60 * time.Second):
		t.Fatal("Timeout waiting for server")
	}

	// Concurrent test
	var wg sync.WaitGroup
	const numWriters = 3
	const messagesPerWriter = 5

	// Writers send messages
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < messagesPerWriter; i++ {
				msg := fmt.Sprintf("writer%d-msg%d", writerID, i)
				clientConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				_, err := clientConn.Write([]byte(msg))
				if err != nil {
					t.Logf("Writer %d error: %v", writerID, err)
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
		}(w)
	}

	// Reader collects echoes
	received := make(chan string, numWriters*messagesPerWriter)
	go func() {
		buf := make([]byte, 256)
		for {
			clientConn.SetReadDeadline(time.Now().Add(15 * time.Second))
			n, err := clientConn.Read(buf)
			if err != nil {
				return
			}
			received <- string(buf[:n])
		}
	}()

	// Wait for writers
	wg.Wait()

	// Give time for echoes to arrive
	time.Sleep(2 * time.Second)
	clientConn.Close()

	// Count received
	close(received)
	count := 0
	for msg := range received {
		t.Logf("Received echo: %q", msg)
		count++
	}

	t.Logf("=== Concurrent Test Results ===")
	t.Logf("Sent: %d messages from %d writers", numWriters*messagesPerWriter, numWriters)
	t.Logf("Received: %d echoes", count)

	// We should receive at least some echoes
	assert.Greater(t, count, 0, "Should have received at least some echo responses")
}
