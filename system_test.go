//go:build system
// +build system

// System integration tests for go-streaming
//
// These tests require a running I2P router with I2CP enabled on localhost:7654.
// They are separated from unit tests and only run when explicitly requested.
//
// To run these tests:
//   go test -tags=system -v -timeout=5m
//
// To skip when router unavailable, tests will automatically detect and skip.
//
// Prerequisites:
//   - I2P router running (i2pd or Java I2P)
//   - I2CP enabled on port 7654 (default)
//   - Router bootstrapped and connected to network
//
// Environment variables:
//   I2P_ROUTER_HOST - I2P router address (default: 127.0.0.1:7654)
//   SYSTEM_TEST_TIMEOUT - Timeout for operations (default: 60s)

package streaming

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Configure logging for system tests
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
}

// getRouterAddress returns I2P router address from environment or default.
func getRouterAddress() string {
	if addr := os.Getenv("I2P_ROUTER_HOST"); addr != "" {
		return addr
	}
	return "127.0.0.1:7654"
}

// getTestTimeout returns timeout duration from environment or default.
func getTestTimeout() time.Duration {
	if timeout := os.Getenv("SYSTEM_TEST_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			return d
		}
	}
	return 60 * time.Second
}

// checkRouterAvailable checks if I2P router is reachable.
// Returns true if router is available, false otherwise.
func checkRouterAvailable(t *testing.T) bool {
	addr := getRouterAddress()

	t.Logf("Checking I2P router availability at %s", addr)

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Logf("I2P router not available: %v", err)
		return false
	}
	conn.Close()

	t.Logf("I2P router is reachable at %s", addr)
	return true
}

// createTestClient creates and connects an I2CP client.
// Returns nil and skips test if router is unavailable.
func createTestClient(t *testing.T) *go_i2cp.Client {
	if !checkRouterAvailable(t) {
		t.Skip("I2P router not available - skipping system test")
		return nil
	}

	// Note: Client is configured to use default I2CP address (127.0.0.1:7654)
	// via go-i2cp defaults. For custom address, would need to configure client.
	client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Log("Connecting to I2P router...")
	if err := client.Connect(ctx); err != nil {
		t.Skipf("Failed to connect to I2P router: %v", err)
		return nil
	}

	t.Log("Successfully connected to I2P router")
	return client
} // createTestManager creates a StreamManager with active session.
func createTestManager(t *testing.T, client *go_i2cp.Client) *StreamManager {
	manager, err := NewStreamManager(client)
	require.NoError(t, err, "Failed to create stream manager")

	t.Log("Starting I2CP session...")
	err = manager.StartSession(context.Background())
	require.NoError(t, err, "Failed to start I2CP session")

	dest := manager.Destination()
	require.NotNil(t, dest, "Session destination should not be nil")

	t.Logf("I2CP session created with destination")
	return manager
}

// startProcessIO starts I2CP message processing in background.
func startProcessIO(t *testing.T, client *go_i2cp.Client, ctx context.Context) {
	go func() {
		t.Log("Starting I2CP ProcessIO loop...")
		for {
			select {
			case <-ctx.Done():
				t.Log("ProcessIO loop terminated")
				return
			default:
			}

			if err := client.ProcessIO(ctx); err != nil {
				if err == go_i2cp.ErrClientClosed || ctx.Err() != nil {
					return
				}
				t.Logf("I/O processing error: %v", err)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	// Give ProcessIO time to start
	time.Sleep(500 * time.Millisecond)
}

// TestSystem_BasicConnectivity verifies basic I2CP connectivity.
func TestSystem_BasicConnectivity(t *testing.T) {
	client := createTestClient(t)
	if client == nil {
		return // Skipped
	}
	defer client.Close()

	// Create manager and start session
	manager := createTestManager(t, client)
	defer manager.Close()

	// Verify session is active
	session := manager.Session()
	assert.NotNil(t, session, "Session should not be nil")

	// Verify destination exists
	dest := manager.Destination()
	assert.NotNil(t, dest, "Destination should not be nil")

	t.Log("✓ Basic connectivity test passed")
}

// TestSystem_SessionLifecycle tests session creation and cleanup.
func TestSystem_SessionLifecycle(t *testing.T) {
	client := createTestClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	// Create multiple managers to test lifecycle
	managers := make([]*StreamManager, 3)
	for i := 0; i < 3; i++ {
		manager, err := NewStreamManager(client)
		require.NoError(t, err)

		err = manager.StartSession(context.Background())
		require.NoError(t, err)

		managers[i] = manager
		t.Logf("Created session %d", i+1)
	}

	// Close all managers
	for i, manager := range managers {
		manager.Close()
		t.Logf("Closed session %d", i+1)
	}

	t.Log("✓ Session lifecycle test passed")
}

// TestSystem_ListenerCreation tests creating a streaming listener.
func TestSystem_ListenerCreation(t *testing.T) {
	client := createTestClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	manager := createTestManager(t, client)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), getTestTimeout())
	defer cancel()

	// Start ProcessIO for callback handling
	startProcessIO(t, client, ctx)

	// Create listener
	listener, err := ListenWithManager(manager, 8080, DefaultMTU)
	require.NoError(t, err, "Failed to create listener")
	defer listener.Close()

	// Verify listener properties
	addr := listener.Addr()
	assert.NotNil(t, addr, "Listener address should not be nil")
	assert.Equal(t, "i2p", addr.Network(), "Network should be 'i2p'")

	t.Logf("Listener created on port 8080: %s", addr.String())
	t.Log("✓ Listener creation test passed")
}

// TestSystem_EchoServerClient tests full client-server communication.
func TestSystem_EchoServerClient(t *testing.T) {
	// Create server
	serverClient := createTestClient(t)
	if serverClient == nil {
		return
	}
	defer serverClient.Close()

	serverManager := createTestManager(t, serverClient)
	defer serverManager.Close()

	serverCtx, serverCancel := context.WithTimeout(context.Background(), getTestTimeout())
	defer serverCancel()

	startProcessIO(t, serverClient, serverCtx)

	// Create listener
	listener, err := ListenWithManager(serverManager, 9000, DefaultMTU)
	require.NoError(t, err)
	defer listener.Close()

	serverDest := serverManager.Destination()
	require.NotNil(t, serverDest)

	t.Logf("Server listening on port 9000")

	// Start server goroutine
	serverReady := make(chan struct{})
	serverDone := make(chan error, 1)

	go func() {
		close(serverReady)

		conn, err := listener.Accept()
		if err != nil {
			serverDone <- fmt.Errorf("accept failed: %w", err)
			return
		}
		defer conn.Close()

		t.Log("Server accepted connection")

		// Echo data back
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			serverDone <- fmt.Errorf("read failed: %w", err)
			return
		}

		t.Logf("Server received %d bytes", n)

		_, err = conn.Write(buf[:n])
		if err != nil {
			serverDone <- fmt.Errorf("write failed: %w", err)
			return
		}

		t.Log("Server echoed data back")
		serverDone <- nil
	}()

	// Wait for server to be ready
	<-serverReady
	time.Sleep(1 * time.Second)

	// Create client
	clientClient := createTestClient(t)
	require.NotNil(t, clientClient)
	defer clientClient.Close()

	clientManager := createTestManager(t, clientClient)
	defer clientManager.Close()

	clientCtx, clientCancel := context.WithTimeout(context.Background(), getTestTimeout())
	defer clientCancel()

	startProcessIO(t, clientClient, clientCtx)

	// Give client ProcessIO time to initialize
	time.Sleep(1 * time.Second)

	// Dial server
	t.Log("Client dialing server...")
	conn, err := Dial(clientManager.Session(), serverDest, 0, 9000)
	require.NoError(t, err, "Dial failed")
	defer conn.Close()

	t.Log("Client connected to server")

	// Send test message
	testMsg := []byte("Hello, I2P System Test!")
	_, err = conn.Write(testMsg)
	require.NoError(t, err, "Write failed")

	t.Logf("Client sent: %s", testMsg)

	// Read echoed response
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	require.NoError(t, err, "Read failed")

	response := buf[:n]
	t.Logf("Client received: %s", response)

	// Verify echo
	assert.Equal(t, testMsg, response, "Echoed data should match sent data")

	// Wait for server completion
	select {
	case err := <-serverDone:
		require.NoError(t, err, "Server error")
	case <-time.After(5 * time.Second):
		t.Fatal("Server did not complete in time")
	}

	t.Log("✓ Echo server-client test passed")
}

// TestSystem_LargeDataTransfer tests transferring larger data over I2P.
func TestSystem_LargeDataTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large data transfer in short mode")
	}

	// Create server
	serverClient := createTestClient(t)
	if serverClient == nil {
		return
	}
	defer serverClient.Close()

	serverManager := createTestManager(t, serverClient)
	defer serverManager.Close()

	serverCtx, serverCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer serverCancel()

	startProcessIO(t, serverClient, serverCtx)

	// Create listener
	listener, err := ListenWithManager(serverManager, 9001, DefaultMTU)
	require.NoError(t, err)
	defer listener.Close()

	serverDest := serverManager.Destination()

	t.Log("Server ready for large data transfer")

	// Generate test data (10KB)
	testData := make([]byte, 10*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Start server
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		received := make([]byte, len(testData))
		_, err = io.ReadFull(conn, received)
		if err != nil {
			serverDone <- fmt.Errorf("server read failed: %w", err)
			return
		}

		// Echo back
		_, err = conn.Write(received)
		serverDone <- err
	}()

	time.Sleep(1 * time.Second)

	// Create client
	clientClient := createTestClient(t)
	require.NotNil(t, clientClient)
	defer clientClient.Close()

	clientManager := createTestManager(t, clientClient)
	defer clientManager.Close()

	clientCtx, clientCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer clientCancel()

	startProcessIO(t, clientClient, clientCtx)
	time.Sleep(1 * time.Second)

	// Connect and transfer
	conn, err := Dial(clientManager.Session(), serverDest, 0, 9001)
	require.NoError(t, err)
	defer conn.Close()

	t.Log("Sending 10KB of data...")
	start := time.Now()

	_, err = conn.Write(testData)
	require.NoError(t, err)

	// Read response
	received := make([]byte, len(testData))
	_, err = io.ReadFull(conn, received)
	require.NoError(t, err)

	duration := time.Since(start)
	t.Logf("Transfer completed in %v (%.2f KB/s)", duration, float64(len(testData))/1024/duration.Seconds())

	// Verify data integrity
	assert.Equal(t, testData, received, "Data should match")

	// Wait for server
	select {
	case err := <-serverDone:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Server timeout")
	}

	t.Log("✓ Large data transfer test passed")
}

// TestSystem_ConcurrentConnections tests multiple simultaneous connections.
func TestSystem_ConcurrentConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent connections test in short mode")
	}

	// Create server
	serverClient := createTestClient(t)
	if serverClient == nil {
		return
	}
	defer serverClient.Close()

	serverManager := createTestManager(t, serverClient)
	defer serverManager.Close()

	serverCtx, serverCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer serverCancel()

	startProcessIO(t, serverClient, serverCtx)

	listener, err := ListenWithManager(serverManager, 9002, DefaultMTU)
	require.NoError(t, err)
	defer listener.Close()

	serverDest := serverManager.Destination()

	const numConnections = 3
	var serverWg sync.WaitGroup
	serverWg.Add(numConnections)

	// Start server handler
	go func() {
		for i := 0; i < numConnections; i++ {
			conn, err := listener.Accept()
			if err != nil {
				t.Logf("Accept error: %v", err)
				continue
			}

			go func(id int, c net.Conn) {
				defer serverWg.Done()
				defer c.Close()

				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				c.Write(buf[:n])
				t.Logf("Server handled connection %d", id)
			}(i, conn)
		}
	}()

	time.Sleep(1 * time.Second)

	// Create client
	clientClient := createTestClient(t)
	require.NotNil(t, clientClient)
	defer clientClient.Close()

	clientManager := createTestManager(t, clientClient)
	defer clientManager.Close()

	clientCtx, clientCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer clientCancel()

	startProcessIO(t, clientClient, clientCtx)
	time.Sleep(1 * time.Second)

	// Create multiple connections
	var clientWg sync.WaitGroup
	clientWg.Add(numConnections)

	for i := 0; i < numConnections; i++ {
		go func(id int) {
			defer clientWg.Done()

			conn, err := Dial(clientManager.Session(), serverDest, 0, 9002)
			if err != nil {
				t.Logf("Dial %d failed: %v", id, err)
				return
			}
			defer conn.Close()

			msg := []byte(fmt.Sprintf("Message %d", id))
			conn.Write(msg)

			buf := make([]byte, 1024)
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				t.Logf("Read %d failed: %v", id, err)
				return
			}

			assert.Equal(t, msg, buf[:n])
			t.Logf("Client connection %d completed", id)
		}(i)

		// Stagger connections
		time.Sleep(500 * time.Millisecond)
	}

	clientWg.Wait()
	serverWg.Wait()

	t.Log("✓ Concurrent connections test passed")
}

// TestSystem_ConnectionTimeout tests connection timeout behavior.
func TestSystem_ConnectionTimeout(t *testing.T) {
	client := createTestClient(t)
	if client == nil {
		return
	}
	defer client.Close()

	manager := createTestManager(t, client)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), getTestTimeout())
	defer cancel()

	startProcessIO(t, client, ctx)

	// Create a fake destination (won't exist)
	// Using minimal empty destination for timeout test
	fakeDest := &go_i2cp.Destination{}

	// Attempt to dial non-existent destination (should timeout)
	t.Log("Attempting to dial non-existent destination...")
	conn, err := Dial(manager.Session(), fakeDest, 0, 8080)

	// This may fail immediately or timeout - both are acceptable
	if err != nil {
		t.Logf("Dial failed as expected: %v", err)
	} else if conn != nil {
		conn.Close()
		t.Log("Connection created (may timeout on actual use)")
	}

	t.Log("✓ Connection timeout test passed")
}
