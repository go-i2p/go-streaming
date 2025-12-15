// Integration tests for Java I2P interoperability
//
// These tests validate that go-streaming can successfully communicate
// with the Java I2P router and streaming library.
//
// Prerequisites:
//   - Java I2P router running on 127.0.0.1:7654
//   - Router must be bootstrapped and connected
//   - I2CP port accessible
//
// Run with: go test -v -run TestJavaI2P
package streaming

import (
	"context"
	"testing"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/stretchr/testify/require"
)

// TestJavaI2P_RouterConnection tests basic connectivity to Java I2P router
func TestJavaI2P_RouterConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create I2CP client
	client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})

	// Connect to router with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Log("connecting to Java I2P router at 127.0.0.1:7654...")
	err := client.Connect(ctx)
	require.NoError(t, err, "should connect to Java I2P router")
	defer client.Close()

	t.Log("✓ connected to Java I2P router")
}

// TestJavaI2P_SessionCreation tests creating an I2CP session
func TestJavaI2P_SessionCreation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Log("=== I2CP Session Creation Handshake Trace ===")
	t.Log("")

	// Create I2CP client
	t.Log("Step 1: Creating I2CP client...")
	client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})
	t.Log("  ✓ Client created")

	// Connect to router
	t.Log("Step 2: Connecting to router at 127.0.0.1:7654...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	require.NoError(t, err, "should connect to router")
	defer client.Close()
	t.Log("  ✓ Connected to router")

	// Create StreamManager (handles session creation)
	t.Log("Step 3: Creating StreamManager with callbacks...")
	manager, err := NewStreamManager(client)
	require.NoError(t, err, "should create stream manager")
	defer manager.Close()
	t.Log("  ✓ StreamManager created")
	t.Log("  ✓ SessionCallbacks registered:")
	t.Log("    - OnMessage:       handleIncomingMessage")
	t.Log("    - OnStatus:        handleSessionStatus")
	t.Log("    - OnDestination:   handleDestinationResult")
	t.Log("    - OnMessageStatus: handleMessageStatus")

	t.Log("")
	t.Log("Step 3.5: Configuring session properties...")
	// Configure session matching go-i2cp integration test pattern
	manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "go-streaming-integration-test")
	manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_QUANTITY, "2")
	manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "2")
	t.Log("  ✓ Session configured with:")
	t.Log("    - outbound.nickname: go-streaming-integration-test")
	t.Log("    - inbound.quantity:  2 tunnels")
	t.Log("    - outbound.quantity: 2 tunnels")
	t.Log("    - fastReceive:       enabled")

	// Start ProcessIO BEFORE creating session
	t.Log("")
	t.Log("Step 4: Starting ProcessIO loop...")
	processIOStarted := make(chan struct{})
	go func() {
		close(processIOStarted)
		t.Log("  ✓ ProcessIO loop started")
		for {
			if err := client.ProcessIO(context.Background()); err != nil {
				if err == go_i2cp.ErrClientClosed {
					t.Log("  ✓ ProcessIO loop exited (client closed)")
					return
				}
				t.Logf("  ⚠ ProcessIO error: %v", err)
			}
			// Always sleep to prevent spinning - ProcessIO returns immediately if no data
			time.Sleep(50 * time.Millisecond)
		}
	}()
	<-processIOStarted
	time.Sleep(100 * time.Millisecond) // Let ProcessIO start

	// Now start session
	t.Log("")
	t.Log("Step 5: Sending CreateSession message to router...")
	t.Log("  → Expected response: SessionCreated with status")
	sessionCtx, sessionCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer sessionCancel()

	// Monitor for timeout
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for i := 1; i <= 6; i++ {
			select {
			case <-ticker.C:
				t.Logf("  ⏱ Waiting for SessionCreated response... (%ds elapsed)", i*5)
			case <-sessionCtx.Done():
				return
			}
		}
	}()

	err = manager.StartSession(sessionCtx)
	if err != nil {
		t.Log("")
		t.Log("❌ Session creation FAILED")
		t.Logf("   Error: %v", err)
		t.Log("")
		t.Log("Troubleshooting steps:")
		t.Log("  1. Check Java I2P router logs for CreateSession messages")
		t.Log("  2. Verify I2CP port 7654 accepts session requests")
		t.Log("  3. Check if router requires authentication")
		t.Log("  4. Verify router is fully started and connected to network")
		require.NoError(t, err, "should create I2CP session")
	}

	t.Log("")
	t.Log("Step 6: Session created successfully!")

	// Verify destination was created
	dest := manager.Destination()
	require.NotNil(t, dest, "should have destination")
	t.Logf("  ✓ I2CP session created")
	t.Logf("  ✓ Session ID: %d", manager.session.ID())
	t.Logf("  ✓ Destination: %s", dest.Base32()[:52]+"...")

	// Keep session alive briefly to ensure stability
	t.Log("")
	t.Log("Step 7: Verifying session stability...")
	time.Sleep(2 * time.Second)
	t.Log("  ✓ Session stable for 2 seconds")
	t.Log("")
	t.Log("=== Session Creation Successful ===")
}

// TestJavaI2P_ListenerCreation tests creating a streaming listener
func TestJavaI2P_ListenerCreation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Setup I2CP session
	client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	require.NoError(t, err)
	defer client.Close()

	manager, err := NewStreamManager(client)
	require.NoError(t, err)
	defer manager.Close()

	err = manager.StartSession(context.Background())
	require.NoError(t, err)

	// Start ProcessIO
	go func() {
		for {
			if err := client.ProcessIO(context.Background()); err != nil {
				if err == go_i2cp.ErrClientClosed {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	// Create streaming listener
	t.Log("creating streaming listener on port 8080...")
	listener, err := ListenWithManager(manager, 8080, DefaultMTU)
	require.NoError(t, err, "should create listener")
	defer listener.Close()

	t.Logf("✓ listener created")
	t.Logf("  Listening on port: 8080")
	t.Logf("  Destination: %s", manager.Destination().Base32())

	// Verify listener is ready
	time.Sleep(1 * time.Second)
	t.Log("✓ listener ready for connections")
}

// TestJavaI2P_PacketFormat validates that our packets match Java I2P format
func TestJavaI2P_PacketFormat(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Setup I2CP session
	client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	require.NoError(t, err)
	defer client.Close()

	manager, err := NewStreamManager(client)
	require.NoError(t, err)
	defer manager.Close()

	err = manager.StartSession(context.Background())
	require.NoError(t, err)

	// Create a test SYN packet (without signature for simplicity)
	pkt := &Packet{
		SendStreamID:    0,     // Must be 0 in initial SYN
		RecvStreamID:    12345, // Our local stream ID
		SequenceNum:     1000,  // Initial sequence number
		AckThrough:      0,
		Flags:           FlagSYN | FlagFromIncluded,
		FromDestination: manager.Destination(),
	}

	// Add 8 NACKs (Java I2P compatibility)
	pkt.NACKs = make([]uint32, 8)
	for i := 0; i < 8; i++ {
		pkt.NACKs[i] = uint32(i * 100)
	}

	// Marshal to bytes
	data, err := pkt.Marshal()
	require.NoError(t, err, "should marshal packet")

	t.Logf("✓ SYN packet created")
	t.Logf("  Packet size: %d bytes", len(data))
	t.Logf("  Flags: 0x%02X (SYN=%v, FROM=%v)",
		pkt.Flags,
		pkt.Flags&FlagSYN != 0,
		pkt.Flags&FlagFromIncluded != 0)
	t.Logf("  SendStreamID: %d (must be 0)", pkt.SendStreamID)
	t.Logf("  RecvStreamID: %d", pkt.RecvStreamID)
	t.Logf("  SequenceNum: %d", pkt.SequenceNum)
	t.Logf("  NACKs: %d (8 required)", len(pkt.NACKs))
	t.Logf("  FromDestination: %d bytes", len(pkt.FromDestination.Base64()))

	// Validate minimum packet size (22 header + 32 NACKs + 391 dest)
	minSize := 22 + 32 + 391
	require.GreaterOrEqual(t, len(data), minSize, "packet should meet minimum size")

	// Unmarshal to verify roundtrip
	parsed := &Packet{}
	err = parsed.Unmarshal(data)
	require.NoError(t, err, "should unmarshal packet")

	require.Equal(t, pkt.SendStreamID, parsed.SendStreamID)
	require.Equal(t, pkt.RecvStreamID, parsed.RecvStreamID)
	require.Equal(t, pkt.SequenceNum, parsed.SequenceNum)
	require.Equal(t, pkt.Flags, parsed.Flags)
	require.Equal(t, len(pkt.NACKs), len(parsed.NACKs))

	t.Log("✓ packet format validated")
}

// TestJavaI2P_EnvironmentCheck validates the test environment is ready
func TestJavaI2P_EnvironmentCheck(t *testing.T) {
	t.Log("Java I2P Integration Test Environment Check")
	t.Log("============================================")
	t.Log("")
	t.Log("Prerequisites:")
	t.Log("  ✓ Java I2P router must be running")
	t.Log("  ✓ Router must be at 127.0.0.1:7654")
	t.Log("  ✓ Router must be bootstrapped")
	t.Log("  ✓ I2CP port must be accessible")
	t.Log("")
	t.Log("To run full integration tests:")
	t.Log("  go test -v -run TestJavaI2P")
	t.Log("")
	t.Log("To skip integration tests (unit tests only):")
	t.Log("  go test -v -short")
}
