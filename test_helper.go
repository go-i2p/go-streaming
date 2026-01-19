package streaming

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/armon/circbuf"
	go_i2cp "github.com/go-i2p/go-i2cp"
)

// TestI2CPConnection holds a shared I2CP connection for tests.
// This ensures all tests use a real I2P router connection.
type TestI2CPConnection struct {
	Client   *go_i2cp.Client
	Manager  *StreamManager
	mu       sync.Mutex
	refCount int
}

var (
	sharedTestConnection *TestI2CPConnection
	testConnectionMu     sync.Mutex
	testConnectionOnce   sync.Once
)

// RequireI2CP returns a shared I2CP connection for tests.
// It connects to the I2P router at localhost:7654.
// Tests will fail if no I2P router is available.
func RequireI2CP(t *testing.T) *TestI2CPConnection {
	t.Helper()

	testConnectionMu.Lock()
	defer testConnectionMu.Unlock()

	if sharedTestConnection == nil {
		// Create new connection
		client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		err := client.Connect(ctx)
		if err != nil {
			t.Fatalf("FATAL: Cannot connect to I2P router at localhost:7654. "+
				"I2P is a required dependency. Error: %v", err)
		}

		// Create StreamManager
		manager, err := NewStreamManager(client)
		if err != nil {
			client.Close()
			t.Fatalf("FATAL: Cannot create StreamManager: %v", err)
		}

		// Configure session
		manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
		manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "go-streaming-test")
		manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_QUANTITY, "1")
		manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "1")

		// Start ProcessIO loop
		go func() {
			for {
				if err := client.ProcessIO(context.Background()); err != nil {
					if err == go_i2cp.ErrClientClosed {
						return
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
		}()

		// Start session
		sessionCtx, sessionCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer sessionCancel()

		err = manager.StartSession(sessionCtx)
		if err != nil {
			client.Close()
			t.Fatalf("FATAL: Cannot start I2CP session. "+
				"Ensure I2P router is running and accessible. Error: %v", err)
		}

		sharedTestConnection = &TestI2CPConnection{
			Client:   client,
			Manager:  manager,
			refCount: 0,
		}

		t.Logf("Connected to I2P router, destination: %s...",
			manager.Destination().Base32()[:32])
	}

	sharedTestConnection.refCount++

	// Register cleanup on test completion
	t.Cleanup(func() {
		testConnectionMu.Lock()
		defer testConnectionMu.Unlock()
		if sharedTestConnection != nil {
			sharedTestConnection.refCount--
			// Don't close - let it be reused by other tests
		}
	})

	return sharedTestConnection
}

// CreateTestStreamConn creates a StreamConn for testing with a real I2CP session.
// This replaces the old createTestConnection that used session: nil.
func CreateTestStreamConn(t *testing.T) *StreamConn {
	t.Helper()

	i2cp := RequireI2CP(t)

	recvBuf, err := circbuf.NewBuffer(64 * 1024)
	if err != nil {
		t.Fatalf("Failed to create receive buffer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	conn := &StreamConn{
		session:           i2cp.Manager.session,
		dest:              i2cp.Manager.Destination(), // Send to ourselves for testing
		localPort:         12345,
		remotePort:        80,
		sendSeq:           GenerateTestISN(),
		recvSeq:           100,
		windowSize:        DefaultWindowSize,
		cwnd:              DefaultWindowSize,
		rtt:               8 * time.Second,
		rto:               9 * time.Second,
		recvBuf:           recvBuf,
		recvChan:          make(chan *Packet, 32),
		errChan:           make(chan error, 1),
		ctx:               ctx,
		cancel:            cancel,
		state:             StateEstablished,
		localMTU:          DefaultMTU,
		remoteMTU:         DefaultMTU,
		sentPackets:       make(map[uint32]*sentPacket),
		nackCounts:        make(map[uint32]int),
		outOfOrderPackets: make(map[uint32]*Packet),
		nackList:          make(map[uint32]struct{}),
	}
	conn.recvCond = sync.NewCond(&conn.mu)
	conn.sendCond = sync.NewCond(&conn.mu)

	return conn
}

// GenerateTestISN generates a fixed ISN for testing.
// Exported so tests can use it for assertions.
func GenerateTestISN() uint32 {
	return 1000
}

// CreateSecondI2CPSession creates a separate I2CP session for client/server tests.
// This is needed because loopback to the same destination may not work reliably.
// Returns a new StreamManager with its own session and destination.
func CreateSecondI2CPSession(t *testing.T) *StreamManager {
	t.Helper()

	// Create new client
	client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Cannot connect second I2CP client: %v", err)
	}

	// Create StreamManager
	manager, err := NewStreamManager(client)
	if err != nil {
		client.Close()
		t.Fatalf("Cannot create second StreamManager: %v", err)
	}

	// Configure session
	manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "go-streaming-test-2")
	manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_QUANTITY, "1")
	manager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "1")

	// Start ProcessIO loop
	go func() {
		for {
			if err := client.ProcessIO(context.Background()); err != nil {
				if err == go_i2cp.ErrClientClosed {
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	// Start session
	sessionCtx, sessionCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer sessionCancel()

	err = manager.StartSession(sessionCtx)
	if err != nil {
		client.Close()
		t.Fatalf("Cannot start second I2CP session: %v", err)
	}

	t.Logf("Created second session, destination: %s...",
		manager.Destination().Base32()[:32])

	// Register cleanup
	t.Cleanup(func() {
		manager.Close()
		client.Close()
	})

	return manager
}

// CleanupTestConnections closes the shared test connection.
// Call this from TestMain if needed.
func CleanupTestConnections() {
	testConnectionMu.Lock()
	defer testConnectionMu.Unlock()

	if sharedTestConnection != nil {
		sharedTestConnection.Manager.Close()
		sharedTestConnection.Client.Close()
		sharedTestConnection = nil
	}
}

// RequireI2CPSession returns a shared I2CP session for tests that need
// just a session object (not a full StreamManager connection setup).
// This is useful for unit tests that construct StreamConn manually.
func RequireI2CPSession(t *testing.T) *go_i2cp.Session {
	t.Helper()
	i2cp := RequireI2CP(t)
	return i2cp.Manager.Session()
}
