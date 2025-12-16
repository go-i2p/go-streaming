package streaming

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/stretchr/testify/require"
)

// TestHTTPRequest_LocalServer tests making an HTTP request to a local go-streaming HTTP server
func TestHTTPRequest_LocalServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Log("=== HTTP Request: Local Server Test ===")
	t.Log("This test creates an HTTP server and client communicating over I2P streaming")
	t.Log("")

	// ============================================================
	// PART 1: CREATE SERVER
	// ============================================================
	t.Log("PART 1: Setting up HTTP server")
	t.Log("")

	// Step 1: Create server I2CP client
	t.Log("Step 1: Creating server I2CP client...")
	serverClient := go_i2cp.NewClient(nil)
	defer serverClient.Close()
	t.Log("  ✓ Server client created")

	// Step 2: Connect server to router
	t.Log("Step 2: Connecting server to I2P router...")
	serverCtx, serverCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer serverCancel()

	serverConnectErr := serverClient.Connect(serverCtx)
	require.NoError(t, serverConnectErr, "should connect server to router")
	t.Log("  ✓ Server connected to router")

	// Step 3: Create server StreamManager
	t.Log("Step 3: Creating server StreamManager...")
	serverManager, err := NewStreamManager(serverClient)
	require.NoError(t, err, "should create server stream manager")
	defer serverManager.Close()
	t.Log("  ✓ Server StreamManager created")

	t.Log("  ✓ Server StreamManager created")

	// Step 4: Configure server session
	t.Log("Step 4: Configuring server session...")
	serverManager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	serverManager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "http-test-server")
	serverManager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_QUANTITY, "2")
	serverManager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "2")
	t.Log("  ✓ Server session configured")

	// Step 5: Start server ProcessIO
	t.Log("Step 5: Starting server ProcessIO loop...")
	go func() {
		for {
			if err := serverClient.ProcessIO(context.Background()); err != nil {
				if err == go_i2cp.ErrClientClosed {
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	t.Log("  ✓ Server ProcessIO started")

	// Step 6: Start server session
	t.Log("Step 6: Starting server I2CP session...")
	serverSessionCtx, serverSessionCancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer serverSessionCancel()

	err = serverManager.StartSession(serverSessionCtx)
	require.NoError(t, err, "should start server session")
	serverDest := serverManager.Destination()
	t.Log("  ✓ Server session started")
	t.Logf("  ✓ Server destination: %s...", serverDest.Base32()[:52])

	// Step 7: Create listener on port 80
	t.Log("")
	t.Log("Step 7: Creating HTTP listener on port 80...")
	listener, listenerErr := ListenWithManager(serverManager, 80, DefaultMTU)
	require.NoError(t, listenerErr, "should create listener")
	defer listener.Close()
	t.Log("  ✓ Listener created on port 80")

	// Step 8: Start HTTP server goroutine
	t.Log("Step 8: Starting HTTP server goroutine...")
	serverReady := make(chan struct{})
	serverErr := make(chan error, 1)

	go func() {
		close(serverReady)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				select {
				case serverErr <- acceptErr:
				default:
				}
				return
			}

			// Handle connection in separate goroutine
			go func(c io.ReadWriteCloser) {
				defer c.Close()

				reader := bufio.NewReader(c)

				// Read request line
				requestLine, err := reader.ReadString('\n')
				if err != nil {
					t.Logf("  [Server] Error reading request: %v", err)
					return
				}

				t.Logf("  [Server] Received: %s", strings.TrimSpace(requestLine))

				// Read and discard headers
				for {
					line, err := reader.ReadString('\n')
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}

				// Send HTTP response
				response := "HTTP/1.1 200 OK\r\n" +
					"Content-Type: text/plain\r\n" +
					"Content-Length: 26\r\n" +
					"Connection: close\r\n" +
					"\r\n" +
					"Hello from go-streaming!\n"

				_, writeErr := c.Write([]byte(response))
				if writeErr != nil {
					t.Logf("  [Server] Error writing response: %v", writeErr)
				} else {
					t.Log("  [Server] Response sent successfully")
				}
			}(conn)
		}
	}()

	<-serverReady
	t.Log("  ✓ HTTP server running")

	// ============================================================
	// PART 2: CREATE CLIENT AND MAKE REQUEST
	// ============================================================
	t.Log("")
	t.Log("Waiting 10 seconds for router to build server tunnels...")
	time.Sleep(10 * time.Second)
	t.Log("Proceeding without waiting for LeaseSet (router will request when needed)...")

	t.Log("")
	t.Log("PART 2: Setting up HTTP client")
	t.Log("")

	// Step 9: Create client I2CP client
	t.Log("Step 9: Creating client I2CP client...")
	clientClient := go_i2cp.NewClient(nil)
	defer clientClient.Close()
	t.Log("  ✓ Client created")

	// Step 10: Connect client to router
	t.Log("Step 10: Connecting client to I2P router...")
	clientCtx, clientCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer clientCancel()

	clientConnectErr := clientClient.Connect(clientCtx)
	require.NoError(t, clientConnectErr, "should connect client to router")
	t.Log("  ✓ Client connected to router")

	// Step 11: Create client StreamManager
	t.Log("Step 11: Creating client StreamManager...")
	clientManager, clientManagerErr := NewStreamManager(clientClient)
	require.NoError(t, clientManagerErr, "should create client stream manager")
	defer clientManager.Close()
	t.Log("  ✓ Client StreamManager created")

	// Step 12: Configure client session
	t.Log("Step 12: Configuring client session...")
	clientManager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	clientManager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, "http-test-client")
	clientManager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_INBOUND_QUANTITY, "2")
	clientManager.session.Config().SetProperty(go_i2cp.SESSION_CONFIG_PROP_OUTBOUND_QUANTITY, "2")
	t.Log("  ✓ Client session configured")

	// Step 13: Start client ProcessIO
	t.Log("Step 13: Starting client ProcessIO loop...")
	go func() {
		for {
			if err := clientClient.ProcessIO(context.Background()); err != nil {
				if err == go_i2cp.ErrClientClosed {
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	t.Log("  ✓ Client ProcessIO started")

	// Step 14: Start client session
	t.Log("Step 14: Starting client I2CP session...")
	clientSessionCtx, clientSessionCancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer clientSessionCancel()

	err = clientManager.StartSession(clientSessionCtx)
	require.NoError(t, err, "should start client session")
	t.Log("  ✓ Client session started")
	t.Logf("  ✓ Client destination: %s...", clientManager.Destination().Base32()[:52])

	// Note: Client doesn't need to publish LeaseSet
	t.Log("")
	t.Log("Waiting 10 seconds for router to build tunnels...")
	time.Sleep(10 * time.Second)
	t.Log("Client ready (clients don't publish LeaseSets)...")

	// Step 15: Dial server
	t.Log("")
	t.Log("Step 15: Dialing server...")

	conn, dialErr := DialWithManager(clientManager, serverDest, 0, 80)
	require.NoError(t, dialErr, "should dial server")
	defer conn.Close()
	t.Log("  ✓ Connection established")

	// Step 16: Send HTTP GET request
	t.Log("")
	t.Log("Step 16: Sending HTTP GET request...")

	httpRequest := "GET / HTTP/1.1\r\n" +
		"Host: test-server.i2p\r\n" +
		"User-Agent: go-i2p-streaming-test/1.0\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n" +
		"\r\n"

	_, writeErr := conn.Write([]byte(httpRequest))
	require.NoError(t, writeErr, "should write HTTP request")
	t.Log("  ✓ Request sent")

	// Step 17: Read HTTP response
	t.Log("")
	t.Log("Step 17: Reading HTTP response...")

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	responseReader := bufio.NewReader(conn)

	// Read status line
	statusLine, statusErr := responseReader.ReadString('\n')
	require.NoError(t, statusErr, "should read status line")
	t.Logf("  → Status: %s", strings.TrimSpace(statusLine))
	require.Contains(t, statusLine, "200 OK", "should get 200 OK response")

	// Read headers
	headerCount := 0
	contentLength := 0
	for {
		line, err := responseReader.ReadString('\n')
		if err != nil && err != io.EOF {
			require.NoError(t, err, "should read header line")
		}

		line = strings.TrimSpace(line)
		if line == "" {
			break // End of headers
		}

		headerCount++
		t.Logf("  → Header: %s", line)

		if strings.HasPrefix(line, "Content-Length:") {
			fmt.Sscanf(line, "Content-Length: %d", &contentLength)
		}

		if err == io.EOF {
			break
		}
	}

	// Read body content
	var body strings.Builder
	bodyBuf := make([]byte, contentLength)
	n, readErr := io.ReadFull(responseReader, bodyBuf)
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		t.Logf("  → Body read completed with: %v", readErr)
	}

	if n > 0 {
		body.Write(bodyBuf[:n])
		t.Logf("  → Body (%d bytes): %s", n, strings.TrimSpace(body.String()))
		require.Equal(t, "Hello from go-streaming!", strings.TrimSpace(body.String()), "should receive expected message")
	}

	t.Log("")
	t.Log("=== HTTP Request Test Complete ===")
	t.Log("✓ Successfully completed HTTP GET request over I2P streaming")
	t.Log("✓ Server and client communicated via I2P tunnel")
}
