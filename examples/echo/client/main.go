// Echo client example for go-i2p/go-streaming
//
// This demonstrates a simple TCP-like echo client that connects to an
// I2P streaming server and sends/receives data.
//
// IMPORTANT: This example requires:
//   - I2P router running locally with I2CP enabled (default port 7654)
//   - Router must be bootstrapped and connected to the I2P network
//   - A valid I2CP session (session creation code omitted for brevity)
//   - Server destination address (base64 or .b32.i2p address)
//
// Usage (conceptual - requires session setup):
//
//	go run client/main.go <server-destination>
//
// The client will:
// 1. Connect to the specified I2P destination
// 2. Send test messages
// 3. Receive echoed responses
// 4. Display round-trip statistics
//
// NOTE: This is a demonstration of the streaming API.
// Production code would include proper I2CP session management,
// error recovery, and timeout handling.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
	streaming "github.com/go-i2p/go-streaming"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Configure logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	log.Info().Msg("starting I2P echo client")

	// Parse server destination from command line
	if len(os.Args) < 2 {
		log.Fatal().Msg("usage: client <server-destination-base64>")
	}
	serverDestB64 := os.Args[1]

	// Create I2CP client with empty callbacks
	client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})

	// Connect to I2P router with timeout
	connCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Info().Msg("connecting to I2P router at 127.0.0.1:7654")
	if err := client.Connect(connCtx); err != nil {
		log.Fatal().Err(err).Msg("failed to connect to I2P router")
	}
	defer client.Close()

	log.Info().Msg("connected to I2P router")

	// Create StreamManager to handle I2CP callbacks and packet routing
	manager, err := streaming.NewStreamManager(client)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create stream manager")
	}
	defer manager.Close()

	// Start I2CP session via manager
	if err := manager.StartSession(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("failed to start session")
	}

	// Start I2CP ProcessIO in background to receive messages
	// This is REQUIRED for the callbacks to work
	go func() {
		log.Info().Msg("starting I2CP ProcessIO loop")
		for {
			if err := client.ProcessIO(context.Background()); err != nil {
				if err == go_i2cp.ErrClientClosed {
					log.Info().Msg("I2CP client closed")
					return
				}
				log.Error().Err(err).Msg("I/O processing error")
				time.Sleep(time.Second)
			}
		}
	}()

	// Parse server destination from base64
	log.Info().Msg("parsing server destination")
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestinationFromBase64(serverDestB64, crypto)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse server destination")
	}

	// Connect to remote server
	const localPort = 0     // Use ephemeral port
	const remotePort = 8080 // Server's listening port
	const connectTimeout = 30 * time.Second

	log.Info().
		Str("destination", "<server-dest>").
		Uint16("remote_port", remotePort).
		Msg("connecting to server")

	// Create connection with manager support
	conn, err := dialWithManager(
		manager,
		dest,
		localPort,
		remotePort,
		1730, // Default MTU
		connectTimeout,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect")
	}
	defer conn.Close()

	log.Info().
		Str("local", conn.LocalAddr().String()).
		Str("remote", conn.RemoteAddr().String()).
		Msg("connected")

	// Run echo test
	testCtx := context.Background()
	if err := runEchoTest(testCtx, conn); err != nil {
		log.Fatal().Err(err).Msg("echo test failed")
	}

	log.Info().Msg("echo test completed successfully")
}

// dialWithManager is a helper to create a connection using StreamManager.
// This will be integrated into the streaming package API later.
func dialWithManager(
	manager *streaming.StreamManager,
	dest *go_i2cp.Destination,
	localPort, remotePort uint16,
	mtu int,
	timeout time.Duration,
) (*streaming.StreamConn, error) {
	// For now, use the existing Dial but we'll need to integrate manager support
	// The receiveLoop will get packets via the manager's callback routing
	conn, err := streaming.DialWithMTU(
		manager.Session(),
		dest,
		localPort,
		remotePort,
		mtu,
		timeout,
	)
	if err != nil {
		return nil, err
	}

	// Note: Connection should auto-register with manager in future
	// For now, the manager pattern works best with Listen operations
	return conn, nil
}

// runEchoTest sends test messages and verifies echoed responses
func runEchoTest(ctx context.Context, conn net.Conn) error {
	testMessages := []string{
		"Hello, I2P!",
		"Testing streaming protocol",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
		"The quick brown fox jumps over the lazy dog",
	}

	for i, msg := range testMessages {
		log.Info().
			Int("test", i+1).
			Int("total", len(testMessages)).
			Str("message", msg).
			Msg("sending test message")

		start := time.Now()

		// Send message
		n, err := conn.Write([]byte(msg))
		if err != nil {
			return fmt.Errorf("write failed: %w", err)
		}

		log.Debug().
			Int("bytes_sent", n).
			Msg("message sent")

		// Set read deadline
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Read echo response
		buf := make([]byte, 4096)
		totalRead := 0
		expected := len(msg)

		for totalRead < expected {
			n, err := conn.Read(buf[totalRead:])
			if err != nil {
				if err == io.EOF {
					return fmt.Errorf("unexpected EOF after %d bytes", totalRead)
				}
				return fmt.Errorf("read failed: %w", err)
			}
			totalRead += n
		}

		rtt := time.Since(start)
		response := string(buf[:totalRead])

		// Verify echo
		if response != msg {
			return fmt.Errorf("echo mismatch: sent %q, got %q", msg, response)
		}

		log.Info().
			Int("test", i+1).
			Int("bytes", totalRead).
			Dur("rtt", rtt).
			Msg("echo verified")

		// Brief pause between tests
		time.Sleep(100 * time.Millisecond)
	}

	return nil
}
