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
	configureLogging()
	log.Info().Msg("starting I2P echo client")

	serverDestB64 := parseServerDestination()

	client := createI2CPClient()
	defer client.Close()

	manager := createStreamManager(client)
	defer manager.Close()

	startProcessIOLoop(client)

	dest := parseDestinationFromBase64(serverDestB64)
	conn := connectToServer(manager, dest)
	defer conn.Close()

	runEchoTestOrFail(conn)
}

// configureLogging sets up the zerolog logger with console output and standard formatting.
func configureLogging() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
}

// parseServerDestination parses the server destination from command line arguments.
// It terminates the program with a fatal error if no destination is provided.
func parseServerDestination() string {
	if len(os.Args) < 2 {
		log.Fatal().Msg("usage: client <server-destination-base64>")
	}
	return os.Args[1]
}

// createI2CPClient creates a new I2CP client and connects to the I2P router.
// It terminates the program with a fatal error if the connection fails.
func createI2CPClient() *go_i2cp.Client {
	client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})

	connCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Info().Msg("connecting to I2P router at 127.0.0.1:7654")
	if err := client.Connect(connCtx); err != nil {
		log.Fatal().Err(err).Msg("failed to connect to I2P router")
	}

	log.Info().Msg("connected to I2P router")
	return client
}

// createStreamManager creates a stream manager from the I2CP client and starts
// an I2CP session. It terminates the program with a fatal error on failure.
func createStreamManager(client *go_i2cp.Client) *streaming.StreamManager {
	manager, err := streaming.NewStreamManager(client)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create stream manager")
	}

	if err := manager.StartSession(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("failed to start session")
	}

	return manager
}

// startProcessIOLoop starts a background goroutine that continuously processes
// I2CP I/O operations. This is required for callbacks to function properly.
func startProcessIOLoop(client *go_i2cp.Client) {
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
}

// parseDestinationFromBase64 parses an I2P destination from its base64 representation.
// It terminates the program with a fatal error if parsing fails.
func parseDestinationFromBase64(destB64 string) *go_i2cp.Destination {
	log.Info().Msg("parsing server destination")
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestinationFromBase64(destB64, crypto)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse server destination")
	}
	return dest
}

// connectToServer establishes a streaming connection to the remote server.
// It terminates the program with a fatal error if the connection fails.
func connectToServer(manager *streaming.StreamManager, dest *go_i2cp.Destination) *streaming.StreamConn {
	const localPort = 0
	const remotePort = 8080
	const connectTimeout = 30 * time.Second

	log.Info().
		Str("destination", "<server-dest>").
		Uint16("remote_port", remotePort).
		Msg("connecting to server")

	conn, err := dialWithManager(manager, dest, localPort, remotePort, 1730, connectTimeout)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect")
	}

	log.Info().
		Str("local", conn.LocalAddr().String()).
		Str("remote", conn.RemoteAddr().String()).
		Msg("connected")

	return conn
}

// runEchoTestOrFail runs the echo test and terminates the program on failure.
func runEchoTestOrFail(conn *streaming.StreamConn) {
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

// runEchoTest sends test messages and verifies echoed responses.
func runEchoTest(ctx context.Context, conn net.Conn) error {
	testMessages := []string{
		"Hello, I2P!",
		"Testing streaming protocol",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
		"The quick brown fox jumps over the lazy dog",
	}

	for i, msg := range testMessages {
		if err := runSingleEchoTest(conn, i+1, len(testMessages), msg); err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

// runSingleEchoTest sends a single test message and verifies the echoed response.
func runSingleEchoTest(conn net.Conn, testNum, totalTests int, msg string) error {
	log.Info().
		Int("test", testNum).
		Int("total", totalTests).
		Str("message", msg).
		Msg("sending test message")

	start := time.Now()

	if err := sendTestMessage(conn, msg); err != nil {
		return err
	}

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	response, err := readEchoResponse(conn, len(msg))
	if err != nil {
		return err
	}

	rtt := time.Since(start)

	if err := verifyEchoResponse(msg, response); err != nil {
		return err
	}

	log.Info().
		Int("test", testNum).
		Int("bytes", len(response)).
		Dur("rtt", rtt).
		Msg("echo verified")

	return nil
}

// sendTestMessage writes a test message to the connection.
func sendTestMessage(conn net.Conn, msg string) error {
	n, err := conn.Write([]byte(msg))
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	log.Debug().
		Int("bytes_sent", n).
		Msg("message sent")

	return nil
}

// readEchoResponse reads the echoed response from the connection until expected bytes are received.
func readEchoResponse(conn net.Conn, expected int) (string, error) {
	buf := make([]byte, 4096)
	totalRead := 0

	for totalRead < expected {
		n, err := conn.Read(buf[totalRead:])
		if err != nil {
			if err == io.EOF {
				return "", fmt.Errorf("unexpected EOF after %d bytes", totalRead)
			}
			return "", fmt.Errorf("read failed: %w", err)
		}
		totalRead += n
	}

	return string(buf[:totalRead]), nil
}

// verifyEchoResponse checks that the response matches the original message.
func verifyEchoResponse(sent, received string) error {
	if received != sent {
		return fmt.Errorf("echo mismatch: sent %q, got %q", sent, received)
	}
	return nil
}
