// Echo server example for go-i2p/go-streaming
//
// This demonstrates a simple TCP-like echo server that listens for incoming
// I2P streaming connections and echoes back any data received.
//
// IMPORTANT: This example requires:
//   - I2P router running locally with I2CP enabled (default port 7654)
//   - Router must be bootstrapped and connected to the I2P network
//   - A valid I2CP session (session creation code omitted for brevity)
//
// Usage (conceptual - requires session setup):
//
//	go run server/main.go
//
// The server will:
// 1. Listen for incoming streaming connections
// 2. For each connection, read data and echo it back
// 3. Log connection lifecycle and data transfer
//
// NOTE: This is a demonstration of the streaming API.
// Production code would include proper I2CP session management,
// error recovery, and graceful shutdown.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
	streaming "github.com/go-i2p/go-streaming"
	"github.com/go-i2p/logger"
)

var log = logger.GetGoI2PLogger()

func main() {
	log.Info("starting I2P echo server")

	client := createI2CPClient()
	defer client.Close()

	// IMPORTANT: Start ProcessIO loop BEFORE creating the stream manager.
	// ProcessIO must be running to receive SessionCreated responses from the router.
	startProcessIOLoop(client)

	manager := createStreamManager(client)
	defer manager.Close()

	listener := createListener(manager)
	defer listener.Close()
	// print the destination for clients to connect
	if dest := manager.Destination(); dest != nil {
		log.WithField("destination", dest.Base64()).Info("server destination")
	}

	shutdownCtx, shutdownCancel := setupShutdownHandler(listener)
	defer shutdownCancel()

	runAcceptLoop(shutdownCtx, listener)
}

// createI2CPClient creates a new I2CP client and connects to the I2P router.
// It terminates the program with a fatal error if the connection fails.
func createI2CPClient() *go_i2cp.Client {
	client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Info("connecting to I2P router at 127.0.0.1:7654")
	if err := client.Connect(ctx); err != nil {
		log.WithError(err).Fatal("failed to connect to I2P router")
	}

	log.Info("connected to I2P router")
	return client
}

// createStreamManager creates a stream manager from the I2CP client and starts
// an I2CP session. It terminates the program with a fatal error on failure.
func createStreamManager(client *go_i2cp.Client) *streaming.StreamManager {
	log.Info("creating stream manager and starting session")
	manager, err := streaming.NewStreamManager(client)
	if err != nil {
		log.WithError(err).Fatal("failed to create stream manager")
	}

	if err := manager.StartSession(context.Background()); err != nil {
		log.WithError(err).Fatal("failed to start session")
	}

	if dest := manager.Destination(); dest != nil {
		log.WithField("destination", "session created").Info("I2CP session ready")
	}

	return manager
}

// startProcessIOLoop starts a background goroutine that continuously processes
// I2CP I/O operations. This is required for callbacks to function properly.
func startProcessIOLoop(client *go_i2cp.Client) {
	go func() {
		log.Info("starting I2CP ProcessIO loop")
		for {
			if err := client.ProcessIO(context.Background()); err != nil {
				if err == go_i2cp.ErrClientClosed {
					log.Info("I2CP client closed")
					return
				}
				log.WithError(err).Error("I/O processing error")
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
}

// createListener creates a streaming listener on port 8080 with the default MTU.
// It terminates the program with a fatal error if listener creation fails.
func createListener(manager *streaming.StreamManager) *streaming.StreamListener {
	const listenPort = 8080
	listener, err := streaming.ListenWithManager(manager, listenPort, streaming.DefaultMTU)
	if err != nil {
		log.WithError(err).Fatal("failed to create listener")
	}

	log.WithField("addr", listener.Addr().String()).Info("listening for connections")

	return listener
}

// setupShutdownHandler configures graceful shutdown handling for OS signals.
// It returns a context that will be cancelled on SIGINT or SIGTERM, and a
// cancel function that should be deferred by the caller.
func setupShutdownHandler(listener *streaming.StreamListener) (context.Context, context.CancelFunc) {
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Info("received shutdown signal")
		shutdownCancel()
		listener.Close()
	}()

	return shutdownCtx, shutdownCancel
}

// runAcceptLoop continuously accepts incoming connections and handles them
// in separate goroutines until the shutdown context is cancelled.
func runAcceptLoop(shutdownCtx context.Context, listener *streaming.StreamListener) {
	for {
		if shutdownCtx.Err() != nil {
			log.Info("shutting down")
			return
		}

		conn := acceptConnection(shutdownCtx, listener)
		if conn == nil {
			continue
		}

		go handleConnection(shutdownCtx, conn)
	}
}

// acceptConnection attempts to accept a single connection from the listener.
// It returns nil if the shutdown context is cancelled or if accept fails.
func acceptConnection(shutdownCtx context.Context, listener *streaming.StreamListener) net.Conn {
	conn, err := listener.Accept()
	if err != nil {
		if shutdownCtx.Err() != nil {
			return nil
		}
		log.WithError(err).Error("accept failed")
		return nil
	}

	log.WithField("remote", conn.RemoteAddr().String()).Info("accepted connection")

	return conn
}

// handleConnection echoes data back to the client.
// This demonstrates using the streaming connection as a standard net.Conn.
func handleConnection(ctx context.Context, conn net.Conn) {
	defer closeConnection(conn)

	conn.SetReadDeadline(time.Now().Add(90 * time.Second))

	buf := make([]byte, 4096)
	totalBytes := 0

	for {
		if ctx.Err() != nil {
			return
		}

		n, done := readFromClient(conn, buf, totalBytes)
		if done {
			return
		}
		if n == 0 {
			continue
		}

		totalBytes += n
		logReceivedData(conn, buf[:n])

		if !echoToClient(conn, buf[:n]) {
			return
		}

		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	}
}

// closeConnection closes the connection and logs the closure.
func closeConnection(conn net.Conn) {
	conn.Close()
	log.WithField("remote", conn.RemoteAddr().String()).Info("connection closed")
}

// readFromClient reads data from the client connection into the buffer.
// It returns the number of bytes read and a boolean indicating if the connection should terminate.
func readFromClient(conn net.Conn, buf []byte, totalBytes int) (int, bool) {
	n, err := conn.Read(buf)
	if err != nil {
		if err == io.EOF {
			log.WithFields(logger.Fields{
				"remote":      conn.RemoteAddr().String(),
				"total_bytes": totalBytes,
			}).Info("client closed connection")
			return 0, true
		}
		log.WithError(err).WithField("remote", conn.RemoteAddr().String()).Error("read error")
		return 0, true
	}
	return n, false
}

// logReceivedData logs debug information about received data.
func logReceivedData(conn net.Conn, data []byte) {
	log.WithFields(logger.Fields{
		"remote":  conn.RemoteAddr().String(),
		"bytes":   len(data),
		"preview": fmt.Sprintf("%.50s", data),
	}).Debug("received data")
}

// echoToClient writes data back to the client connection.
// It returns true if the write was successful, false otherwise.
func echoToClient(conn net.Conn, data []byte) bool {
	written, err := conn.Write(data)
	if err != nil {
		log.WithError(err).WithField("remote", conn.RemoteAddr().String()).Error("write error")
		return false
	}

	log.WithFields(logger.Fields{
		"remote": conn.RemoteAddr().String(),
		"bytes":  written,
	}).Debug("echoed data")

	return true
}
