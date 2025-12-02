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
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Configure logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	log.Info().Msg("starting I2P echo server")

	// Create I2CP client with empty callbacks
	// The StreamManager will register SessionCallbacks for packet routing
	client := go_i2cp.NewClient(&go_i2cp.ClientCallBacks{})

	// Connect to I2P router with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Info().Msg("connecting to I2P router at 127.0.0.1:7654")
	if err := client.Connect(ctx); err != nil {
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

	// Get our destination address
	dest := manager.Destination()
	if dest != nil {
		log.Info().
			Str("destination", "session created").
			Msg("I2CP session ready")
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
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	// Create streaming listener on port 8080 with default MTU
	const listenPort = 8080
	listener, err := streaming.ListenWithManager(manager, listenPort, streaming.DefaultMTU)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create listener")
	}
	defer listener.Close()

	log.Info().
		Str("addr", listener.Addr().String()).
		Msg("listening for connections")

	// Handle graceful shutdown
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	defer shutdownCancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Info().Msg("received shutdown signal")
		shutdownCancel()
		listener.Close()
	}()

	// Accept loop
	for {
		select {
		case <-shutdownCtx.Done():
			log.Info().Msg("shutting down")
			return
		default:
		}

		// Accept returns net.Conn interface
		conn, err := listener.Accept()
		if err != nil {
			if shutdownCtx.Err() != nil {
				return
			}
			log.Error().Err(err).Msg("accept failed")
			continue
		}

		log.Info().
			Str("remote", conn.RemoteAddr().String()).
			Msg("accepted connection")

		// Handle connection in goroutine
		go handleConnection(shutdownCtx, conn)
	}
}

// handleConnection echoes data back to the client
// This demonstrates using the streaming connection as a standard net.Conn
func handleConnection(ctx context.Context, conn net.Conn) {
	defer func() {
		conn.Close()
		log.Info().
			Str("remote", conn.RemoteAddr().String()).
			Msg("connection closed")
	}()

	// Set read timeout to detect inactive connections
	conn.SetReadDeadline(time.Now().Add(90 * time.Second))

	buf := make([]byte, 4096)
	totalBytes := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read data from client
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				log.Info().
					Str("remote", conn.RemoteAddr().String()).
					Int("total_bytes", totalBytes).
					Msg("client closed connection")
				return
			}
			log.Error().
				Err(err).
				Str("remote", conn.RemoteAddr().String()).
				Msg("read error")
			return
		}

		if n == 0 {
			continue
		}

		totalBytes += n

		log.Debug().
			Str("remote", conn.RemoteAddr().String()).
			Int("bytes", n).
			Str("preview", fmt.Sprintf("%.50s", buf[:n])).
			Msg("received data")

		// Echo data back to client
		written, err := conn.Write(buf[:n])
		if err != nil {
			log.Error().
				Err(err).
				Str("remote", conn.RemoteAddr().String()).
				Msg("write error")
			return
		}

		log.Debug().
			Str("remote", conn.RemoteAddr().String()).
			Int("bytes", written).
			Msg("echoed data")

		// Reset read deadline after successful read/write
		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	}
}
