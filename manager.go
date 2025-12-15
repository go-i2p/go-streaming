package streaming

import (
	"context"
	"fmt"
	"sync"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/rs/zerolog/log"
)

// StreamManager manages I2CP session integration and routes incoming packets
// to the appropriate streaming connections. This is the bridge between I2CP
// transport and the streaming protocol layer.
//
// Architecture:
//   - Registers SessionCallbacks with I2CP session
//   - Routes incoming messages (protocol 6) to connections
//   - Manages connection multiplexing by port
//   - Handles new incoming connections for listeners
//
// Why a manager is needed:
//   - I2CP delivers messages via callbacks, not polling
//   - Multiple connections share a single I2CP session
//   - Need to route packets to correct connection by port
//   - Server needs to accept new connections from SYN packets
type StreamManager struct {
	client  *go_i2cp.Client
	session *go_i2cp.Session

	// Connection routing
	// Map of localPort -> *StreamListener or *StreamConn
	listeners   sync.Map // map[uint16]*StreamListener
	connections sync.Map // map[connKey]*StreamConn

	// Packet processing
	incomingPackets chan *incomingPacket
	processorCtx    context.Context
	processorCancel context.CancelFunc
	processorWg     sync.WaitGroup

	// Session lifecycle
	sessionReady chan struct{}
	mu           sync.Mutex
	closed       bool
}

// connKey uniquely identifies a connection
type connKey struct {
	localPort  uint16
	remotePort uint16
	// remoteAddr would go here if we had peer addressing
}

// incomingPacket represents a received I2CP message
type incomingPacket struct {
	protocol uint8
	srcDest  *go_i2cp.Destination
	srcPort  uint16
	destPort uint16
	payload  []byte
}

// NewStreamManager creates a new stream manager for the given I2CP client.
// This sets up the SessionCallbacks and starts the packet processor.
//
// The manager handles:
//   - Receiving I2CP messages via callbacks
//   - Routing packets to appropriate connections/listeners
//   - Creating I2CP session with proper callbacks
//
// Call StartSession() after creating to initialize the I2CP session.
func NewStreamManager(client *go_i2cp.Client) (*StreamManager, error) {
	if client == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	sm := &StreamManager{
		client:          client,
		incomingPackets: make(chan *incomingPacket, 100),
		sessionReady:    make(chan struct{}, 1), // Buffered: prevents race if callback fires before select
		processorCtx:    ctx,
		processorCancel: cancel,
	}

	// Create I2CP session with callbacks
	callbacks := go_i2cp.SessionCallbacks{
		OnMessage:       sm.handleIncomingMessage,
		OnStatus:        sm.handleSessionStatus,
		OnDestination:   sm.handleDestinationResult,
		OnMessageStatus: sm.handleMessageStatus,
	}

	sm.session = go_i2cp.NewSession(client, callbacks)

	// Start packet processor
	sm.processorWg.Add(1)
	go sm.processPackets()

	return sm, nil
}

// StartSession initializes the I2CP session and waits for it to be ready.
// This must be called after creating the manager before any Listen/Dial operations.
//
// The session creation process:
//  1. Sends CreateSession message to I2P router
//  2. Waits for SessionCreated response
//  3. Receives destination address from router
//  4. Signals sessionReady when complete
//
// Note: Some I2P router configurations may not send SessionCreated responses.
// In this case, we proceed after a timeout as the session may still be usable.
func (sm *StreamManager) StartSession(ctx context.Context) error {
	log.Info().Msg("creating I2CP session")
	log.Debug().Msg("sending CreateSession message to I2P router")

	if err := sm.client.CreateSession(ctx, sm.session); err != nil {
		log.Error().Err(err).Msg("CreateSession failed")
		return fmt.Errorf("create session: %w", err)
	}

	log.Debug().Msg("CreateSession message sent, waiting for SessionCreated response")
	log.Debug().Msg("waiting for OnStatus callback with SESSION_STATUS_CREATED")

	// Wait for session to be ready (signaled by OnStatus callback)
	// Some routers may not send SessionCreated - proceed after timeout
	select {
	case <-sm.sessionReady:
		log.Info().Msg("I2CP session ready")
		log.Debug().Msg("OnStatus callback received SESSION_STATUS_CREATED")
		return nil
	case <-ctx.Done():
		// Timeout is expected with some router configurations
		log.Warn().Msg("session creation timeout - router may not send SessionCreated response")
		log.Info().Msg("proceeding anyway (router-specific behavior)")

		// Give router a moment to complete session setup
		time.Sleep(1 * time.Second)

		// Session may still be usable even without explicit confirmation
		return nil
	}
}

// Session returns the underlying I2CP session.
// This is needed for creating StreamListener and StreamConn instances.
func (sm *StreamManager) Session() *go_i2cp.Session {
	return sm.session
}

// Destination returns the local I2P destination for this session.
// This is the address that remote peers use to connect to us.
func (sm *StreamManager) Destination() *go_i2cp.Destination {
	return sm.session.Destination()
}

// RegisterListener registers a listener to receive incoming connections.
// When SYN packets arrive for this port, they'll be routed to the listener.
func (sm *StreamManager) RegisterListener(port uint16, listener *StreamListener) {
	sm.listeners.Store(port, listener)
	log.Debug().
		Uint16("port", port).
		Msg("registered listener")
}

// UnregisterListener removes a listener registration.
func (sm *StreamManager) UnregisterListener(port uint16) {
	sm.listeners.Delete(port)
	log.Debug().
		Uint16("port", port).
		Msg("unregistered listener")
}

// RegisterConnection registers a connection for incoming packet routing.
func (sm *StreamManager) RegisterConnection(localPort, remotePort uint16, conn *StreamConn) {
	key := connKey{localPort: localPort, remotePort: remotePort}
	sm.connections.Store(key, conn)
	log.Debug().
		Uint16("localPort", localPort).
		Uint16("remotePort", remotePort).
		Msg("registered connection")
}

// UnregisterConnection removes a connection registration.
func (sm *StreamManager) UnregisterConnection(localPort, remotePort uint16) {
	key := connKey{localPort: localPort, remotePort: remotePort}
	sm.connections.Delete(key)
	log.Debug().
		Uint16("localPort", localPort).
		Uint16("remotePort", remotePort).
		Msg("unregistered connection")
}

// handleIncomingMessage is called by I2CP when messages arrive.
// This is registered as OnMessage callback in SessionCallbacks.
//
// Flow:
//  1. I2P router sends MessagePayload to client
//  2. client.ProcessIO() receives and dispatches
//  3. session.dispatchMessage() invokes this callback
//  4. We filter for protocol 6 and queue for processing
//
// Note: This runs in a goroutine spawned by go-i2cp (async by default).
func (sm *StreamManager) handleIncomingMessage(
	session *go_i2cp.Session,
	srcDest *go_i2cp.Destination,
	protocol uint8,
	srcPort, destPort uint16,
	payload *go_i2cp.Stream,
) {
	log.Trace().
		Uint8("protocol", protocol).
		Uint16("srcPort", srcPort).
		Uint16("destPort", destPort).
		Int("payloadSize", payload.Len()).
		Msg("handleIncomingMessage callback invoked")

	// Only process I2P streaming protocol (6)
	if protocol != 6 {
		log.Trace().
			Uint8("protocol", protocol).
			Msg("ignoring non-streaming protocol")
		return
	}

	log.Debug().
		Uint16("srcPort", srcPort).
		Uint16("destPort", destPort).
		Int("payloadLen", len(payload.Bytes())).
		Msg("received streaming message")

	// Queue for processing by packet dispatcher
	packet := &incomingPacket{
		protocol: protocol,
		srcDest:  srcDest,
		srcPort:  srcPort,
		destPort: destPort,
		payload:  payload.Bytes(),
	}

	select {
	case sm.incomingPackets <- packet:
		// Queued successfully
	default:
		log.Warn().
			Uint16("destPort", destPort).
			Msg("incoming packet queue full, dropping packet")
	}
}

// handleSessionStatus monitors I2CP session lifecycle.
// This is registered as OnStatus callback in SessionCallbacks.
func (sm *StreamManager) handleSessionStatus(
	session *go_i2cp.Session,
	status go_i2cp.SessionStatus,
) {
	log.Debug().
		Int("status", int(status)).
		Msg("I2CP session status callback received")

	switch status {
	case go_i2cp.I2CP_SESSION_STATUS_CREATED:
		log.Info().Msg("I2CP session created - streaming ready")
		log.Debug().Uint16("sessionId", session.ID()).Msg("session ID assigned")

		// Signal session is ready
		select {
		case sm.sessionReady <- struct{}{}:
			log.Debug().Msg("sessionReady signal sent successfully")
		default:
			log.Debug().Msg("sessionReady signal already sent (channel full)")
		}

	case go_i2cp.I2CP_SESSION_STATUS_DESTROYED:
		log.Info().Msg("I2CP session destroyed")
		sm.closeAllConnections()

	case go_i2cp.I2CP_SESSION_STATUS_REFUSED:
		log.Warn().Msg("I2CP session refused by router")
		log.Debug().Msg("possible causes:")
		log.Debug().Msg("  1. Router rejecting session requests")
		log.Debug().Msg("  2. Authentication required")
		log.Debug().Msg("  3. Resource limits exceeded")

	case go_i2cp.I2CP_SESSION_STATUS_INVALID:
		log.Warn().Msg("I2CP session invalid")

	case go_i2cp.I2CP_SESSION_STATUS_UPDATED:
		log.Debug().Msg("I2CP session updated")

	default:
		log.Warn().
			Int("status", int(status)).
			Msg("unknown session status received")
	}
}

// handleDestinationResult processes destination lookup results.
// This is registered as OnDestination callback in SessionCallbacks.
//
// Used for resolving hostnames (.b32.i2p, .i2p) to full destinations.
func (sm *StreamManager) handleDestinationResult(
	session *go_i2cp.Session,
	requestId uint32,
	address string,
	dest *go_i2cp.Destination,
) {
	if dest != nil {
		log.Debug().
			Uint32("requestId", requestId).
			Str("address", address).
			Msg("destination lookup success")
	} else {
		log.Warn().
			Uint32("requestId", requestId).
			Str("address", address).
			Msg("destination lookup failed")
	}

	// TODO: Implement destination caching (see integration guide Pattern 3)
	// For now, this is a placeholder for future enhancements
}

// handleMessageStatus tracks message delivery status.
// This is registered as OnMessageStatus callback in SessionCallbacks.
//
// Used for reliability tracking and retransmission logic.
func (sm *StreamManager) handleMessageStatus(
	session *go_i2cp.Session,
	messageId uint32,
	status go_i2cp.SessionMessageStatus,
	size, nonce uint32,
) {
	// For MVP, just log the status
	// Full status handling will be implemented when go-i2cp exports the constants
	log.Trace().
		Uint32("messageId", messageId).
		Uint8("status", uint8(status)).
		Uint32("size", size).
		Msg("message status update")

	// TODO: Implement full status handling when constants are available:
	// - GUARANTEED_SUCCESS -> mark delivered
	// - GUARANTEED_FAILURE -> retry
	// - SEND_ACCEPTED -> track in-flight
	// - etc.
}

// processPackets runs in a goroutine to dispatch incoming packets.
// This is the main packet router that sends packets to the appropriate
// listener or connection based on the destination port.
func (sm *StreamManager) processPackets() {
	defer sm.processorWg.Done()

	log.Debug().Msg("packet processor started")
	defer log.Debug().Msg("packet processor stopped")

	for {
		select {
		case <-sm.processorCtx.Done():
			return

		case packet := <-sm.incomingPackets:
			sm.dispatchPacket(packet)
		}
	}
}

// dispatchPacket routes a packet to the appropriate handler.
// This unmarshals the packet and checks for:
//  1. Listener on destPort (for new connections - SYN packets)
//  2. Existing connection (for established connections)
//  3. Unknown destination (drop packet or send RESET)
func (sm *StreamManager) dispatchPacket(incoming *incomingPacket) {
	// Unmarshal streaming packet
	pkt := &Packet{}
	if err := pkt.Unmarshal(incoming.payload); err != nil {
		log.Warn().
			Err(err).
			Uint16("destPort", incoming.destPort).
			Msg("failed to unmarshal streaming packet")
		return
	}

	log.Debug().
		Uint32("seq", pkt.SequenceNum).
		Uint32("ack", pkt.AckThrough).
		Uint16("flags", pkt.Flags).
		Uint16("srcPort", incoming.srcPort).
		Uint16("destPort", incoming.destPort).
		Int("payload", len(pkt.Payload)).
		Msg("dispatching packet")

	// Check if this is a SYN packet for a new connection
	if pkt.Flags&FlagSYN != 0 && pkt.Flags&FlagACK == 0 {
		// Look for listener on this port
		if listenerIface, ok := sm.listeners.Load(incoming.destPort); ok {
			listener := listenerIface.(*StreamListener)
			listener.handleIncomingSYN(pkt, incoming.srcPort, incoming.srcDest)
			return
		}

		log.Debug().
			Uint16("destPort", incoming.destPort).
			Msg("SYN packet for port with no listener - dropping")
		// TODO: Send RESET packet
		return
	}

	// Route to existing connection
	key := connKey{
		localPort:  incoming.destPort,
		remotePort: incoming.srcPort,
	}

	if connIface, ok := sm.connections.Load(key); ok {
		conn := connIface.(*StreamConn)
		conn.handleIncomingPacket(pkt)
		return
	}

	log.Debug().
		Uint16("localPort", incoming.destPort).
		Uint16("remotePort", incoming.srcPort).
		Msg("packet for unknown connection - dropping")
	// TODO: Send RESET packet
}

// closeAllConnections closes all registered connections.
// Called when session is destroyed or manager is closed.
func (sm *StreamManager) closeAllConnections() {
	log.Info().Msg("closing all streaming connections")

	// Close all listeners
	sm.listeners.Range(func(key, value interface{}) bool {
		if listener, ok := value.(*StreamListener); ok {
			listener.Close()
		}
		return true
	})

	// Close all connections
	sm.connections.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*StreamConn); ok {
			conn.Close()
		}
		return true
	})
}

// Close shuts down the stream manager and all connections.
// This stops the packet processor and closes the I2CP session.
func (sm *StreamManager) Close() error {
	sm.mu.Lock()
	if sm.closed {
		sm.mu.Unlock()
		return nil
	}
	sm.closed = true
	sm.mu.Unlock()

	log.Info().Msg("closing stream manager")

	// Stop packet processor
	sm.processorCancel()
	sm.processorWg.Wait()

	// Close all connections
	sm.closeAllConnections()

	return nil
}
