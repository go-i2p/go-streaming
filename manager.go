package streaming

import (
	"context"
	"fmt"
	"sync"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
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
//   - Handles ping/pong (ECHO) packets per I2P streaming spec
//
// Why a manager is needed:
//   - I2CP delivers messages via callbacks, not polling
//   - Multiple connections share a single I2P session
//   - Need to route packets to correct connection by port
//   - Server needs to accept new connections from SYN packets
type StreamManager struct {
	client  *go_i2cp.Client
	session *go_i2cp.Session

	// Connection routing
	// Map of localPort -> *StreamListener or *StreamConn
	listeners   sync.Map // map[uint16]*StreamListener
	connections sync.Map // map[connKey]*StreamConn

	// Ping/pong handling
	pingMgr *pingManager

	// Connection rate limiting
	limiter *connectionLimiter

	// Access list filtering
	accessFilter *accessFilter

	// Message status tracking for reliable delivery
	msgTracker *messageStatusTracker

	// TCB cache for RFC 2140 control block sharing
	// Shares RTT, RTT variance, and window size between connections to same peer
	tcbCache *tcbCache

	// Profile configuration for traffic pattern hints
	// Per I2P spec: i2p.streaming.profile option
	profileConfig ProfileConfig

	// Packet processing
	incomingPackets chan *incomingPacket
	processorCtx    context.Context
	processorCancel context.CancelFunc
	processorWg     sync.WaitGroup

	// Session lifecycle
	sessionReady  chan struct{}
	leaseSetReady chan struct{}
	leaseSetOnce  sync.Once
	mu            sync.Mutex
	closed        bool

	// Destination lookup results
	lookupResults sync.Map // map[uint32]*lookupResult
}

// lookupResult stores the result of a destination lookup
type lookupResult struct {
	address string
	dest    *go_i2cp.Destination
	ready   chan struct{}
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
		leaseSetReady:   make(chan struct{}),    // Non-buffered: signal can only fire once via sync.Once
		processorCtx:    ctx,
		processorCancel: cancel,
	}

	// Initialize ping manager with default config
	sm.pingMgr = newPingManager(sm, DefaultPingConfig())

	// Initialize connection limiter with default config (unlimited)
	sm.limiter = newConnectionLimiter(DefaultConnectionLimitsConfig())

	// Initialize access filter with default config (disabled)
	sm.accessFilter = newAccessFilter(DefaultAccessListConfig())

	// Initialize message status tracker for delivery confirmation
	sm.msgTracker = newMessageStatusTracker(sm)

	// Initialize TCB cache for RFC 2140 control block sharing
	sm.tcbCache = newTCBCache(DefaultTCBCacheConfig())

	// Initialize profile config with default (bulk)
	sm.profileConfig = DefaultProfileConfig()

	// Create I2CP session with callbacks
	callbacks := go_i2cp.SessionCallbacks{
		OnMessage:       sm.handleIncomingMessage,
		OnStatus:        sm.handleSessionStatus,
		OnDestination:   sm.handleDestinationResult,
		OnMessageStatus: sm.handleMessageStatus,
		OnLeaseSet2:     sm.handleLeaseSet2,
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
	log.Info("creating I2CP session")
	log.Debug("sending CreateSession message to I2P router")

	if err := sm.client.CreateSession(ctx, sm.session); err != nil {
		log.WithError(err).Error("CreateSession failed")
		return fmt.Errorf("create session: %w", err)
	}

	log.Debug("CreateSession message sent, waiting for SessionCreated response")
	log.Debug("waiting for OnStatus callback with SESSION_STATUS_CREATED")

	// Wait for session to be ready (signaled by OnStatus callback)
	// Some routers may not send SessionCreated - proceed after timeout
	select {
	case <-sm.sessionReady:
		log.Info("I2CP session ready")
		log.Debug("OnStatus callback received SESSION_STATUS_CREATED")
		return nil
	case <-ctx.Done():
		// Timeout is expected with some router configurations
		log.Warn("session creation timeout - router may not send SessionCreated response")
		log.Info("proceeding anyway (router-specific behavior)")

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
	log.WithField("port", port).Debug("registered listener")
}

// UnregisterListener removes a listener registration.
func (sm *StreamManager) UnregisterListener(port uint16) {
	sm.listeners.Delete(port)
	log.WithField("port", port).Debug("unregistered listener")
}

// LookupDestination performs a destination lookup and waits for the result.
// This is a convenience method that handles the request tracking and result retrieval.
func (sm *StreamManager) LookupDestination(ctx context.Context, hostname string) (*go_i2cp.Destination, error) {
	// Register result tracker
	result := &lookupResult{
		ready: make(chan struct{}),
	}

	// Initiate lookup
	requestID, err := sm.client.DestinationLookup(ctx, sm.session, hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate lookup: %w", err)
	}

	// Store the result tracker
	sm.lookupResults.Store(requestID, result)
	defer sm.lookupResults.Delete(requestID)

	// Wait for result
	select {
	case <-result.ready:
		if result.dest == nil {
			return nil, fmt.Errorf("destination lookup failed for %s", hostname)
		}
		return result.dest, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// RegisterConnection registers a connection for incoming packet routing.
func (sm *StreamManager) RegisterConnection(localPort, remotePort uint16, conn *StreamConn) {
	key := connKey{localPort: localPort, remotePort: remotePort}
	sm.connections.Store(key, conn)
	log.WithFields(map[string]interface{}{
		"localPort":  localPort,
		"remotePort": remotePort,
	}).Debug("registered connection")
}

// UnregisterConnection removes a connection registration.
func (sm *StreamManager) UnregisterConnection(localPort, remotePort uint16) {
	key := connKey{localPort: localPort, remotePort: remotePort}
	sm.connections.Delete(key)
	log.WithFields(map[string]interface{}{
		"localPort":  localPort,
		"remotePort": remotePort,
	}).Debug("unregistered connection")
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
	log.WithFields(map[string]interface{}{
		"protocol":    protocol,
		"srcPort":     srcPort,
		"destPort":    destPort,
		"payloadSize": payload.Len(),
	}).Debug("handleIncomingMessage callback invoked")

	// Only process I2P streaming protocol (6)
	if protocol != 6 {
		log.WithField("protocol", protocol).Debug("ignoring non-streaming protocol")
		return
	}

	log.WithFields(map[string]interface{}{
		"srcPort":    srcPort,
		"destPort":   destPort,
		"payloadLen": len(payload.Bytes()),
	}).Debug("received streaming message")

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
		log.WithField("destPort", destPort).Warn("incoming packet queue full, dropping packet")
	}
}

// handleSessionStatus monitors I2CP session lifecycle.
// This is registered as OnStatus callback in SessionCallbacks.
func (sm *StreamManager) handleSessionStatus(
	session *go_i2cp.Session,
	status go_i2cp.SessionStatus,
) {
	log.WithField("status", int(status)).Debug("I2CP session status callback received")

	switch status {
	case go_i2cp.I2CP_SESSION_STATUS_CREATED:
		log.Info("I2CP session created - streaming ready")
		log.WithField("sessionId", session.ID()).Debug("session ID assigned")

		// Signal session is ready
		select {
		case sm.sessionReady <- struct{}{}:
			log.Debug("sessionReady signal sent successfully")
		default:
			log.Debug("sessionReady signal already sent (channel full)")
		}

	case go_i2cp.I2CP_SESSION_STATUS_DESTROYED:
		log.Info("I2CP session destroyed")
		sm.closeAllConnections()

	case go_i2cp.I2CP_SESSION_STATUS_REFUSED:
		log.Warn("I2CP session refused by router")
		log.Debug("possible causes:")
		log.Debug("  1. Router rejecting session requests")
		log.Debug("  2. Authentication required")
		log.Debug("  3. Resource limits exceeded")

	case go_i2cp.I2CP_SESSION_STATUS_INVALID:
		log.Warn("I2CP session invalid")

	case go_i2cp.I2CP_SESSION_STATUS_UPDATED:
		log.Debug("I2CP session updated")

	default:
		log.WithField("status", int(status)).Warn("unknown session status received")
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
		log.WithFields(map[string]interface{}{
			"requestId": requestId,
			"address":   address,
		}).Debug("destination lookup success")
	} else {
		log.WithFields(map[string]interface{}{
			"requestId": requestId,
			"address":   address,
		}).Warn("destination lookup failed")
	}

	// Store the lookup result
	if result, ok := sm.lookupResults.Load(requestId); ok {
		lr := result.(*lookupResult)
		lr.address = address
		lr.dest = dest
		close(lr.ready)
	}
}

// handleMessageStatus tracks message delivery status.
// This is registered as OnMessageStatus callback in SessionCallbacks.
//
// Used for reliability tracking and retransmission logic.
// Now fully implemented using go-i2cp's exported status constants.
func (sm *StreamManager) handleMessageStatus(
	session *go_i2cp.Session,
	messageId uint32,
	status go_i2cp.SessionMessageStatus,
	size, nonce uint32,
) {
	// Get the status category for logging
	category := go_i2cp.GetMessageStatusCategory(status)

	log.WithFields(map[string]interface{}{
		"messageId": messageId,
		"status":    uint8(status),
		"category":  category,
		"size":      size,
	}).Debug("message status update")

	// Delegate to the message status tracker for proper handling
	if sm.msgTracker != nil {
		sm.msgTracker.HandleStatus(messageId, status, size, nonce)
	}
}

// GetMessageStats returns the current message delivery statistics.
func (sm *StreamManager) GetMessageStats() MessageStats {
	if sm.msgTracker == nil {
		return MessageStats{}
	}
	return sm.msgTracker.GetStats()
}

// MessageTracker returns the message status tracker for this manager.
// This is used internally by connections to track outgoing messages.
func (sm *StreamManager) MessageTracker() *messageStatusTracker {
	return sm.msgTracker
}

// GetStreamProfile returns the configured stream profile hint.
// Returns ProfileBulk (1) for bulk transfer or ProfileInteractive (2) for interactive.
func (sm *StreamManager) GetStreamProfile() StreamProfile {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.profileConfig.Profile
}

// SetStreamProfile sets the stream profile hint for new connections.
// ProfileBulk (1) is optimized for large data transfers.
// ProfileInteractive (2) is optimized for low-latency exchanges.
func (sm *StreamManager) SetStreamProfile(profile StreamProfile) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.profileConfig.Profile = profile
}

// processPackets runs in a goroutine to dispatch incoming packets.
// This is the main packet router that sends packets to the appropriate
// listener or connection based on the destination port.
func (sm *StreamManager) processPackets() {
	defer sm.processorWg.Done()

	log.Debug("packet processor started")
	defer log.Debug("packet processor stopped")

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
//  0. ECHO packets (ping/pong) - handled specially per I2P streaming spec
//  1. Listener on destPort (for new connections - SYN packets)
//  2. Existing connection (for established connections)
//  3. Unknown destination (drop packet or send RESET)
func (sm *StreamManager) dispatchPacket(incoming *incomingPacket) {
	pkt, err := sm.unmarshalIncomingPacket(incoming)
	if err != nil {
		return
	}

	sm.logDispatchingPacket(pkt, incoming)

	// Per spec: "if the ECHO option is set, then most other flags, options,
	// ackThrough, sequenceNum, NACKs, etc. are ignored."
	// Handle ECHO packets before any other routing.
	if pkt.Flags&FlagECHO != 0 {
		sm.handleEchoPacket(pkt, incoming)
		return
	}

	if sm.isSynPacket(pkt) {
		sm.handleSynPacket(pkt, incoming)
		return
	}

	sm.routeToConnection(pkt, incoming)
}

// unmarshalIncomingPacket unmarshals the streaming packet from incoming payload.
func (sm *StreamManager) unmarshalIncomingPacket(incoming *incomingPacket) (*Packet, error) {
	pkt := &Packet{}
	if err := pkt.Unmarshal(incoming.payload); err != nil {
		log.WithError(err).WithField("destPort", incoming.destPort).Warn("failed to unmarshal streaming packet")
		return nil, err
	}
	return pkt, nil
}

// logDispatchingPacket logs debug information about a dispatched packet.
func (sm *StreamManager) logDispatchingPacket(pkt *Packet, incoming *incomingPacket) {
	log.WithFields(map[string]interface{}{
		"seq":      pkt.SequenceNum,
		"ack":      pkt.AckThrough,
		"flags":    pkt.Flags,
		"srcPort":  incoming.srcPort,
		"destPort": incoming.destPort,
		"payload":  len(pkt.Payload),
	}).Debug("dispatching packet")
}

// isSynPacket checks if the packet is a SYN packet for a new connection.
// Per I2P streaming spec, the initial SYN has SendStreamID=0 (unknown) since
// the receiver hasn't yet assigned their stream ID. A SYN-ACK response will
// have SendStreamID > 0.
func (sm *StreamManager) isSynPacket(pkt *Packet) bool {
	return pkt.Flags&FlagSYN != 0 && pkt.SendStreamID == 0
}

// handleEchoPacket handles ping and pong packets per I2P streaming spec.
// Per spec:
//   - Ping: ECHO flag set, sendStreamId > 0 (response with pong)
//   - Pong: ECHO flag set, sendStreamId == 0 (resolve pending ping)
func (sm *StreamManager) handleEchoPacket(pkt *Packet, incoming *incomingPacket) {
	if isPingPacket(pkt) {
		log.WithFields(map[string]interface{}{
			"streamID":   pkt.SendStreamID,
			"payloadLen": len(pkt.Payload),
		}).Debug("received ping")
		sm.pingMgr.handlePing(pkt, incoming.srcDest, incoming.srcPort, incoming.destPort)
	} else if isPongPacket(pkt) {
		log.WithFields(map[string]interface{}{
			"streamID":   pkt.RecvStreamID,
			"payloadLen": len(pkt.Payload),
		}).Debug("received pong")
		sm.pingMgr.handlePong(pkt)
	} else {
		log.WithFields(map[string]interface{}{
			"flags":        pkt.Flags,
			"sendStreamID": pkt.SendStreamID,
		}).Debug("received ECHO packet with unexpected format")
	}
}

// Ping sends a ping packet to the specified destination and waits for a pong response.
// This implements the I2P streaming ping/pong mechanism per specification.
//
// Per spec:
//   - A ping packet has ECHO, SIGNATURE_INCLUDED, and FROM_INCLUDED flags set
//   - The sendStreamId must be greater than zero
//   - Payload up to 32 bytes is echoed back in the pong
//
// Example:
//
//	result := manager.Ping(ctx, destination, []byte("hello"))
//	if result.Err != nil {
//	    log.WithError(result.Err).Error("ping failed")
//	} else {
//	    log.WithField("rtt", result.RTT).Info("ping successful")
//	}
func (sm *StreamManager) Ping(ctx context.Context, dest *go_i2cp.Destination, payload []byte) *PingResult {
	return sm.pingMgr.Ping(ctx, dest, payload)
}

// SetPingConfig updates the ping configuration.
// Use this to enable/disable answering pings or adjust timeout.
func (sm *StreamManager) SetPingConfig(config *PingConfig) {
	if config == nil {
		config = DefaultPingConfig()
	}
	sm.pingMgr.mu.Lock()
	sm.pingMgr.config = config
	sm.pingMgr.mu.Unlock()
}

// GetPingConfig returns a copy of the current ping configuration.
func (sm *StreamManager) GetPingConfig() *PingConfig {
	sm.pingMgr.mu.Lock()
	defer sm.pingMgr.mu.Unlock()
	return &PingConfig{
		AnswerPings: sm.pingMgr.config.AnswerPings,
		PingTimeout: sm.pingMgr.config.PingTimeout,
	}
}

// SetConnectionLimits updates the connection rate limiting configuration.
// Use this to protect against connection flooding attacks.
//
// Example:
//
//	manager.SetConnectionLimits(&streaming.ConnectionLimitsConfig{
//	    MaxConcurrentStreams: 100,
//	    MaxConnsPerMinute:    10,
//	    LimitAction:          streaming.LimitActionReset,
//	})
func (sm *StreamManager) SetConnectionLimits(config *ConnectionLimitsConfig) {
	sm.limiter.SetConfig(config)
}

// GetConnectionLimits returns a copy of the current connection limits configuration.
func (sm *StreamManager) GetConnectionLimits() *ConnectionLimitsConfig {
	return sm.limiter.GetConfig()
}

// ActiveStreams returns the current number of active streams.
func (sm *StreamManager) ActiveStreams() int {
	return sm.limiter.ActiveStreams()
}

// ConnectionLimiter returns the connection limiter for this manager.
// This is used internally by listeners to check limits.
func (sm *StreamManager) ConnectionLimiter() *connectionLimiter {
	return sm.limiter
}

// SetAccessFilter configures the access list filtering for this manager.
// Pass nil to use default (disabled) configuration.
func (sm *StreamManager) SetAccessFilter(config *AccessListConfig) {
	if config == nil {
		config = DefaultAccessListConfig()
	}
	sm.accessFilter = newAccessFilter(config)
}

// GetAccessFilter returns a copy of the current access filter configuration.
func (sm *StreamManager) GetAccessFilter() *AccessListConfig {
	return sm.accessFilter.GetConfig()
}

// AccessFilter returns the access filter for this manager.
// This is used internally by listeners to check access permissions.
func (sm *StreamManager) AccessFilter() *accessFilter {
	return sm.accessFilter
}

// AddToAccessList adds a destination hash to the access list.
// The hash should be the base64 representation of the destination hash.
func (sm *StreamManager) AddToAccessList(hash string) {
	sm.accessFilter.AddHash(hash)
}

// RemoveFromAccessList removes a destination hash from the access list.
func (sm *StreamManager) RemoveFromAccessList(hash string) {
	sm.accessFilter.RemoveHash(hash)
}

// SetAccessListEnabled enables or disables access list filtering.
func (sm *StreamManager) SetAccessListEnabled(enabled bool, mode AccessListMode) {
	config := sm.accessFilter.GetConfig()
	if enabled {
		config.Mode = mode
	} else {
		config.Mode = AccessListModeDisabled
	}
	sm.accessFilter.SetConfig(config)
}

// SetAccessListMode sets the access list mode (whitelist or blacklist).
func (sm *StreamManager) SetAccessListMode(mode AccessListMode) {
	config := sm.accessFilter.GetConfig()
	config.Mode = mode
	sm.accessFilter.SetConfig(config)
}

// handleSynPacket handles a SYN packet by routing to a listener or sending RESET.
func (sm *StreamManager) handleSynPacket(pkt *Packet, incoming *incomingPacket) {
	if listenerIface, ok := sm.listeners.Load(incoming.destPort); ok {
		listener := listenerIface.(*StreamListener)
		listener.handleIncomingSYN(pkt, incoming.srcPort, incoming.srcDest)
		return
	}
	log.WithField("destPort", incoming.destPort).Debug("SYN packet for port with no listener - sending RESET")
	sm.sendResetPacket(incoming.srcDest, pkt.SendStreamID, incoming.destPort, incoming.srcPort)
}

// routeToConnection routes a packet to an existing connection or sends RESET.
func (sm *StreamManager) routeToConnection(pkt *Packet, incoming *incomingPacket) {
	key := connKey{localPort: incoming.destPort, remotePort: incoming.srcPort}
	if connIface, ok := sm.connections.Load(key); ok {
		conn := connIface.(*StreamConn)
		conn.handleIncomingPacket(pkt)
		return
	}
	log.WithFields(map[string]interface{}{
		"localPort":  incoming.destPort,
		"remotePort": incoming.srcPort,
	}).Debug("packet for unknown connection - sending RESET")
	sm.sendResetPacket(incoming.srcDest, pkt.SendStreamID, incoming.destPort, incoming.srcPort)
}

// closeAllConnections closes all registered connections.
// Called when session is destroyed or manager is closed.
func (sm *StreamManager) closeAllConnections() {
	log.Info("closing all streaming connections")

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

// handleLeaseSet2 is called when the I2P router publishes our LeaseSet.
// This indicates that our inbound tunnels are ready and the router has
// published our destination to the network, allowing other peers to reach us.
func (sm *StreamManager) handleLeaseSet2(session *go_i2cp.Session, leaseSet *go_i2cp.LeaseSet2) {
	log.WithFields(map[string]interface{}{
		"type":    leaseSet.Type(),
		"leases":  leaseSet.LeaseCount(),
		"expires": leaseSet.Expires(),
	}).Info("LeaseSet published")

	// Signal that our LeaseSet is ready (only once)
	sm.leaseSetOnce.Do(func() {
		close(sm.leaseSetReady)
	})
}

// sendResetPacket sends a RESET packet to notify a peer that their connection
// or SYN request is invalid. Per I2P streaming spec, RESET should be sent for:
//   - Packets for unknown connections
//   - SYN packets for ports with no listener
//   - Connection limit exceeded (when implemented)
//
// The RESET packet contains:
//   - SendStreamID: 0 (we don't have a local stream for this)
//   - RecvStreamID: The sender's stream ID (so they know which connection to reset)
//   - Flags: FlagRESET
//   - Optional signature if session has signing capability
//
// Parameters:
//   - dest: The remote destination to send the RESET to
//   - remoteStreamID: The stream ID from the received packet (becomes RecvStreamID)
//   - localPort: Our local port (for logging)
//   - remotePort: Remote port to send to
func (sm *StreamManager) sendResetPacket(dest *go_i2cp.Destination, remoteStreamID uint32, localPort, remotePort uint16) {
	if err := sm.validateResetPrerequisites(dest); err != nil {
		log.WithError(err).Warn("cannot send RESET")
		return
	}

	pkt := sm.createResetPacket(remoteStreamID)
	sm.signResetPacket(pkt)

	if err := sm.sendPacketToDest(pkt, dest, localPort, remotePort); err != nil {
		log.WithError(err).WithFields(map[string]interface{}{
			"localPort":  localPort,
			"remotePort": remotePort,
		}).Warn("failed to send RESET packet")
		return
	}

	log.WithFields(map[string]interface{}{
		"remoteStreamID": remoteStreamID,
		"localPort":      localPort,
		"remotePort":     remotePort,
	}).Debug("sent RESET packet")
}

// validateResetPrerequisites checks that dest and session are valid for sending RESET.
func (sm *StreamManager) validateResetPrerequisites(dest *go_i2cp.Destination) error {
	if dest == nil {
		return fmt.Errorf("destination is nil")
	}
	if sm.session == nil {
		return fmt.Errorf("no I2CP session")
	}
	return nil
}

// createResetPacket builds a RESET packet with the given remote stream ID.
func (sm *StreamManager) createResetPacket(remoteStreamID uint32) *Packet {
	return &Packet{
		SendStreamID:    0,              // No local stream
		RecvStreamID:    remoteStreamID, // Remote's stream ID
		SequenceNum:     0,              // Not relevant for RESET
		AckThrough:      0,              // Not relevant for RESET
		Flags:           FlagRESET | FlagSignatureIncluded | FlagFromIncluded,
		FromDestination: sm.session.Destination(),
	}
}

// signResetPacket attempts to sign the packet, clearing signature flag on failure.
func (sm *StreamManager) signResetPacket(pkt *Packet) {
	keyPair, err := sm.session.SigningKeyPair()
	if err != nil {
		log.WithError(err).Warn("failed to get signing key pair for RESET packet - sending unsigned")
		pkt.Flags &^= FlagSignatureIncluded
		return
	}

	if err := SignPacket(pkt, keyPair); err != nil {
		log.WithError(err).Warn("failed to sign RESET packet - sending unsigned")
		pkt.Flags &^= FlagSignatureIncluded
	}
}

// sendPacketToDest marshals and sends a packet to the specified destination.
func (sm *StreamManager) sendPacketToDest(pkt *Packet, dest *go_i2cp.Destination, localPort, remotePort uint16) error {
	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal packet: %w", err)
	}

	stream := go_i2cp.NewStream(data)
	return sm.session.SendMessage(dest, 6, localPort, remotePort, stream, 0)
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

	log.Info("closing stream manager")

	// Stop packet processor
	sm.processorCancel()
	sm.processorWg.Wait()

	// Close all connections
	sm.closeAllConnections()

	return nil
}

// TCBCache returns the TCB cache instance for direct access.
// The TCB cache implements RFC 2140 control block sharing, storing
// RTT, RTT variance, and window size estimates per remote peer.
func (sm *StreamManager) TCBCache() *tcbCache {
	return sm.tcbCache
}

// GetTCBCacheConfig returns the current TCB cache configuration.
func (sm *StreamManager) GetTCBCacheConfig() TCBCacheConfig {
	return sm.tcbCache.GetConfig()
}

// SetTCBCacheConfig updates the TCB cache configuration.
// Changes affect new cache entries and lookups immediately.
func (sm *StreamManager) SetTCBCacheConfig(config TCBCacheConfig) {
	sm.tcbCache.SetConfig(config)
}

// EnableTCBCache enables or disables TCB cache sharing.
// When disabled, connections will not use cached RTT/window values.
func (sm *StreamManager) EnableTCBCache(enabled bool) {
	config := sm.tcbCache.GetConfig()
	config.Enabled = enabled
	sm.tcbCache.SetConfig(config)
}

// CleanupTCBCache removes expired entries from the TCB cache.
// This can be called periodically to prevent memory growth.
// Returns the number of entries removed.
func (sm *StreamManager) CleanupTCBCache() int {
	return sm.tcbCache.CleanupExpired()
}

// GetProfileConfig returns the current streaming profile configuration.
// Per I2P spec: i2p.streaming.profile option.
func (sm *StreamManager) GetProfileConfig() ProfileConfig {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.profileConfig
}

// SetProfileConfig updates the streaming profile configuration.
// This affects new connections only; existing connections retain their profile.
// Per I2P spec: i2p.streaming.profile option.
func (sm *StreamManager) SetProfileConfig(config ProfileConfig) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.profileConfig = config
}

// SetProfile is a convenience method to set the streaming profile.
// Valid values are ProfileBulk (1) and ProfileInteractive (2).
func (sm *StreamManager) SetProfile(profile StreamProfile) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.profileConfig.Profile = profile
}

// GetProfile returns the current streaming profile.
func (sm *StreamManager) GetProfile() StreamProfile {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.profileConfig.Profile
}
