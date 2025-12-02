// Package streaming implements the I2P streaming protocol, providing TCP-like
// reliable, ordered, bidirectional streams over the I2P anonymous network.
//
// This is an MVP implementation focusing on correctness over performance.
// It uses github.com/go-i2p/go-i2cp for I2CP transport and implements the
// I2P streaming packet format using standard library encoding.
//
// Architecture:
//   - Each I2CP message carries one TCP-like packet (not fragmented at I2CP layer)
//   - Default MTU is 1730 bytes payload (fits in 2x 1KB I2NP tunnel messages)
//   - ECIES connections can use 1812 bytes MTU (lower overhead)
//   - Windowing uses packet count, not byte count per I2P streaming spec
package streaming

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/armon/circbuf"
	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/rs/zerolog/log"
)

// ConnState represents the current state of a streaming connection.
// Follows I2P streaming protocol state machine.
type ConnState int

const (
	// StateInit is the initial state before any handshake
	StateInit ConnState = iota
	// StateSynSent indicates SYN sent, waiting for SYN-ACK
	StateSynSent
	// StateSynRcvd indicates SYN received, SYN-ACK sent, waiting for ACK
	StateSynRcvd
	// StateEstablished indicates connection is established and ready for data
	StateEstablished
	// StateCloseWait indicates CLOSE received, waiting to send CLOSE response
	StateCloseWait
	// StateClosing indicates CLOSE sent, waiting for CLOSE response
	StateClosing
	// StateClosed indicates connection is fully closed
	StateClosed
)

// String returns a human-readable representation of the connection state.
func (s ConnState) String() string {
	switch s {
	case StateInit:
		return "INIT"
	case StateSynSent:
		return "SYN_SENT"
	case StateSynRcvd:
		return "SYN_RCVD"
	case StateEstablished:
		return "ESTABLISHED"
	case StateCloseWait:
		return "CLOSE_WAIT"
	case StateClosing:
		return "CLOSING"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// I2PAddr implements the net.Addr interface for I2P destinations.
// This allows StreamConn to be used anywhere net.Conn is expected.
type I2PAddr struct {
	dest *go_i2cp.Destination
	port uint16
}

// Network returns the network type ("i2p").
// Implements net.Addr interface.
func (a *I2PAddr) Network() string {
	return "i2p"
}

// String returns a string representation of the I2P address.
// For now, returns "destination:port" format.
// Implements net.Addr interface.
func (a *I2PAddr) String() string {
	if a.dest == nil {
		return fmt.Sprintf("*:%d", a.port)
	}
	// For MVP, use simplified representation
	// In production, would use full base64 destination or .b32.i2p address
	return fmt.Sprintf("i2p:%d", a.port)
}

// StreamConn represents a single bidirectional stream over I2CP.
// Implements net.Conn interface.
//
// Design decisions:
//   - Single sync.Mutex for simplicity (can optimize later with RWMutex)
//   - Simple []byte buffers initially (no fancy circular buffers yet)
//   - Fixed window size for MVP (dynamic sizing in post-MVP)
//   - Packet-based windowing per I2P spec (not byte-based like TCP)
type StreamConn struct {
	// Stream manager for packet routing (optional, nil for backward compatibility)
	manager *StreamManager

	// I2CP transport layer
	session *go_i2cp.Session
	dest    *go_i2cp.Destination

	// Port numbers for multiplexing (future feature)
	localPort  uint16
	remotePort uint16

	// Sequence tracking per I2P streaming spec
	sendSeq    uint32 // Our current sequence number
	recvSeq    uint32 // Expected remote sequence number
	ackThrough uint32 // Highest packet number acked by remote

	// Flow control - packet-based per I2P spec (not byte-based)
	windowSize uint32        // Current window size in packets (max 128)
	rtt        time.Duration // Round trip time estimate
	rto        time.Duration // Retransmission timeout

	// Choking mechanism per I2P streaming spec
	// optDelay field: 0-60000ms = advisory delay, >60000 = choked
	optDelay uint16 // Optional delay field from last packet
	choked   bool   // Are we being choked by receiver?

	// MTU negotiation
	localMTU  uint16 // Our advertised MTU
	remoteMTU uint16 // Remote peer's MTU (0 until negotiated)

	// Simple byte buffers for MVP
	// Using github.com/armon/circbuf for receive buffer to avoid wraparound bugs
	sendBuf []byte
	recvBuf *circbuf.Buffer

	// Receive loop coordination
	recvChan chan *Packet       // Channel for incoming packets
	errChan  chan error         // Channel for errors from receive loop
	ctx      context.Context    // Context for cancellation
	cancel   context.CancelFunc // Cancel function

	// Synchronization primitives for blocking reads
	recvCond *sync.Cond // Condition variable for Read() blocking

	// Deadlines for net.Conn interface
	readDeadline  time.Time
	writeDeadline time.Time

	// Connection state and synchronization
	mu     sync.Mutex // Protects all fields above
	closed bool
	state  ConnState
}

// StreamListener listens for and accepts incoming streaming connections.
// Minimal implementation for MVP.
type StreamListener struct {
	manager    *StreamManager // Manager for packet routing
	session    *go_i2cp.Session
	localPort  uint16
	acceptChan chan *StreamConn // Buffered channel for incoming connections
	localMTU   uint16           // Our advertised MTU
	mu         sync.Mutex
	closed     bool
}

// MTU constants per I2P streaming specification
const (
	// DefaultMTU is the default maximum transmission unit in bytes (payload only).
	// Set to 1730 to fit in 2x 1KB I2NP tunnel messages.
	DefaultMTU = 1730

	// ECIESMTU is the recommended MTU for ECIES-X25519 connections.
	// Lower overhead allows 1812 bytes payload.
	ECIESMTU = 1812

	// MinMTU is the minimum MTU that must be supported per spec.
	MinMTU = 512

	// DefaultWindowSize is the initial window size in packets (not bytes).
	// Per I2P streaming spec, start with 6 packets if no control block data available.
	DefaultWindowSize = 6

	// MaxWindowSize is the maximum window size in packets.
	// Per I2P streaming spec, maximum is 128 packets.
	MaxWindowSize = 128

	// DefaultConnectTimeout is the default timeout for Dial operations.
	DefaultConnectTimeout = 60 * time.Second

	// DefaultHandshakeTimeout is the timeout for waiting for SYN-ACK response.
	DefaultHandshakeTimeout = 30 * time.Second
)

// Dial initiates a connection to the specified I2P destination.
// This implements the client side of the three-way handshake:
//  1. Send SYN packet with our MTU and random ISN
//  2. Wait for SYN-ACK response
//  3. Send ACK to complete handshake
//
// The connection includes MTU negotiation - both peers advertise their
// maximum supported MTU and use the minimum of the two.
//
// MVP implementation uses simple polling with time.Sleep() rather than
// sophisticated channel-based state management. This can be optimized later.
//
// Parameters:
//   - session: Active I2CP session for sending/receiving messages
//   - dest: Remote I2P destination to connect to
//   - localPort: Source port for this connection (0 for automatic)
//   - remotePort: Destination port on remote peer
//
// Returns the established connection or an error if handshake fails.
func Dial(session *go_i2cp.Session, dest *go_i2cp.Destination, localPort, remotePort uint16) (*StreamConn, error) {
	return DialWithMTU(session, dest, localPort, remotePort, DefaultMTU, DefaultConnectTimeout)
}

// DialWithMTU is like Dial but allows specifying a custom MTU and timeout.
// Use ECIESMTU (1812) for ECIES-X25519 connections for better efficiency.
func DialWithMTU(session *go_i2cp.Session, dest *go_i2cp.Destination, localPort, remotePort uint16, mtu int, timeout time.Duration) (*StreamConn, error) {
	if mtu < MinMTU {
		return nil, fmt.Errorf("MTU %d is below minimum %d", mtu, MinMTU)
	}
	if mtu > DefaultMTU && mtu != ECIESMTU {
		return nil, fmt.Errorf("MTU %d exceeds recommended maximum %d (use %d for ECIES)", mtu, DefaultMTU, ECIESMTU)
	}
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}
	if dest == nil {
		return nil, fmt.Errorf("destination cannot be nil")
	}

	// Generate random ISN for security
	isn, err := generateISN()
	if err != nil {
		return nil, fmt.Errorf("generate ISN: %w", err)
	}

	// Create receive buffer
	recvBuf, err := circbuf.NewBuffer(64 * 1024) // 64KB receive buffer
	if err != nil {
		return nil, fmt.Errorf("create receive buffer: %w", err)
	}

	// Create context for receive loop
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize connection structure
	conn := &StreamConn{
		session:    session,
		dest:       dest,
		localPort:  localPort,
		remotePort: remotePort,
		sendSeq:    isn,
		recvSeq:    0, // Will be set from SYN-ACK
		windowSize: DefaultWindowSize,
		rtt:        8 * time.Second, // Initial RTT estimate
		rto:        9 * time.Second, // Initial RTO per spec
		recvBuf:    recvBuf,
		recvChan:   make(chan *Packet, 32), // Buffer for incoming packets
		errChan:    make(chan error, 1),
		ctx:        ctx,
		cancel:     cancel,
		state:      StateInit,
		localMTU:   uint16(mtu),
		remoteMTU:  0, // Will be negotiated
	}
	conn.recvCond = sync.NewCond(&conn.mu)

	log.Info().
		Uint16("localPort", localPort).
		Uint16("remotePort", remotePort).
		Uint32("isn", isn).
		Int("mtu", mtu).
		Msg("initiating connection")

	// Send SYN packet
	if err := conn.sendSYN(); err != nil {
		return nil, fmt.Errorf("send SYN: %w", err)
	}

	// Transition to SYN_SENT state
	conn.setState(StateSynSent)

	// Wait for SYN-ACK with timeout
	// MVP: Use simple polling instead of sophisticated channel-based waiting
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), timeout)
	defer timeoutCancel()

	synAck, err := conn.waitForSynAck(timeoutCtx)
	if err != nil {
		return nil, fmt.Errorf("wait for SYN-ACK: %w", err)
	}

	// Process SYN-ACK: extract remote ISN and MTU
	conn.processSynAck(synAck)

	// Send final ACK to complete handshake
	if err := conn.sendACK(); err != nil {
		return nil, fmt.Errorf("send ACK: %w", err)
	}

	// Transition to ESTABLISHED state
	conn.setState(StateEstablished)

	// Start receive loop goroutine
	go conn.receiveLoop()

	log.Info().
		Str("state", conn.state.String()).
		Uint16("negotiatedMTU", conn.getNegotiatedMTU()).
		Dur("rtt", conn.rtt).
		Msg("connection established")

	return conn, nil
}

// sendSYN sends a SYN packet to initiate the handshake.
// Includes our MTU in the MAX_PACKET_SIZE_INCLUDED option for negotiation.
func (s *StreamConn) sendSYN() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pkt := &Packet{
		SendStreamID:  uint32(s.localPort),
		RecvStreamID:  uint32(s.remotePort),
		SequenceNum:   s.sendSeq,
		AckThrough:    0, // No ACK yet
		Flags:         FlagSYN | FlagMaxPacketSizeIncluded,
		MaxPacketSize: s.localMTU, // Advertise our MTU
		// Payload could contain initial data (allowed per spec)
		// For MVP, keep it simple - no initial data in SYN
	}

	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal SYN: %w", err)
	}

	stream := go_i2cp.NewStream(data)
	err = s.session.SendMessage(s.dest, 6, s.localPort, s.remotePort, stream, 0)
	if err != nil {
		return fmt.Errorf("send SYN message: %w", err)
	}

	log.Debug().
		Uint32("seq", pkt.SequenceNum).
		Uint16("flags", pkt.Flags).
		Uint16("localMTU", s.localMTU).
		Uint16("localPort", s.localPort).
		Uint16("remotePort", s.remotePort).
		Msg("sent SYN")

	return nil
}

// waitForSynAck polls for incoming SYN-ACK packet.
// MVP implementation uses simple polling with time.Sleep().
// This will be replaced with channel-based approach in later phases.
func (s *StreamConn) waitForSynAck(ctx context.Context) (*Packet, error) {
	// MVP: Simple polling approach
	// In Phase 4, we'll have a proper receive goroutine with channels
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	log.Debug().Msg("waiting for SYN-ACK (MVP: polling not yet implemented)")

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for SYN-ACK: %w", ctx.Err())
		case <-ticker.C:
			// TODO: In Phase 4, implement actual packet reception
			// For now, this is a placeholder for the structure
			// Real implementation will check incoming message queue
			continue
		}
	}
}

// processSynAck extracts information from SYN-ACK packet.
// Sets remote sequence number and negotiates MTU.
func (s *StreamConn) processSynAck(pkt *Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Extract remote ISN
	s.recvSeq = pkt.SequenceNum + 1 // Next expected sequence

	// MTU negotiation: use minimum of local and remote
	// For MVP, assume remote MTU is in packet metadata or use default
	s.remoteMTU = DefaultMTU

	log.Debug().
		Uint32("remoteSeq", pkt.SequenceNum).
		Uint32("ourAck", s.recvSeq).
		Uint16("remoteMTU", s.remoteMTU).
		Msg("processed SYN-ACK")
}

// sendACK sends the final ACK to complete the three-way handshake.
func (s *StreamConn) sendACK() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pkt := &Packet{
		SendStreamID: uint32(s.localPort),
		RecvStreamID: uint32(s.remotePort),
		SequenceNum:  s.sendSeq,
		AckThrough:   s.recvSeq - 1, // ACK the SYN-ACK
		Flags:        FlagACK,
	}

	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal ACK: %w", err)
	}

	stream := go_i2cp.NewStream(data)
	err = s.session.SendMessage(s.dest, 6, s.localPort, s.remotePort, stream, 0)
	if err != nil {
		return fmt.Errorf("send ACK message: %w", err)
	}

	log.Debug().
		Uint32("seq", pkt.SequenceNum).
		Uint32("ack", pkt.AckThrough).
		Uint16("flags", pkt.Flags).
		Msg("sent ACK")

	return nil
}

// setState transitions the connection to a new state with logging.
func (s *StreamConn) setState(newState ConnState) {
	oldState := s.state
	s.state = newState

	log.Info().
		Str("from", oldState.String()).
		Str("to", newState.String()).
		Msg("state transition")
}

// getNegotiatedMTU returns the negotiated MTU (minimum of local and remote).
func (s *StreamConn) getNegotiatedMTU() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.remoteMTU == 0 {
		return s.localMTU
	}
	if s.localMTU < s.remoteMTU {
		return s.localMTU
	}
	return s.remoteMTU
}

// Listen creates a StreamListener that accepts incoming connections on the specified port.
// This sets up the infrastructure for the server side of the handshake.
//
// The listener will wait for incoming SYN packets and complete the three-way handshake:
//  1. Receive SYN packet (via StreamManager callback)
//  2. Send SYN-ACK response
//  3. Wait for ACK to complete (handled by connection)
//
// This function creates a StreamManager internally to handle I2CP callbacks.
// The manager routes incoming packets to this listener based on port.
//
// Parameters:
//   - session: Active I2CP session for sending/receiving messages
//   - localPort: Port to listen on (0 for automatic)
//
// Returns a listener ready to accept connections.
//
// IMPORTANT: The caller must call StartProcessingIO() on the returned listener
// to begin receiving messages from I2CP. Without this, no packets will be received.
func Listen(session *go_i2cp.Session, localPort uint16) (*StreamListener, error) {
	return ListenWithMTU(session, localPort, DefaultMTU)
}

// ListenWithMTU is like Listen but allows specifying a custom MTU.
// Use ECIESMTU (1812) for ECIES-X25519 connections.
func ListenWithMTU(session *go_i2cp.Session, localPort uint16, mtu int) (*StreamListener, error) {
	if mtu < MinMTU {
		return nil, fmt.Errorf("MTU %d is below minimum %d", mtu, MinMTU)
	}
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}

	listener := &StreamListener{
		manager:    nil, // Will be set if using manager pattern
		session:    session,
		localPort:  localPort,
		acceptChan: make(chan *StreamConn, 10), // Buffer 10 pending connections
		localMTU:   uint16(mtu),
	}

	log.Info().
		Uint16("port", localPort).
		Int("mtu", mtu).
		Msg("listening for connections")

	return listener, nil
}

// ListenWithManager creates a StreamListener that uses a StreamManager for packet routing.
// This is the recommended way to create listeners as it integrates with I2CP callbacks.
//
// The manager handles:
//   - Registering SessionCallbacks with I2CP
//   - Routing incoming SYN packets to this listener
//   - Managing multiple listeners/connections on one session
//
// Use this instead of Listen() when you want automatic packet routing from I2CP.
func ListenWithManager(manager *StreamManager, localPort uint16, mtu int) (*StreamListener, error) {
	if mtu < MinMTU {
		return nil, fmt.Errorf("MTU %d is below minimum %d", mtu, MinMTU)
	}
	if manager == nil {
		return nil, fmt.Errorf("manager cannot be nil")
	}

	listener := &StreamListener{
		manager:    manager,
		session:    manager.Session(),
		localPort:  localPort,
		acceptChan: make(chan *StreamConn, 10),
		localMTU:   uint16(mtu),
	}

	// Register with manager for packet routing
	manager.RegisterListener(localPort, listener)

	log.Info().
		Uint16("port", localPort).
		Int("mtu", mtu).
		Msg("listening for connections (with manager)")

	return listener, nil
}

// Accept waits for and returns the next incoming connection.
// This blocks until a connection is available or the listener is closed.
//
// MVP implementation uses simple channel-based approach.
// The actual SYN packet processing will be implemented in Phase 4.
func (l *StreamListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, fmt.Errorf("listener closed")
	}
	l.mu.Unlock()

	// Wait for incoming connection
	conn, ok := <-l.acceptChan
	if !ok {
		return nil, fmt.Errorf("listener closed")
	}

	log.Info().
		Str("state", conn.state.String()).
		Uint16("remotePort", conn.remotePort).
		Msg("accepted connection")

	return conn, nil
}

// Close stops the listener and rejects new connections.
func (l *StreamListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}

	l.closed = true
	close(l.acceptChan)

	// Unregister from manager if using manager pattern
	if l.manager != nil {
		l.manager.UnregisterListener(l.localPort)
	}

	log.Info().
		Uint16("port", l.localPort).
		Msg("closed listener")

	return nil
}

// handleIncomingSYN processes an incoming SYN packet and completes the handshake.
// This is called by the StreamManager when a SYN packet arrives for this listener.
//
// Steps:
//  1. Validate SYN packet
//  2. Generate random ISN for our side
//  3. Create connection structure
//  4. Send SYN-ACK with our MTU
//  5. Register connection with manager
//  6. Transition to SYN_RCVD state
//  7. Queue connection for Accept()
//
// The connection will transition to ESTABLISHED when it receives the final ACK.
func (l *StreamListener) handleIncomingSYN(synPkt *Packet, remotePort uint16) error {
	log.Debug().
		Uint32("remoteSeq", synPkt.SequenceNum).
		Uint16("remotePort", remotePort).
		Uint16("localPort", l.localPort).
		Msg("received SYN")

	// Generate our ISN
	isn, err := generateISN()
	if err != nil {
		return fmt.Errorf("generate ISN: %w", err)
	}

	// Extract remote MTU from SYN packet if present
	var remoteMTU uint16 = DefaultMTU
	if synPkt.Flags&FlagMaxPacketSizeIncluded != 0 && synPkt.MaxPacketSize > 0 {
		remoteMTU = synPkt.MaxPacketSize
		log.Debug().
			Uint16("remoteMTU", remoteMTU).
			Uint16("localMTU", l.localMTU).
			Msg("extracted MTU from SYN")
	} else {
		log.Warn().Msg("SYN missing MTU, using default")
	}

	// Create receive buffer
	recvBuf, err := circbuf.NewBuffer(64 * 1024)
	if err != nil {
		return fmt.Errorf("create receive buffer: %w", err)
	}

	// Create context for receive loop
	ctx, cancel := context.WithCancel(context.Background())

	// Create connection structure
	conn := &StreamConn{
		manager:    l.manager,
		session:    l.session,
		dest:       nil, // TODO: Extract from packet or lease set
		localPort:  l.localPort,
		remotePort: remotePort,
		sendSeq:    isn,
		recvSeq:    synPkt.SequenceNum + 1, // Next expected sequence
		windowSize: DefaultWindowSize,
		rtt:        8 * time.Second,
		rto:        9 * time.Second,
		recvBuf:    recvBuf,
		recvChan:   make(chan *Packet, 32),
		errChan:    make(chan error, 1),
		ctx:        ctx,
		cancel:     cancel,
		state:      StateInit,
		localMTU:   l.localMTU,
		remoteMTU:  remoteMTU, // Extracted from SYN packet
	}
	conn.recvCond = sync.NewCond(&conn.mu)

	// Register connection with manager for packet routing
	if l.manager != nil {
		l.manager.RegisterConnection(l.localPort, remotePort, conn)
	}

	// Send SYN-ACK
	if err := conn.sendSynAck(); err != nil {
		if l.manager != nil {
			l.manager.UnregisterConnection(l.localPort, remotePort)
		}
		return fmt.Errorf("send SYN-ACK: %w", err)
	}

	// Transition to SYN_RCVD state
	conn.setState(StateSynRcvd)

	// Queue connection for Accept()
	// The connection will transition to ESTABLISHED when it receives the final ACK
	select {
	case l.acceptChan <- conn:
		log.Debug().
			Uint16("localPort", l.localPort).
			Uint16("remotePort", remotePort).
			Msg("queued connection for Accept()")
	default:
		log.Warn().Msg("accept channel full, dropping connection")
		if l.manager != nil {
			l.manager.UnregisterConnection(l.localPort, remotePort)
		}
		return fmt.Errorf("accept queue full")
	}

	return nil
}

// sendSynAck sends a SYN-ACK packet in response to a SYN.
// Includes our MTU in the MAX_PACKET_SIZE_INCLUDED option for negotiation.
func (s *StreamConn) sendSynAck() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pkt := &Packet{
		SendStreamID:  uint32(s.localPort),
		RecvStreamID:  uint32(s.remotePort),
		SequenceNum:   s.sendSeq,
		AckThrough:    s.recvSeq - 1, // ACK the SYN
		Flags:         FlagSYN | FlagACK | FlagMaxPacketSizeIncluded,
		MaxPacketSize: s.localMTU, // Advertise our MTU
	}

	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal SYN-ACK: %w", err)
	}

	stream := go_i2cp.NewStream(data)
	err = s.session.SendMessage(s.dest, 6, s.localPort, s.remotePort, stream, 0)
	if err != nil {
		return fmt.Errorf("send SYN-ACK message: %w", err)
	}

	log.Debug().
		Uint32("seq", pkt.SequenceNum).
		Uint32("ack", pkt.AckThrough).
		Uint16("flags", pkt.Flags).
		Uint16("localMTU", s.localMTU).
		Msg("sent SYN-ACK")

	return nil
}

// Write sends data over the connection.
// Implements the io.Writer interface.
//
// This method handles MTU-aware chunking, splitting large writes into
// multiple packets that fit within the negotiated MTU. Each packet is
// sent with proper sequence numbers and flow control.
//
// MVP implementation:
//   - Simple chunking based on MTU
//   - Increment sequence number for each packet
//   - No sophisticated buffering (send immediately)
//   - No retransmission (Phase 6+)
//   - Fixed 6-packet window (no dynamic windowing yet)
//
// Returns the number of bytes written or an error.
func (s *StreamConn) Write(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return 0, fmt.Errorf("connection closed")
	}

	if s.state != StateEstablished {
		return 0, fmt.Errorf("connection not established (state: %s)", s.state)
	}

	total := len(data)
	mtu := int(s.getNegotiatedMTULocked())

	log.Debug().
		Int("bytes", total).
		Int("mtu", mtu).
		Uint32("startSeq", s.sendSeq).
		Msg("writing data")

	// Split data into MTU-sized chunks
	for len(data) > 0 {
		chunk := data
		if len(chunk) > mtu {
			chunk = data[:mtu]
		}

		// Create packet with data
		pkt := &Packet{
			SendStreamID: uint32(s.localPort),
			RecvStreamID: uint32(s.remotePort),
			SequenceNum:  s.sendSeq,
			AckThrough:   s.recvSeq - 1, // Piggyback ACK
			Flags:        FlagACK,       // Always include ACK flag
			Payload:      chunk,
		}

		// Send packet
		if err := s.sendPacketLocked(pkt); err != nil {
			return total - len(data), fmt.Errorf("send packet: %w", err)
		}

		// Increment sequence number by payload length
		s.sendSeq += uint32(len(chunk))

		// Move to next chunk
		data = data[len(chunk):]
	}

	log.Debug().
		Int("bytes", total).
		Uint32("endSeq", s.sendSeq).
		Msg("write complete")

	return total, nil
}

// Read receives data from the connection.
// Implements the io.Reader interface.
//
// This method blocks until data is available in the receive buffer.
// The receive buffer is populated by the receiveLoop() goroutine
// which processes incoming packets.
//
// MVP implementation:
//   - Simple blocking using sync.Cond
//   - Use circbuf.Bytes() and manual management (no built-in Read method)
//   - No timeout support yet (Phase 5+)
//
// Returns the number of bytes read or an error.
// Read receives data from the connection.
// Implements the io.Reader and net.Conn interfaces.
//
// This method blocks until data is available in the receive buffer.
// The receive buffer is populated by the receiveLoop() goroutine
// which processes incoming packets.
//
// Phase 5 additions:
//   - Returns io.EOF when connection is closed (per net.Conn spec)
//   - Respects read deadlines
//
// Returns the number of bytes read or an error.
func (s *StreamConn) Read(buf []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if connection closed with no data
	if s.closed && s.recvBuf.TotalWritten() == 0 {
		return 0, io.EOF
	}

	// Block until data is available or deadline expires
	for s.recvBuf.TotalWritten() == 0 && !s.closed {
		// Check read deadline before waiting
		if !s.readDeadline.IsZero() && time.Now().After(s.readDeadline) {
			return 0, &timeoutError{}
		}

		// Wait with timeout if deadline is set
		if !s.readDeadline.IsZero() {
			timeout := time.Until(s.readDeadline)
			if timeout <= 0 {
				return 0, &timeoutError{}
			}
			// Use a timer to wake up at deadline
			timer := time.AfterFunc(timeout, func() {
				s.mu.Lock()
				s.recvCond.Broadcast()
				s.mu.Unlock()
			})
			defer timer.Stop()
		}

		s.recvCond.Wait()

		// Recheck deadline after waking
		if !s.readDeadline.IsZero() && time.Now().After(s.readDeadline) {
			return 0, &timeoutError{}
		}
	}

	// Check if closed while waiting - return io.EOF
	if s.closed && s.recvBuf.TotalWritten() == 0 {
		return 0, io.EOF
	}

	// Get available data from circular buffer
	data := s.recvBuf.Bytes()
	n := copy(buf, data)

	// Reset buffer and write back any remaining data
	s.recvBuf.Reset()
	if n < len(data) {
		remaining := data[n:]
		if _, err := s.recvBuf.Write(remaining); err != nil {
			return n, fmt.Errorf("write remaining data: %w", err)
		}
	}

	log.Debug().
		Int("bytes", n).
		Msg("read data")

	return n, nil
}

// timeoutError implements net.Error interface for timeout errors.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// receiveLoop runs in a goroutine to receive and process incoming packets.
// This is the main receive path that:
//  1. Receives packets from recvChan (populated by manager's callback)
//  2. Validates sequence numbers
//  3. Processes based on flags (SYN-ACK, ACK, CLOSE, data)
//  4. Writes payload to receive buffer
//  5. Sends ACKs
//
// Updated in Phase 3: Now uses callback-driven packet delivery instead of polling.
// Packets arrive via handleIncomingPacket() which is called by StreamManager
// when the I2CP OnMessage callback fires.
func (s *StreamConn) receiveLoop() {
	log.Debug().Msg("receive loop started")
	defer log.Debug().Msg("receive loop stopped")

	for {
		select {
		case <-s.ctx.Done():
			return

		case pkt := <-s.recvChan:
			// Process packet from manager
			if err := s.processPacket(pkt); err != nil {
				log.Warn().
					Err(err).
					Uint32("seq", pkt.SequenceNum).
					Msg("failed to process packet")
			}
		}
	}
}

// processPacket handles an incoming packet based on connection state and flags.
// This is called by receiveLoop when packets arrive from the manager.
func (s *StreamConn) processPacket(pkt *Packet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Debug().
		Uint32("seq", pkt.SequenceNum).
		Uint32("ack", pkt.AckThrough).
		Uint16("flags", pkt.Flags).
		Int("payload", len(pkt.Payload)).
		Str("state", s.state.String()).
		Msg("processing packet")

	// Handle based on flags and state
	// Note: Order matters! More specific cases first.
	switch {
	case pkt.Flags&FlagSYN != 0 && pkt.Flags&FlagACK != 0:
		// SYN-ACK packet (client side handshake response)
		return s.handleSynAckLocked(pkt)

	case pkt.Flags&FlagACK != 0 && s.state == StateSynRcvd:
		// Final ACK of three-way handshake (server side)
		return s.handleFinalAckLocked(pkt)

	case pkt.Flags&FlagCLOSE != 0:
		// CLOSE packet
		return s.handleCloseLocked(pkt)

	case pkt.Flags&FlagRESET != 0:
		// RESET packet
		return s.handleResetLocked(pkt)

	case len(pkt.Payload) > 0:
		// Data packet (may also have ACK flag - handled in handleDataLocked)
		return s.handleDataLocked(pkt)

	case pkt.Flags&FlagACK != 0:
		// Pure ACK packet (no data)
		return s.handleAckLocked(pkt)

	default:
		log.Debug().
			Uint16("flags", pkt.Flags).
			Msg("packet with no recognized flags")
	}

	return nil
}

// handleSynAckLocked processes a SYN-ACK packet (client side).
// Must be called with s.mu held.
func (s *StreamConn) handleSynAckLocked(pkt *Packet) error {
	if s.state != StateSynSent {
		log.Warn().
			Str("state", s.state.String()).
			Msg("unexpected SYN-ACK in state")
		return fmt.Errorf("unexpected SYN-ACK")
	}

	log.Debug().
		Uint32("remoteSeq", pkt.SequenceNum).
		Msg("received SYN-ACK")

	// Extract remote ISN and MTU
	s.recvSeq = pkt.SequenceNum + 1 // Next expected sequence

	// Extract MTU from packet if present (FlagMaxPacketSizeIncluded)
	if pkt.Flags&FlagMaxPacketSizeIncluded != 0 && pkt.MaxPacketSize > 0 {
		s.remoteMTU = pkt.MaxPacketSize
		log.Debug().
			Uint16("remoteMTU", s.remoteMTU).
			Uint16("localMTU", s.localMTU).
			Uint16("negotiatedMTU", s.getNegotiatedMTULocked()).
			Msg("MTU negotiated")
	} else {
		s.remoteMTU = DefaultMTU
		log.Warn().Msg("SYN-ACK missing MTU, using default")
	}

	// Send final ACK
	if err := s.sendAckLocked(); err != nil {
		return fmt.Errorf("send ACK: %w", err)
	}

	// Transition to ESTABLISHED
	s.setState(StateEstablished)

	return nil
}

// handleFinalAckLocked processes the final ACK of handshake (server side).
// Must be called with s.mu held.
func (s *StreamConn) handleFinalAckLocked(pkt *Packet) error {
	log.Debug().
		Uint32("ack", pkt.AckThrough).
		Msg("received final ACK")

	// Verify ACK is for our SYN-ACK
	if pkt.AckThrough != s.sendSeq-1 {
		log.Warn().
			Uint32("expected", s.sendSeq-1).
			Uint32("got", pkt.AckThrough).
			Msg("ACK number mismatch")
	}

	// Transition to ESTABLISHED
	s.setState(StateEstablished)

	return nil
}

// handleCloseLocked processes a CLOSE packet.
// Must be called with s.mu held.
func (s *StreamConn) handleCloseLocked(pkt *Packet) error {
	log.Debug().Msg("received CLOSE")

	switch s.state {
	case StateEstablished:
		// Peer initiated close - send CLOSE response
		if err := s.sendCloseLocked(); err != nil {
			log.Warn().Err(err).Msg("failed to send CLOSE response")
		}
		s.setState(StateClosed)
		s.closed = true
		s.recvCond.Broadcast() // Wake readers to return io.EOF

	case StateClosing:
		// Peer responded to our close
		s.setState(StateClosed)
		s.closed = true
		s.recvCond.Broadcast()

	default:
		log.Warn().
			Str("state", s.state.String()).
			Msg("unexpected CLOSE")
	}

	return nil
}

// handleResetLocked processes a RESET packet.
// Must be called with s.mu held.
func (s *StreamConn) handleResetLocked(pkt *Packet) error {
	log.Warn().Msg("received RESET - aborting connection")

	s.setState(StateClosed)
	s.closed = true
	s.recvCond.Broadcast()

	return fmt.Errorf("connection reset by peer")
}

// handleAckLocked processes an ACK packet.
// Must be called with s.mu held.
func (s *StreamConn) handleAckLocked(pkt *Packet) error {
	// Update ackThrough if this ACKs more data
	if pkt.AckThrough > s.ackThrough {
		s.ackThrough = pkt.AckThrough
		log.Debug().
			Uint32("ackThrough", s.ackThrough).
			Msg("updated ackThrough")
	}

	// Handle optional delay (choking mechanism)
	if pkt.OptionalDelay > 60000 {
		s.choked = true
		log.Debug().
			Uint16("delay", pkt.OptionalDelay).
			Msg("peer is choked")
	} else {
		s.choked = false
	}

	return nil
}

// handleDataLocked processes a data packet.
// Must be called with s.mu held.
func (s *StreamConn) handleDataLocked(pkt *Packet) error {
	// Validate sequence number (in-order only for MVP)
	if pkt.SequenceNum != s.recvSeq {
		log.Warn().
			Uint32("expected", s.recvSeq).
			Uint32("got", pkt.SequenceNum).
			Msg("sequence mismatch - dropping packet (MVP: no reordering)")
		return fmt.Errorf("sequence mismatch")
	}

	// Write to receive buffer
	n, err := s.recvBuf.Write(pkt.Payload)
	if err != nil {
		log.Error().Err(err).Msg("receive buffer full")
		// TODO: Set choke flag
		return fmt.Errorf("write to receive buffer: %w", err)
	}

	log.Debug().
		Int("bytes", n).
		Uint32("oldRecvSeq", s.recvSeq).
		Uint32("newRecvSeq", s.recvSeq+uint32(n)).
		Msg("buffered payload")

	// Update receive sequence number
	s.recvSeq += uint32(n)

	// Update ackThrough if packet has ACK
	if pkt.Flags&FlagACK != 0 && pkt.AckThrough > s.ackThrough {
		s.ackThrough = pkt.AckThrough
	}

	// Wake up any blocked Read() calls
	s.recvCond.Broadcast()

	// Send ACK for this packet
	if err := s.sendAckLocked(); err != nil {
		log.Warn().
			Err(err).
			Msg("failed to send ACK")
	}

	return nil
}

// handleIncomingPacket is called by the StreamManager when a packet arrives for this connection.
// It queues the packet for processing by the receiveLoop.
//
// This is the entry point from the I2CP callback chain:
//
//	I2CP OnMessage -> StreamManager.handleIncomingMessage -> StreamManager.dispatchPacket -> here
func (s *StreamConn) handleIncomingPacket(pkt *Packet) error {
	log.Debug().
		Uint32("seq", pkt.SequenceNum).
		Uint32("ack", pkt.AckThrough).
		Uint16("flags", pkt.Flags).
		Int("payload", len(pkt.Payload)).
		Msg("queuing packet for receiveLoop")

	// Queue packet for receiveLoop to process
	select {
	case s.recvChan <- pkt:
		return nil
	case <-s.ctx.Done():
		return fmt.Errorf("connection closed")
	default:
		log.Warn().Msg("receive channel full, dropping packet")
		return fmt.Errorf("receive queue full")
	}
}

// sendAckLocked sends an ACK packet.
// Must be called with s.mu held.
func (s *StreamConn) sendAckLocked() error {
	pkt := &Packet{
		SendStreamID:  uint32(s.localPort),
		RecvStreamID:  uint32(s.remotePort),
		SequenceNum:   s.sendSeq,
		AckThrough:    s.recvSeq - 1,
		Flags:         FlagACK,
		OptionalDelay: 0, // Request immediate ACK (MVP: no delay optimization)
	}

	return s.sendPacketLocked(pkt)
}

// sendPacketLocked marshals and sends a packet via I2CP.
// Must be called with s.mu held.
func (s *StreamConn) sendPacketLocked(pkt *Packet) error {
	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal packet: %w", err)
	}

	// MVP: Skip actual I2CP sending if session is nil (for testing)
	if s.session == nil {
		log.Debug().
			Uint32("seq", pkt.SequenceNum).
			Uint32("ack", pkt.AckThrough).
			Uint16("flags", pkt.Flags).
			Int("payload", len(pkt.Payload)).
			Msg("skipped send (no session)")
		return nil
	}

	stream := go_i2cp.NewStream(data)
	err = s.session.SendMessage(s.dest, 6, s.localPort, s.remotePort, stream, 0)
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}

	log.Debug().
		Uint32("seq", pkt.SequenceNum).
		Uint32("ack", pkt.AckThrough).
		Uint16("flags", pkt.Flags).
		Int("payload", len(pkt.Payload)).
		Msg("sent packet")

	return nil
}

// getNegotiatedMTULocked returns the negotiated MTU.
// Must be called with s.mu held.
func (s *StreamConn) getNegotiatedMTULocked() uint16 {
	if s.remoteMTU == 0 {
		return s.localMTU
	}
	if s.localMTU < s.remoteMTU {
		return s.localMTU
	}
	return s.remoteMTU
}

// Close closes the connection and releases resources.
// Implements the io.Closer and net.Conn interfaces.
//
// Phase 5: Implements proper CLOSE handshake per I2P streaming spec.
// CLOSE is distinct from FIN - it's a bidirectional handshake.
func (s *StreamConn) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	log.Info().Msg("closing connection")

	// Send CLOSE packet if connection is established
	if s.state == StateEstablished {
		if err := s.sendCloseLocked(); err != nil {
			log.Warn().Err(err).Msg("failed to send CLOSE packet")
		}
		s.setState(StateClosing)
	}

	// Unregister from manager if using manager pattern
	if s.manager != nil {
		s.manager.UnregisterConnection(s.localPort, s.remotePort)
	}

	// Cancel receive loop
	s.cancel()

	// Mark as closed
	s.closed = true

	// Wake up any blocked readers
	s.recvCond.Broadcast()

	return nil
}

// sendCloseLocked sends a CLOSE packet to initiate connection teardown.
// Must be called with s.mu held.
func (s *StreamConn) sendCloseLocked() error {
	pkt := &Packet{
		SendStreamID: uint32(s.localPort),
		RecvStreamID: uint32(s.remotePort),
		SequenceNum:  s.sendSeq,
		AckThrough:   s.recvSeq - 1,
		Flags:        FlagCLOSE,
	}

	return s.sendPacketLocked(pkt)
}

// LocalAddr returns the local network address.
// Implements net.Conn interface.
func (s *StreamConn) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &I2PAddr{
		dest: nil, // Local destination not exposed in MVP
		port: s.localPort,
	}
}

// RemoteAddr returns the remote network address.
// Implements net.Conn interface.
func (s *StreamConn) RemoteAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &I2PAddr{
		dest: s.dest,
		port: s.remotePort,
	}
}

// SetDeadline sets the read and write deadlines.
// Implements net.Conn interface.
//
// A zero value for t means I/O operations will not time out.
func (s *StreamConn) SetDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.readDeadline = t
	s.writeDeadline = t

	// Wake up any blocked operations to check deadline
	s.recvCond.Broadcast()

	return nil
}

// SetReadDeadline sets the deadline for future Read calls.
// Implements net.Conn interface.
//
// A zero value for t means Read will not time out.
func (s *StreamConn) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.readDeadline = t

	// Wake up any blocked readers to check deadline
	s.recvCond.Broadcast()

	return nil
}

// SetWriteDeadline sets the deadline for future Write calls.
// Implements net.Conn interface.
//
// A zero value for t means Write will not time out.
func (s *StreamConn) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.writeDeadline = t

	return nil
}

// Addr returns the listener's network address.
// Implements net.Listener interface.
func (l *StreamListener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()

	return &I2PAddr{
		dest: nil, // Local destination not exposed in MVP
		port: l.localPort,
	}
}
