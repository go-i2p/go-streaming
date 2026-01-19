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
	"crypto/sha256"
	"encoding/binary"
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

// hashDestination creates a SHA-256 hash of an I2P destination for replay prevention.
// The hash is used in SYN packets' NACK field to prove the sender knows the recipient's destination.
// Returns 32-byte hash suitable for extracting 8 uint32 values.
func hashDestination(dest *go_i2cp.Destination) ([]byte, error) {
	if dest == nil {
		return nil, fmt.Errorf("destination is nil")
	}

	// Serialize the destination to bytes
	stream := go_i2cp.NewStream(make([]byte, 0, 512))
	if err := dest.WriteToStream(stream); err != nil {
		return nil, fmt.Errorf("serialize destination: %w", err)
	}

	// Hash the serialized destination
	hash := sha256.Sum256(stream.Bytes())
	return hash[:], nil
}

// seqLessThan compares two sequence numbers with wrap-around handling.
// Uses RFC 1323 / TCP semantics: a < b iff (a - b) interpreted as signed is negative.
// This correctly handles the case where sequence numbers wrap from 0xFFFFFFFF to 0.
// For example: seqLessThan(0xFFFFFFFE, 0x00000001) returns true (because 0xFFFFFFFE
// is "before" 0x00000001 in the sequence space after wrap-around).
func seqLessThan(a, b uint32) bool {
	// Cast difference to int32 for signed comparison
	// If (a - b) as signed int32 is negative, then a < b in sequence space
	return int32(a-b) < 0
}

// seqLessThanOrEqual compares two sequence numbers with wrap-around handling.
// Returns true if a <= b in sequence number space.
func seqLessThanOrEqual(a, b uint32) bool {
	return a == b || seqLessThan(a, b)
}

// seqGreaterThan compares two sequence numbers with wrap-around handling.
// Returns true if a > b in sequence number space.
func seqGreaterThan(a, b uint32) bool {
	return int32(a-b) > 0
}

// seqGreaterThanOrEqual compares two sequence numbers with wrap-around handling.
// Returns true if a >= b in sequence number space.
func seqGreaterThanOrEqual(a, b uint32) bool {
	return a == b || seqGreaterThan(a, b)
}

// seqDiff returns the distance between two sequence numbers.
// Returns positive value representing how many sequence numbers b is ahead of a.
// Handles wrap-around correctly.
func seqDiff(a, b uint32) uint32 {
	return b - a
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

// sentPacket tracks information about a sent packet for retransmission.
// Used by sender to handle NACK requests from receiver.
type sentPacket struct {
	data       []byte    // Marshaled packet data for retransmission
	sentTime   time.Time // When packet was originally sent
	retryCount int       // Number of times packet has been retransmitted
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

	// Stream IDs per I2P streaming spec (random, non-zero)
	localStreamID  uint32 // Our random stream ID
	remoteStreamID uint32 // Peer's stream ID (extracted from SYN-ACK)

	// Sequence tracking per I2P streaming spec
	sendSeq    uint32 // Our current sequence number (increments by 1 per packet)
	recvSeq    uint32 // Expected remote sequence number (increments by 1 per packet)
	ackThrough uint32 // Highest packet number acked by remote

	// Byte tracking (separate from sequence numbers per I2P spec)
	totalBytesSent     uint64 // Total bytes sent (for statistics)
	totalBytesReceived uint64 // Total bytes received (for statistics)

	// Flow control - packet-based per I2P spec (not byte-based)
	windowSize  uint32        // Current window size in packets (max 128)
	cwnd        uint32        // Congestion window for slow start / congestion avoidance
	ssthresh    uint32        // Slow start threshold
	rtt         time.Duration // Round trip time estimate (last measured RTT)
	rto         time.Duration // Retransmission timeout
	srtt        time.Duration // Smoothed RTT per RFC 6298
	rttVariance time.Duration // RTT variance per RFC 6298

	// Choking mechanism per I2P streaming spec
	// optDelay field: 0-60000ms = advisory delay, >60000 = choked
	optDelay        uint16    // Optional delay field from last packet
	choked          bool      // Are we being choked by remote peer (sender-side)?
	chokedUntil     time.Time // When to resume sending after being choked
	sendingChoke    bool      // Are we sending choke signals to remote peer (receiver-side)?
	lastBufferCheck int64     // Last time we checked buffer usage (TotalWritten value)

	// MTU negotiation
	localMTU  uint16 // Our advertised MTU
	remoteMTU uint16 // Remote peer's MTU (0 until negotiated)

	// Out-of-order packet handling for selective ACK (NACK)
	// Tracks packets received out of sequence to enable retransmission requests
	outOfOrderPackets map[uint32]*Packet  // Buffered packets received out of order
	nackList          map[uint32]struct{} // Sequence numbers we haven't received yet (for NACK field)
	// Using map for O(1) lookup and removal operations

	// Sent packet tracking for retransmission on NACK reception
	// Maps sequence number to sent packet info for unacknowledged packets
	sentPackets map[uint32]*sentPacket // Packets we've sent but not yet ACKed

	// Simple byte buffers for MVP
	// Using github.com/armon/circbuf for receive buffer to avoid wraparound bugs
	sendBuf []byte
	recvBuf *circbuf.Buffer

	// Receive loop coordination
	recvChan chan *Packet       // Channel for incoming packets
	errChan  chan error         // Channel for errors from receive loop
	ctx      context.Context    // Context for cancellation
	cancel   context.CancelFunc // Cancel function

	// Synchronization primitives for blocking reads/writes
	recvCond *sync.Cond // Condition variable for Read() blocking
	sendCond *sync.Cond // Condition variable for Write() flow control blocking

	// Deadlines for net.Conn interface
	readDeadline  time.Time
	writeDeadline time.Time

	// Inactivity timeout detection per I2P streaming spec
	// Default: 90 seconds. Action: send duplicate ACK.
	lastActivity      time.Time     // Last time data was sent or received
	inactivityTimeout time.Duration // Inactivity timeout duration (0 = disabled)

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

	// DefaultInactivityTimeout is the default inactivity timeout per I2P streaming spec.
	// Per spec: i2p.streaming.inactivityTimeout = 90*1000 (90 seconds).
	// When no data is sent or received for this duration, a keepalive action is taken.
	DefaultInactivityTimeout = 90 * time.Second

	// InactivityCheckInterval is how often the inactivity timer checks for timeout.
	InactivityCheckInterval = 10 * time.Second

	// MinRTO is the minimum retransmission timeout.
	// Per I2P streaming spec: MIN_RESEND_DELAY = 100ms.
	MinRTO = 100 * time.Millisecond

	// MaxRTO is the maximum retransmission timeout.
	// Per I2P streaming spec: MAX_RESEND_DELAY = 60 seconds.
	MaxRTO = 60 * time.Second
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

// DialWithManager initiates a connection using a StreamManager for packet routing.
// This is the recommended way to create outgoing connections as it integrates with I2CP callbacks.
// The manager will route incoming packets to this connection automatically.
func DialWithManager(manager *StreamManager, dest *go_i2cp.Destination, localPort, remotePort uint16) (*StreamConn, error) {
	if manager == nil {
		return nil, fmt.Errorf("manager cannot be nil")
	}

	session := manager.Session()
	conn, err := createConnectionStruct(session, manager, dest, localPort, remotePort, DefaultMTU)
	if err != nil {
		return nil, err
	}

	// Register connection with manager BEFORE handshake so SYN-ACK can be routed
	manager.RegisterConnection(localPort, remotePort, conn)

	// Perform handshake
	if err := performHandshake(conn, DefaultConnectTimeout); err != nil {
		manager.UnregisterConnection(localPort, remotePort)
		return nil, err
	}

	return conn, nil
}

// DialWithMTU is like Dial but allows specifying a custom MTU and timeout.
// Use ECIESMTU (1812) for ECIES-X25519 connections for better efficiency.
func DialWithMTU(session *go_i2cp.Session, dest *go_i2cp.Destination, localPort, remotePort uint16, mtu int, timeout time.Duration) (*StreamConn, error) {
	conn, err := createConnectionStruct(session, nil, dest, localPort, remotePort, mtu)
	if err != nil {
		return nil, err
	}

	return conn, performHandshake(conn, timeout)
}

// validateConnectionParams checks MTU bounds, session and destination validity.
// Returns an error if any parameter is invalid.
func validateConnectionParams(session *go_i2cp.Session, dest *go_i2cp.Destination, mtu int) error {
	if mtu < MinMTU {
		return fmt.Errorf("MTU %d is below minimum %d", mtu, MinMTU)
	}
	if mtu > DefaultMTU && mtu != ECIESMTU {
		return fmt.Errorf("MTU %d exceeds recommended maximum %d (use %d for ECIES)", mtu, DefaultMTU, ECIESMTU)
	}
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	if dest == nil {
		return fmt.Errorf("destination cannot be nil")
	}
	return nil
}

// generateConnectionIdentifiers creates the initial sequence number and stream ID.
// Returns ISN, localStreamID, and any error.
func generateConnectionIdentifiers() (uint32, uint32, error) {
	isn, err := generateISN()
	if err != nil {
		return 0, 0, fmt.Errorf("generate ISN: %w", err)
	}

	localStreamID, err := generateISN()
	if err != nil {
		return 0, 0, fmt.Errorf("generate stream ID: %w", err)
	}

	return isn, localStreamID, nil
}

// initializeStreamConn creates and initializes a StreamConn with the given parameters.
// Sets up all fields, buffers, channels, and condition variables.
func initializeStreamConn(session *go_i2cp.Session, manager *StreamManager, dest *go_i2cp.Destination,
	localPort, remotePort uint16, mtu int, isn, localStreamID uint32, recvBuf *circbuf.Buffer,
	ctx context.Context, cancel context.CancelFunc) *StreamConn {

	conn := &StreamConn{
		manager:           manager,
		session:           session,
		dest:              dest,
		localPort:         localPort,
		remotePort:        remotePort,
		localStreamID:     localStreamID,
		remoteStreamID:    0, // Will be set from SYN-ACK
		sendSeq:           isn,
		recvSeq:           0,                 // Will be set from SYN-ACK
		windowSize:        DefaultWindowSize, // Per spec: initial window is 6 packets
		cwnd:              DefaultWindowSize, // Congestion window starts at 6
		ssthresh:          MaxWindowSize,     // Slow start threshold at max (128 packets)
		rtt:               8 * time.Second,   // Initial RTT estimate
		rto:               9 * time.Second,   // Initial RTO per spec
		recvBuf:           recvBuf,
		recvChan:          make(chan *Packet, 32), // Buffer for incoming packets
		errChan:           make(chan error, 1),
		ctx:               ctx,
		cancel:            cancel,
		state:             StateInit,
		localMTU:          uint16(mtu),
		remoteMTU:         0, // Will be negotiated
		lastActivity:      time.Now(),
		inactivityTimeout: DefaultInactivityTimeout,
	}
	conn.recvCond = sync.NewCond(&conn.mu)
	conn.sendCond = sync.NewCond(&conn.mu)

	return conn
}

// createConnectionStruct creates a new StreamConn structure without performing the handshake.
func createConnectionStruct(session *go_i2cp.Session, manager *StreamManager, dest *go_i2cp.Destination, localPort, remotePort uint16, mtu int) (*StreamConn, error) {
	if err := validateConnectionParams(session, dest, mtu); err != nil {
		return nil, err
	}

	isn, localStreamID, err := generateConnectionIdentifiers()
	if err != nil {
		return nil, err
	}

	recvBuf, err := circbuf.NewBuffer(64 * 1024) // 64KB receive buffer
	if err != nil {
		return nil, fmt.Errorf("create receive buffer: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	conn := initializeStreamConn(session, manager, dest, localPort, remotePort, mtu,
		isn, localStreamID, recvBuf, ctx, cancel)

	log.Info().
		Uint16("localPort", localPort).
		Uint16("remotePort", remotePort).
		Uint32("isn", isn).
		Int("mtu", mtu).
		Msg("initiating connection")

	return conn, nil
}

// performHandshake executes the three-way handshake for a connection.
func performHandshake(conn *StreamConn, timeout time.Duration) error {
	if err := conn.sendSYN(); err != nil {
		return fmt.Errorf("send SYN: %w", err)
	}
	conn.setState(StateSynSent)

	if err := completeHandshake(conn, timeout); err != nil {
		return err
	}

	conn.setState(StateEstablished)
	startConnectionGoroutines(conn)
	logConnectionEstablished(conn)
	return nil
}

// completeHandshake waits for SYN-ACK and sends final ACK.
func completeHandshake(conn *StreamConn, timeout time.Duration) error {
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), timeout)
	defer timeoutCancel()

	synAck, err := conn.waitForSynAck(timeoutCtx)
	if err != nil {
		return fmt.Errorf("wait for SYN-ACK: %w", err)
	}
	conn.processSynAck(synAck)

	if err := conn.sendACK(); err != nil {
		return fmt.Errorf("send ACK: %w", err)
	}
	return nil
}

// startConnectionGoroutines starts the receive loop and timer goroutines.
func startConnectionGoroutines(conn *StreamConn) {
	go conn.receiveLoop()
	go conn.retransmitTimer()
	go conn.inactivityTimer()
}

// logConnectionEstablished logs info about the established connection.
func logConnectionEstablished(conn *StreamConn) {
	log.Info().
		Str("state", conn.state.String()).
		Uint16("negotiatedMTU", conn.getNegotiatedMTU()).
		Dur("rtt", conn.rtt).
		Msg("connection established")
}

// sendSYN sends a SYN packet to initiate the handshake.
// Includes our MTU in the MAX_PACKET_SIZE_INCLUDED option for negotiation.
// Per I2P spec, SYN packets include:
//   - 8 NACKs containing hash of remote destination (replay prevention)
//   - FROM destination (our address for replies)
//   - Packet signature (authentication)
func (s *StreamConn) sendSYN() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nacks, err := s.generateReplayPreventionNACKs()
	if err != nil {
		return err
	}

	pkt := s.buildSYNPacket(nacks)

	if err := s.signAndSendPacket(pkt); err != nil {
		return err
	}

	s.logSYNSent(pkt, len(nacks))
	s.sendSeq++ // SYN consumes one sequence number

	return nil
}

// generateReplayPreventionNACKs creates the 8-NACK array from destination hash.
// Per I2P spec, this prevents replay attacks by binding SYN to specific destination.
func (s *StreamConn) generateReplayPreventionNACKs() ([]uint32, error) {
	destHash, err := hashDestination(s.dest)
	if err != nil {
		return nil, fmt.Errorf("hash destination: %w", err)
	}

	nacks := make([]uint32, 8)
	for i := 0; i < 8; i++ {
		nacks[i] = binary.BigEndian.Uint32(destHash[i*4 : (i+1)*4])
	}

	return nacks, nil
}

// buildSYNPacket constructs the SYN packet with all required fields.
// Per I2P streaming spec, initial SYN has FlagNoACK set because ackThrough is not valid yet.
func (s *StreamConn) buildSYNPacket(nacks []uint32) *Packet {
	return &Packet{
		SendStreamID:    0,               // Always 0 in initial SYN per spec
		RecvStreamID:    s.localStreamID, // Our stream ID for peer to use
		SequenceNum:     s.sendSeq,
		AckThrough:      0, // No ACK yet - FlagNoACK tells peer to ignore this
		Flags:           FlagSYN | FlagNoACK | FlagMaxPacketSizeIncluded | FlagSignatureIncluded | FlagFromIncluded,
		MaxPacketSize:   s.localMTU,
		NACKs:           nacks,
		FromDestination: s.session.Destination(),
	}
}

// signAndSendPacket signs the packet and sends it to the remote destination.
func (s *StreamConn) signAndSendPacket(pkt *Packet) error {
	keyPair, err := s.session.SigningKeyPair()
	if err != nil {
		return fmt.Errorf("get signing key: %w", err)
	}
	if err := SignPacket(pkt, keyPair); err != nil {
		return fmt.Errorf("sign SYN: %w", err)
	}

	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal SYN: %w", err)
	}

	stream := go_i2cp.NewStream(data)
	if err := s.session.SendMessage(s.dest, 6, s.localPort, s.remotePort, stream, 0); err != nil {
		return fmt.Errorf("send SYN message: %w", err)
	}

	return nil
}

// logSYNSent logs the SYN packet details.
func (s *StreamConn) logSYNSent(pkt *Packet, nackCount int) {
	log.Debug().
		Uint32("seq", pkt.SequenceNum).
		Uint16("flags", pkt.Flags).
		Uint16("localMTU", s.localMTU).
		Uint32("localStreamID", s.localStreamID).
		Uint16("localPort", s.localPort).
		Uint16("remotePort", s.remotePort).
		Int("nacks", nackCount).
		Msg("sent SYN")
}

// waitForSynAck polls for incoming SYN-ACK packet.
// Reads from recvChan which is populated by handleIncomingPacket.
func (s *StreamConn) waitForSynAck(ctx context.Context) (*Packet, error) {
	log.Debug().Msg("waiting for SYN-ACK")

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for SYN-ACK: %w", ctx.Err())
		case pkt := <-s.recvChan:
			if s.isSynAckPacket(pkt) {
				return pkt, nil
			}
			s.logIgnoredPacket(pkt)
		}
	}
}

// isSynAckPacket checks if the packet is a SYN-ACK response.
// Per I2P streaming spec, a SYN-ACK has the SYN flag set AND SendStreamID > 0
// (indicating the responder has assigned their stream ID, unlike initial SYN
// which has SendStreamID = 0).
func (s *StreamConn) isSynAckPacket(pkt *Packet) bool {
	if pkt.Flags&FlagSYN != 0 && pkt.SendStreamID > 0 {
		log.Debug().
			Uint32("seq", pkt.SequenceNum).
			Uint32("ack", pkt.AckThrough).
			Msg("received SYN-ACK")
		return true
	}
	return false
}

// logIgnoredPacket logs when a non-SYN-ACK packet is received during handshake.
func (s *StreamConn) logIgnoredPacket(pkt *Packet) {
	log.Debug().
		Uint16("flags", pkt.Flags).
		Msg("received non-SYN-ACK packet while waiting, ignoring")
}

// processSynAck extracts information from SYN-ACK packet.
// Sets remote sequence number, negotiates MTU, and initializes ackThrough.
func (s *StreamConn) processSynAck(pkt *Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.recvSeq = pkt.SequenceNum + 1
	s.remoteStreamID = pkt.SendStreamID
	s.ackThrough = pkt.AckThrough
	s.extractRemoteMTUFromSynAck(pkt)
	s.logSynAckProcessed(pkt)
}

// extractRemoteMTUFromSynAck extracts and negotiates MTU from the SYN-ACK packet.
// Per I2P spec, server includes MaxPacketSize in SYN-ACK with FlagMaxPacketSizeIncluded flag.
func (s *StreamConn) extractRemoteMTUFromSynAck(pkt *Packet) {
	if pkt.Flags&FlagMaxPacketSizeIncluded != 0 && pkt.MaxPacketSize > 0 {
		s.remoteMTU = pkt.MaxPacketSize
		log.Debug().
			Uint16("remoteMTU", s.remoteMTU).Uint16("localMTU", s.localMTU).
			Uint16("negotiatedMTU", s.getNegotiatedMTULocked()).
			Msg("MTU negotiated from SYN-ACK")
	} else {
		s.remoteMTU = DefaultMTU
		log.Warn().
			Uint16("localMTU", s.localMTU).Uint16("negotiatedMTU", s.getNegotiatedMTULocked()).
			Msg("SYN-ACK missing MTU flag/value, using default")
	}
}

// logSynAckProcessed logs debug information about the processed SYN-ACK.
func (s *StreamConn) logSynAckProcessed(pkt *Packet) {
	log.Debug().
		Uint32("remoteSeq", pkt.SequenceNum).Uint32("ourAck", s.recvSeq).
		Uint32("remoteStreamID", s.remoteStreamID).Uint16("remoteMTU", s.remoteMTU).
		Uint32("ackThrough", s.ackThrough).Msg("processed SYN-ACK")
}

// sendACK sends the final ACK to complete the three-way handshake.
func (s *StreamConn) sendACK() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Per I2P streaming spec, there is no explicit ACK flag.
	// The ackThrough field is always valid (unless NO_ACK is set on initial SYN).
	// A plain ACK packet has sequenceNum=0 and no SYN flag.
	pkt := &Packet{
		SendStreamID: s.localStreamID,  // Our stream ID
		RecvStreamID: s.remoteStreamID, // Peer's stream ID
		SequenceNum:  0,                // seq=0 without SYN = plain ACK per spec
		AckThrough:   s.recvSeq - 1,    // ACK the SYN-ACK
		Flags:        0,                // No flags needed for plain ACK
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
// validateSYNSource validates the source destination from a SYN packet.
// Returns the peer destination or an error if no source is available.
func (l *StreamListener) validateSYNSource(synPkt *Packet, remoteDest *go_i2cp.Destination) (*go_i2cp.Destination, error) {
	peerDest := remoteDest
	if synPkt.Flags&FlagFromIncluded != 0 && synPkt.FromDestination != nil {
		peerDest = synPkt.FromDestination
		log.Debug().Msg("using FromDestination from SYN packet")
	}

	if peerDest == nil {
		log.Error().Msg("SYN packet has no source destination - cannot reply")
		return nil, fmt.Errorf("SYN packet has no source destination")
	}
	return peerDest, nil
}

// verifySYNSignature verifies the signature on a SYN packet if present.
// Returns an error if verification fails.
func (l *StreamListener) verifySYNSignature(synPkt *Packet) error {
	if synPkt.Flags&FlagSignatureIncluded == 0 {
		return nil
	}
	if err := VerifyPacketSignature(synPkt, nil); err != nil {
		log.Warn().Err(err).Msg("SYN signature verification failed - rejecting packet")
		return fmt.Errorf("SYN signature verification failed: %w", err)
	}
	log.Debug().Msg("SYN signature verified successfully")
	return nil
}

// verifySYNReplayPrevention verifies the replay prevention NACKs in a SYN packet.
// Returns an error if verification fails.
func (l *StreamListener) verifySYNReplayPrevention(synPkt *Packet) error {
	if len(synPkt.NACKs) != 8 {
		return nil
	}

	ourHash, err := hashDestination(l.session.Destination())
	if err != nil {
		log.Warn().Err(err).Msg("failed to hash destination for replay prevention check")
		return nil
	}

	for i := 0; i < 8; i++ {
		expected := binary.BigEndian.Uint32(ourHash[i*4 : (i+1)*4])
		if synPkt.NACKs[i] != expected {
			log.Warn().Msg("SYN replay prevention check failed - rejecting")
			return fmt.Errorf("SYN replay prevention check failed")
		}
	}
	log.Debug().Msg("SYN replay prevention check passed")
	return nil
}

// extractRemoteMTU extracts the MTU from a SYN packet.
// Returns DefaultMTU if not present.
func extractRemoteMTU(synPkt *Packet, localMTU uint16) uint16 {
	if synPkt.Flags&FlagMaxPacketSizeIncluded != 0 && synPkt.MaxPacketSize > 0 {
		log.Debug().
			Uint16("remoteMTU", synPkt.MaxPacketSize).
			Uint16("localMTU", localMTU).
			Msg("extracted MTU from SYN")
		return synPkt.MaxPacketSize
	}
	log.Warn().Msg("SYN missing MTU, using default")
	return DefaultMTU
}

// createIncomingConnection creates a new StreamConn for an incoming SYN.
// Returns the connection and any error.
func (l *StreamListener) createIncomingConnection(synPkt *Packet, remotePort uint16, peerDest *go_i2cp.Destination) (*StreamConn, error) {
	isn, err := generateISN()
	if err != nil {
		return nil, fmt.Errorf("generate ISN: %w", err)
	}

	localStreamID, err := generateStreamID()
	if err != nil {
		return nil, fmt.Errorf("generate stream ID: %w", err)
	}

	recvBuf, err := circbuf.NewBuffer(64 * 1024)
	if err != nil {
		return nil, fmt.Errorf("create receive buffer: %w", err)
	}

	conn := l.initConnectionState(synPkt, remotePort, peerDest, isn, localStreamID, recvBuf)
	return conn, nil
}

// initConnectionState creates a new StreamConn with initialized state from handshake parameters.
func (l *StreamListener) initConnectionState(synPkt *Packet, remotePort uint16, peerDest *go_i2cp.Destination, isn, localStreamID uint32, recvBuf *circbuf.Buffer) *StreamConn {
	ctx, cancel := context.WithCancel(context.Background())
	conn := &StreamConn{
		manager:           l.manager,
		session:           l.session,
		dest:              peerDest,
		localPort:         l.localPort,
		remotePort:        remotePort,
		localStreamID:     localStreamID,
		remoteStreamID:    synPkt.RecvStreamID,
		sendSeq:           isn,
		recvSeq:           synPkt.SequenceNum + 1,
		windowSize:        DefaultWindowSize, // Per spec: initial window is 6 packets
		cwnd:              DefaultWindowSize, // Congestion window starts at 6
		ssthresh:          MaxWindowSize,
		rtt:               8 * time.Second,
		rto:               9 * time.Second,
		recvBuf:           recvBuf,
		recvChan:          make(chan *Packet, 32),
		errChan:           make(chan error, 1),
		ctx:               ctx,
		cancel:            cancel,
		state:             StateInit,
		localMTU:          l.localMTU,
		remoteMTU:         extractRemoteMTU(synPkt, l.localMTU),
		sentPackets:       make(map[uint32]*sentPacket),
		outOfOrderPackets: make(map[uint32]*Packet),
		nackList:          make(map[uint32]struct{}),
		lastActivity:      time.Now(),
		inactivityTimeout: DefaultInactivityTimeout,
	}
	conn.recvCond = sync.NewCond(&conn.mu)
	conn.sendCond = sync.NewCond(&conn.mu)
	return conn
}

// queueConnectionForAccept queues a connection for Accept() and starts the receive loop.
// Returns an error if the accept queue is full.
func (l *StreamListener) queueConnectionForAccept(conn *StreamConn, remotePort uint16) error {
	select {
	case l.acceptChan <- conn:
		log.Debug().
			Uint16("localPort", l.localPort).
			Uint16("remotePort", remotePort).
			Msg("queued connection for Accept()")
		return nil
	default:
		log.Warn().Msg("accept channel full, dropping connection")
		conn.cancel()
		if l.manager != nil {
			l.manager.UnregisterConnection(l.localPort, remotePort)
		}
		return fmt.Errorf("accept queue full")
	}
}

// handleIncomingSYN processes an incoming SYN packet to establish a new connection.
func (l *StreamListener) handleIncomingSYN(synPkt *Packet, remotePort uint16, remoteDest *go_i2cp.Destination) error {
	log.Debug().
		Uint32("remoteSeq", synPkt.SequenceNum).
		Uint16("remotePort", remotePort).
		Uint16("localPort", l.localPort).
		Msg("received SYN")

	if err := l.validateIncomingSYN(synPkt, remoteDest); err != nil {
		return err
	}

	peerDest, _ := l.validateSYNSource(synPkt, remoteDest)
	conn, err := l.createIncomingConnection(synPkt, remotePort, peerDest)
	if err != nil {
		return err
	}

	return l.finalizeIncomingConnection(conn, remotePort)
}

// validateIncomingSYN performs all validation checks on an incoming SYN packet.
func (l *StreamListener) validateIncomingSYN(synPkt *Packet, remoteDest *go_i2cp.Destination) error {
	if _, err := l.validateSYNSource(synPkt, remoteDest); err != nil {
		return err
	}

	if err := l.verifySYNSignature(synPkt); err != nil {
		return err
	}

	return l.verifySYNReplayPrevention(synPkt)
}

// finalizeIncomingConnection registers the connection, sends SYN-ACK, and starts the receive loop.
func (l *StreamListener) finalizeIncomingConnection(conn *StreamConn, remotePort uint16) error {
	if l.manager != nil {
		l.manager.RegisterConnection(l.localPort, remotePort, conn)
	}

	if err := conn.sendSynAck(); err != nil {
		if l.manager != nil {
			l.manager.UnregisterConnection(l.localPort, remotePort)
		}
		return fmt.Errorf("send SYN-ACK: %w", err)
	}

	conn.setState(StateSynRcvd)
	go conn.receiveLoop()

	return l.queueConnectionForAccept(conn, remotePort)
}

// sendSynAck sends a SYN-ACK packet in response to a SYN.
// Includes our MTU in the MAX_PACKET_SIZE_INCLUDED option for negotiation.
func (s *StreamConn) sendSynAck() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pkt := s.buildSynAckPacket()

	if err := s.signSynAckPacket(pkt); err != nil {
		return err
	}

	if err := s.transmitSynAckPacket(pkt); err != nil {
		return err
	}

	s.logSentSynAck(pkt)
	s.sendSeq++
	return nil
}

// buildSynAckPacket creates a SYN-ACK packet with appropriate flags and options.
// Per I2P streaming spec, a SYN-ACK is identified by FlagSYN set and SendStreamID > 0.
// There is no explicit ACK flag - ackThrough is always valid.
func (s *StreamConn) buildSynAckPacket() *Packet {
	return &Packet{
		SendStreamID:    s.localStreamID,
		RecvStreamID:    s.remoteStreamID,
		SequenceNum:     s.sendSeq,
		AckThrough:      s.recvSeq - 1,
		Flags:           FlagSYN | FlagMaxPacketSizeIncluded | FlagSignatureIncluded | FlagFromIncluded,
		MaxPacketSize:   s.localMTU,
		FromDestination: s.session.Destination(),
	}
}

// signSynAckPacket signs the SYN-ACK packet using the session's signing key pair.
func (s *StreamConn) signSynAckPacket(pkt *Packet) error {
	keyPair, err := s.session.SigningKeyPair()
	if err != nil {
		return fmt.Errorf("get signing key pair: %w", err)
	}
	if err := SignPacket(pkt, keyPair); err != nil {
		return fmt.Errorf("sign SYN-ACK: %w", err)
	}
	return nil
}

// transmitSynAckPacket marshals and sends the SYN-ACK packet via I2CP.
func (s *StreamConn) transmitSynAckPacket(pkt *Packet) error {
	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal SYN-ACK: %w", err)
	}
	stream := go_i2cp.NewStream(data)
	if err := s.session.SendMessage(s.dest, 6, s.localPort, s.remotePort, stream, 0); err != nil {
		return fmt.Errorf("send SYN-ACK message: %w", err)
	}
	return nil
}

// logSentSynAck logs debug information about the sent SYN-ACK packet.
func (s *StreamConn) logSentSynAck(pkt *Packet) {
	log.Debug().
		Uint32("seq", pkt.SequenceNum).Uint32("ack", pkt.AckThrough).
		Uint16("flags", pkt.Flags).Uint16("localMTU", s.localMTU).
		Msg("sent SYN-ACK")
}

// validateWriteStateLocked checks if the connection is in a valid state for writing.
// Returns an error if the connection is closed, not established, or deadline exceeded.
// Must be called with s.mu held.
func (s *StreamConn) validateWriteStateLocked() error {
	if s.closed {
		return fmt.Errorf("connection closed")
	}
	if s.state != StateEstablished {
		return fmt.Errorf("connection not established (state: %s)", s.state)
	}
	if !s.writeDeadline.IsZero() && time.Now().After(s.writeDeadline) {
		return &timeoutError{}
	}
	return nil
}

// checkWriteDeadlineLocked checks if the write deadline has been exceeded.
// Returns a timeoutError if the deadline has passed, nil otherwise.
// Must be called with s.mu held.
func (s *StreamConn) checkWriteDeadlineLocked() error {
	if !s.writeDeadline.IsZero() && time.Now().After(s.writeDeadline) {
		return &timeoutError{}
	}
	return nil
}

// waitWithTimerSignal waits on sendCond while a timer goroutine broadcasts on timeout.
// Returns the done channel that must be closed after sendCond.Wait() returns.
// Must be called with s.mu held.
func (s *StreamConn) waitWithTimerSignal(timerChan <-chan time.Time) chan struct{} {
	done := make(chan struct{})
	go func() {
		select {
		case <-timerChan:
			s.mu.Lock()
			if s.sendCond != nil {
				s.sendCond.Broadcast()
			}
			s.mu.Unlock()
		case <-done:
		}
	}()
	return done
}

// waitForChokeCondVar waits for the choke period to expire using condition variables.
// Returns an error if deadline exceeded or connection state becomes invalid.
// Must be called with s.mu held.
func (s *StreamConn) waitForChokeCondVar() error {
	for s.choked && time.Now().Before(s.chokedUntil) && !s.closed {
		if err := s.checkWriteDeadlineLocked(); err != nil {
			return err
		}

		log.Debug().
			Time("chokedUntil", s.chokedUntil).
			Msg("peer is choked - waiting for unchoke or timeout")

		timer, timerChan := s.createChokeTimer()
		done := s.waitWithTimerSignal(timerChan)

		s.sendCond.Wait()
		timer.Stop()
		close(done)

		if err := s.checkWriteDeadlineLocked(); err != nil {
			return err
		}
		if err := s.validateWriteStateLocked(); err != nil {
			return err
		}
	}
	return nil
}

// createChokeTimer creates a timer for the choke wait period.
// Uses write deadline if set, otherwise uses choke expiration time.
// Returns the timer and its channel. Must be called with s.mu held.
func (s *StreamConn) createChokeTimer() (*time.Timer, <-chan time.Time) {
	if !s.writeDeadline.IsZero() {
		timeout := time.Until(s.writeDeadline)
		if timeout <= 0 {
			timeout = time.Nanosecond
		}
		timer := time.NewTimer(timeout)
		return timer, timer.C
	}
	chokeTimeout := time.Until(s.chokedUntil)
	if chokeTimeout <= 0 {
		chokeTimeout = time.Nanosecond
	}
	timer := time.NewTimer(chokeTimeout)
	return timer, timer.C
}

// waitForChokeFallback waits for the choke period using sleep (for tests without sendCond).
// Returns an error if deadline exceeded or connection state becomes invalid.
// Must be called with s.mu held; temporarily releases the lock during sleep.
func (s *StreamConn) waitForChokeFallback() error {
	waitDuration := time.Until(s.chokedUntil)
	if !s.writeDeadline.IsZero() {
		timeUntilDeadline := time.Until(s.writeDeadline)
		if timeUntilDeadline < waitDuration {
			waitDuration = timeUntilDeadline
		}
	}

	if waitDuration <= 0 {
		return &timeoutError{}
	}

	log.Debug().
		Dur("waitDuration", waitDuration).
		Msg("peer is choked - waiting before sending (fallback)")

	s.mu.Unlock()
	time.Sleep(waitDuration)
	s.mu.Lock()

	if err := s.checkWriteDeadlineLocked(); err != nil {
		return err
	}
	return s.validateWriteStateLocked()
}

// handleChokeWaitLocked handles waiting when the peer has sent a choke signal.
// Uses condition variables if available, falls back to sleep otherwise.
// Must be called with s.mu held.
func (s *StreamConn) handleChokeWaitLocked() error {
	if !s.choked || !time.Now().Before(s.chokedUntil) || s.closed {
		return nil
	}

	if s.sendCond != nil {
		return s.waitForChokeCondVar()
	}
	return s.waitForChokeFallback()
}

// waitForWindowSpace waits for space in the congestion window before sending.
// Returns the number of bytes already written (for partial write reporting) and any error.
// Must be called with s.mu held.
func (s *StreamConn) waitForWindowSpace(bytesWritten int) error {
	for s.sendCond != nil && s.sentPackets != nil && uint32(len(s.sentPackets)) >= s.cwnd && !s.closed {
		if err := s.checkWriteDeadlineLocked(); err != nil {
			return err
		}

		log.Debug().
			Int("inFlight", len(s.sentPackets)).
			Uint32("cwnd", s.cwnd).
			Msg("window full - waiting for ACKs")

		timer, done := s.setupWindowWaitTimer()

		s.sendCond.Wait()

		if timer != nil {
			timer.Stop()
			close(done)
		}

		if err := s.checkWriteDeadlineLocked(); err != nil {
			return err
		}
		if err := s.validateWriteStateLocked(); err != nil {
			return err
		}
	}
	return nil
}

// setupWindowWaitTimer creates a timer for window wait with deadline support.
// Returns nil timer and channel if no deadline is set.
// Must be called with s.mu held.
func (s *StreamConn) setupWindowWaitTimer() (*time.Timer, chan struct{}) {
	if s.writeDeadline.IsZero() {
		return nil, nil
	}

	timeout := time.Until(s.writeDeadline)
	if timeout <= 0 {
		timeout = time.Nanosecond
	}

	timer := time.NewTimer(timeout)
	done := s.waitWithTimerSignal(timer.C)
	return timer, done
}

// sendDataChunk sends a single chunk of data as a packet.
// Updates sequence numbers and byte counters. Must be called with s.mu held.
// Per I2P streaming spec, there is no explicit ACK flag - ackThrough is always valid.
func (s *StreamConn) sendDataChunk(chunk []byte) error {
	pkt := &Packet{
		SendStreamID: s.localStreamID,
		RecvStreamID: s.remoteStreamID,
		SequenceNum:  s.sendSeq,
		AckThrough:   s.recvSeq - 1,
		Flags:        0, // No flags needed for data packet
		Payload:      chunk,
	}

	if err := s.sendPacketLocked(pkt); err != nil {
		return fmt.Errorf("send packet: %w", err)
	}

	s.sendSeq++
	s.totalBytesSent += uint64(len(chunk))
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
//   - Window-based flow control: blocks when in-flight packets >= cwnd
//   - Choke handling: waits using condition variable (no race condition)
//
// Returns the number of bytes written or an error.
func (s *StreamConn) Write(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.validateWriteStateLocked(); err != nil {
		return 0, err
	}

	if err := s.handleChokeWaitLocked(); err != nil {
		return 0, err
	}

	return s.writeDataLocked(data)
}

// writeDataLocked writes data in chunks respecting MTU and window limits.
// Must be called with s.mu held.
func (s *StreamConn) writeDataLocked(data []byte) (int, error) {
	total := len(data)
	mtu := int(s.getNegotiatedMTULocked())

	log.Debug().
		Int("bytes", total).
		Int("mtu", mtu).
		Uint32("startSeq", s.sendSeq).
		Msg("writing data")

	written, err := s.writeChunksLocked(data, total, mtu)
	if err != nil {
		return written, err
	}

	log.Debug().
		Int("bytes", total).
		Uint32("endSeq", s.sendSeq).
		Msg("write complete")

	return total, nil
}

// writeChunksLocked writes data in MTU-sized chunks with flow control.
// Must be called with s.mu held.
func (s *StreamConn) writeChunksLocked(data []byte, total, mtu int) (int, error) {
	for len(data) > 0 {
		if err := s.waitForWindowSpace(total - len(data)); err != nil {
			return total - len(data), err
		}

		chunk := data
		if len(chunk) > mtu {
			chunk = data[:mtu]
		}

		if err := s.sendDataChunk(chunk); err != nil {
			return total - len(data), err
		}

		data = data[len(chunk):]
	}
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
//
// validateReadStateLocked checks if the connection has data or is closed with EOF.
// Returns io.EOF if connection is closed with no data.
// Must be called with s.mu held.
func (s *StreamConn) validateReadStateLocked() error {
	if s.closed && s.recvBuf.TotalWritten() == 0 {
		return io.EOF
	}
	return nil
}

// checkReadDeadlineLocked checks if the read deadline has been exceeded.
// Returns a timeoutError if the deadline has passed, nil otherwise.
// Must be called with s.mu held.
func (s *StreamConn) checkReadDeadlineLocked() error {
	if !s.readDeadline.IsZero() && time.Now().After(s.readDeadline) {
		return &timeoutError{}
	}
	return nil
}

// setupReadTimer creates a timer for read deadline and returns cleanup resources.
// Returns nil timer if no deadline is set. Must be called with s.mu held.
func (s *StreamConn) setupReadTimer() (*time.Timer, chan struct{}) {
	if s.readDeadline.IsZero() {
		return nil, nil
	}

	timeout := time.Until(s.readDeadline)
	if timeout <= 0 {
		return nil, nil
	}

	timer := time.NewTimer(timeout)
	done := make(chan struct{})
	go func() {
		select {
		case <-timer.C:
			s.mu.Lock()
			s.recvCond.Broadcast()
			s.mu.Unlock()
		case <-done:
		}
	}()
	return timer, done
}

// waitForReadDataLocked blocks until data is available or deadline expires.
// Returns an error if timeout or closed. Must be called with s.mu held.
func (s *StreamConn) waitForReadDataLocked() error {
	for s.recvBuf.TotalWritten() == 0 && !s.closed {
		if err := s.checkReadDeadlineLocked(); err != nil {
			return err
		}

		timer, done := s.setupReadTimer()
		if timer == nil && !s.readDeadline.IsZero() {
			return &timeoutError{}
		}

		s.recvCond.Wait()

		if timer != nil {
			timer.Stop()
			close(done)
		}

		if err := s.checkReadDeadlineLocked(); err != nil {
			return err
		}
	}
	return nil
}

// consumeBufferDataLocked reads data from the receive buffer and handles remaining data.
// Returns the number of bytes read and any error. Must be called with s.mu held.
func (s *StreamConn) consumeBufferDataLocked(buf []byte) (int, error) {
	data := s.recvBuf.Bytes()
	n := copy(buf, data)

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

// handlePostReadActionsLocked handles buffer delivery and choke signals after reading.
// Must be called with s.mu held.
func (s *StreamConn) handlePostReadActionsLocked() {
	if len(s.outOfOrderPackets) > 0 {
		s.deliverBufferedPacketsLocked()
	}

	if s.sendingChoke {
		currentBufferUsed := s.recvBuf.TotalWritten()
		bufferSize := int64(s.recvBuf.Size())
		bufferUsage := float64(currentBufferUsed) / float64(bufferSize)

		if bufferUsage < 0.3 {
			if err := s.sendUnchokeSignalLocked(); err != nil {
				log.Warn().Err(err).Msg("failed to send unchoke signal after read")
			}
		}
	}
}

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

	if err := s.validateReadStateLocked(); err != nil {
		return 0, err
	}

	if err := s.waitForReadDataLocked(); err != nil {
		return 0, err
	}

	if err := s.validateReadStateLocked(); err != nil {
		return 0, err
	}

	n, err := s.consumeBufferDataLocked(buf)
	if err != nil {
		return n, err
	}

	s.handlePostReadActionsLocked()
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

// retransmitTimer periodically checks for packets that have timed out and need retransmission.
// Implements RFC 6298 timeout-based retransmission with exponential backoff.
// Runs until connection closes or max retries exceeded.
func (s *StreamConn) retransmitTimer() {
	log.Debug().Msg("retransmit timer started")
	defer log.Debug().Msg("retransmit timer stopped")

	// Check every 100ms for timeouts (fine-grained for responsive retransmission)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.checkRetransmissions(); err != nil {
				// Fatal error (max retries exceeded) - close connection
				log.Error().Err(err).Msg("retransmission failed, closing connection")
				s.Close()
				return
			}
		}
	}
}

// findTimedOutPacketsLocked scans sent packets for those exceeding the RTO threshold.
// Returns a slice of sequence numbers for packets that need retransmission.
// Caller must hold s.mu.
func (s *StreamConn) findTimedOutPacketsLocked() []uint32 {
	now := time.Now()
	var timedOutSeqs []uint32

	for seq, info := range s.sentPackets {
		if now.Sub(info.sentTime) > s.rto {
			timedOutSeqs = append(timedOutSeqs, seq)
		}
	}

	return timedOutSeqs
}

// applyExponentialBackoffLocked doubles the RTO per RFC 6298 (capped at 60s).
// Logs the backoff with count of timed-out packets.
// Caller must hold s.mu.
func (s *StreamConn) applyExponentialBackoffLocked(timedOutCount int) {
	oldRTO := s.rto
	s.rto = s.rto * 2
	if s.rto > 60*time.Second {
		s.rto = 60 * time.Second
	}

	log.Debug().
		Int("count", timedOutCount).
		Dur("oldRTO", oldRTO).
		Dur("newRTO", s.rto).
		Msg("packets timed out, applying exponential backoff")
}

// retransmitTimedOutPacketsLocked retransmits all timed-out packets.
// Returns error if any packet exceeds max retries (10 attempts).
// Caller must hold s.mu.
func (s *StreamConn) retransmitTimedOutPacketsLocked(timedOutSeqs []uint32) error {
	for _, seq := range timedOutSeqs {
		info := s.sentPackets[seq]

		// Check max retries BEFORE incrementing (retransmitPacketLocked will increment)
		if info.retryCount >= 10 {
			log.Error().
				Uint32("seq", seq).
				Int("retries", info.retryCount).
				Msg("max retransmissions exceeded")
			return fmt.Errorf("max retransmissions exceeded for packet %d", seq)
		}

		// Retransmit packet (this will increment retryCount and update sentTime)
		if err := s.retransmitPacketLocked(seq); err != nil {
			log.Warn().
				Err(err).
				Uint32("seq", seq).
				Msg("timeout retransmission failed")
			continue
		}

		log.Debug().
			Uint32("seq", seq).
			Int("retryCount", info.retryCount).
			Dur("rto", s.rto).
			Msg("retransmitted packet due to timeout")
	}

	return nil
}

// checkRetransmissions scans sent packets for timeouts and retransmits them.
// Implements exponential backoff per RFC 6298: double RTO on timeout (max 60s).
// Returns error if max retries (10) exceeded for any packet.
func (s *StreamConn) checkRetransmissions() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Skip if no RTO calculated yet (need at least one RTT measurement)
	if s.rto == 0 {
		return nil
	}

	timedOutSeqs := s.findTimedOutPacketsLocked()
	if len(timedOutSeqs) == 0 {
		return nil
	}

	s.applyExponentialBackoffLocked(len(timedOutSeqs))
	return s.retransmitTimedOutPacketsLocked(timedOutSeqs)
}

// inactivityTimer periodically checks for connection inactivity and sends keepalive.
// Per I2P streaming spec (i2p.streaming.inactivityTimeout), default is 90 seconds.
// The default inactivity action is to send a duplicate ACK as a keepalive.
// Runs until connection closes.
func (s *StreamConn) inactivityTimer() {
	log.Debug().Msg("inactivity timer started")
	defer log.Debug().Msg("inactivity timer stopped")

	ticker := time.NewTicker(InactivityCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkInactivity()
		}
	}
}

// checkInactivity checks if the connection has been inactive for too long.
// If inactive beyond the timeout, sends a duplicate ACK as a keepalive.
// This is per I2P streaming spec: i2p.streaming.inactivityAction = 1 (send duplicate ACK).
func (s *StreamConn) checkInactivity() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Skip if inactivity timeout is disabled or connection not established
	if s.inactivityTimeout == 0 || s.state != StateEstablished || s.closed {
		return
	}

	// Check if we've been inactive for too long
	inactiveDuration := time.Since(s.lastActivity)
	if inactiveDuration < s.inactivityTimeout {
		return
	}

	log.Debug().
		Dur("inactive", inactiveDuration).
		Dur("timeout", s.inactivityTimeout).
		Msg("inactivity timeout reached - sending keepalive ACK")

	// Send a duplicate ACK as keepalive (i2p.streaming.inactivityAction = 1)
	// This signals we're still alive without consuming sequence numbers
	if err := s.sendAckLocked(); err != nil {
		log.Warn().Err(err).Msg("failed to send keepalive ACK")
		return
	}

	// Update lastActivity after sending keepalive
	s.lastActivity = time.Now()
}

// SetInactivityTimeout sets the inactivity timeout for the connection.
// Set to 0 to disable inactivity detection.
// Default is 90 seconds per I2P streaming spec.
func (s *StreamConn) SetInactivityTimeout(timeout time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inactivityTimeout = timeout
}

// GetInactivityTimeout returns the current inactivity timeout setting.
func (s *StreamConn) GetInactivityTimeout() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inactivityTimeout
}

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

	s.lastActivity = time.Now()
	s.logProcessingPacket(pkt)
	return s.dispatchPacketByFlags(pkt)
}

// logProcessingPacket logs debug information about the packet being processed.
func (s *StreamConn) logProcessingPacket(pkt *Packet) {
	log.Debug().
		Uint32("seq", pkt.SequenceNum).Uint32("ack", pkt.AckThrough).
		Uint16("flags", pkt.Flags).Int("payload", len(pkt.Payload)).
		Str("state", s.state.String()).Msg("processing packet")
}

// dispatchPacketByFlags routes the packet to the appropriate handler based on flags.
// Per I2P streaming spec:
//   - There is no explicit ACK flag; ackThrough is always valid unless NO_ACK is set
//   - SYN-ACK is identified by SYN flag + SendStreamID > 0
//   - Plain ACK is identified by sequenceNum=0 and no SYN flag (per spec: "If the
//     sequenceNum is 0 and the SYN flag is not set, this is a plain ACK packet that
//     should not be ACKed.")
//
// Note: Order matters! More specific cases first. Plain ACK must be checked before
// data payload to ensure packets with seq=0 are handled correctly.
func (s *StreamConn) dispatchPacketByFlags(pkt *Packet) error {
	switch {
	case pkt.Flags&FlagSYN != 0 && pkt.SendStreamID > 0:
		// SYN-ACK: SYN flag set and has a stream ID (response, not initial SYN)
		return s.handleSynAckLocked(pkt)
	case s.state == StateSynRcvd && pkt.Flags&FlagSYN == 0 && pkt.Flags&FlagCLOSE == 0 && pkt.Flags&FlagRESET == 0:
		// Final ACK of three-way handshake: not SYN/CLOSE/RESET while in SynRcvd state
		return s.handleFinalAckLocked(pkt)
	case pkt.Flags&FlagCLOSE != 0:
		return s.handleCloseLocked(pkt)
	case pkt.Flags&FlagRESET != 0:
		return s.handleResetLocked(pkt)
	case pkt.SequenceNum == 0 && pkt.Flags&FlagSYN == 0:
		// Per spec: sequenceNum=0 without SYN = plain ACK packet.
		// Plain ACK packets should NOT be ACKed back. handleAckLocked does not
		// send an ACK, which is correct. This case must be checked BEFORE the
		// data payload case to handle plain ACK packets with any payload correctly.
		return s.handleAckLocked(pkt)
	case len(pkt.Payload) > 0:
		return s.handleDataLocked(pkt)
	default:
		log.Debug().Uint16("flags", pkt.Flags).Msg("packet with no recognized flags")
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

	// Initialize ackThrough from the final ACK of the 3-way handshake.
	// This is critical: the client's ACK acknowledges our SYN-ACK (with AckThrough = our ISN).
	// We must initialize ackThrough here so that subsequent ACK comparisons
	// using seqGreaterThan() work correctly. Without this, ackThrough stays at 0
	// and seqGreaterThan(small_positive, 0) can fail due to signed int32 overflow.
	s.ackThrough = pkt.AckThrough

	// Transition to ESTABLISHED
	s.setState(StateEstablished)

	// Start retransmit timer now that we're established
	// (receiveLoop was already started in handleIncomingSYN)
	go s.retransmitTimer()

	// Start inactivity timer for keepalive detection
	go s.inactivityTimer()

	log.Info().
		Str("state", s.state.String()).
		Uint16("negotiatedMTU", s.getNegotiatedMTULocked()).
		Msg("server-side connection established")

	return nil
}

// handleCloseLocked processes a CLOSE packet.
// Must be called with s.mu held.
func (s *StreamConn) handleCloseLocked(pkt *Packet) error {
	log.Debug().Msg("received CLOSE")

	// Verify CLOSE signature if present
	if pkt.Flags&FlagSignatureIncluded != 0 {
		if err := VerifyPacketSignature(pkt, nil); err != nil {
			log.Warn().Err(err).Msg("CLOSE signature verification failed - rejecting packet")
			return fmt.Errorf("CLOSE signature verification failed: %w", err)
		}
		log.Debug().Msg("CLOSE signature verified successfully")
	}

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

	// Verify RESET signature if present
	if pkt.Flags&FlagSignatureIncluded != 0 {
		if err := VerifyPacketSignature(pkt, nil); err != nil {
			log.Warn().Err(err).Msg("RESET signature verification failed - rejecting packet")
			return fmt.Errorf("RESET signature verification failed: %w", err)
		}
		log.Debug().Msg("RESET signature verified successfully")
	}

	s.setState(StateClosed)
	s.closed = true
	s.recvCond.Broadcast()

	return fmt.Errorf("connection reset by peer")
}

// handleAckLocked processes an ACK packet.
// updateRTTEstimate updates RTT estimates per RFC 6298 algorithm.
// Must be called with s.mu held.
func (s *StreamConn) updateRTTEstimate(rtt time.Duration) {
	s.rtt = rtt

	if s.srtt == 0 {
		s.srtt = rtt
		s.rttVariance = rtt / 2
		log.Debug().
			Dur("rtt", rtt).
			Dur("srtt", s.srtt).
			Dur("rttVar", s.rttVariance).
			Msg("first RTT measurement")
		return
	}

	const alpha = 0.125 // 1/8
	const beta = 0.25   // 1/4

	var diff time.Duration
	if s.srtt > rtt {
		diff = s.srtt - rtt
	} else {
		diff = rtt - s.srtt
	}

	s.rttVariance = time.Duration(float64(s.rttVariance)*(1-beta) + beta*float64(diff))
	s.srtt = time.Duration(float64(s.srtt)*(1-alpha) + alpha*float64(rtt))

	log.Debug().
		Dur("rtt", rtt).
		Dur("srtt", s.srtt).
		Dur("rttVar", s.rttVariance).
		Msg("updated RTT estimate")
}

// calculateRTO calculates and sets the retransmission timeout.
// Uses MinRTO (100ms) and MaxRTO (60s) bounds per I2P streaming spec.
// Must be called with s.mu held.
func (s *StreamConn) calculateRTO() {
	s.rto = s.srtt + 4*s.rttVariance

	if s.rto < MinRTO {
		s.rto = MinRTO
	}
	if s.rto > MaxRTO {
		s.rto = MaxRTO
	}

	log.Debug().
		Dur("rto", s.rto).
		Msg("calculated RTO")
}

// measureRTTFromAck measures RTT from an ACKed packet if available.
// Must be called with s.mu held.
func (s *StreamConn) measureRTTFromAck(ackThrough uint32) {
	info, exists := s.sentPackets[ackThrough]
	if !exists {
		return
	}

	rtt := time.Since(info.sentTime)
	s.updateRTTEstimate(rtt)
	s.calculateRTO()
}

// updateCongestionWindow updates the congestion window based on slow start/congestion avoidance.
// Must be called with s.mu held.
func (s *StreamConn) updateCongestionWindow() {
	if s.cwnd < s.ssthresh {
		oldCwnd := s.cwnd
		s.cwnd = min(s.cwnd*2, s.ssthresh)
		s.windowSize = s.cwnd

		log.Debug().
			Uint32("oldCwnd", oldCwnd).
			Uint32("newCwnd", s.cwnd).
			Uint32("ssthresh", s.ssthresh).
			Msg("slow start: doubled window")
	} else {
		oldCwnd := s.cwnd
		s.cwnd = min(s.cwnd+1, MaxWindowSize)
		s.windowSize = s.cwnd

		log.Debug().
			Uint32("oldCwnd", oldCwnd).
			Uint32("newCwnd", s.cwnd).
			Uint32("maxWindow", MaxWindowSize).
			Msg("congestion avoidance: incremented window")
	}
}

// handleNACKsLocked processes NACKs and triggers retransmissions.
// Must be called with s.mu held.
func (s *StreamConn) handleNACKsLocked(nacks []uint32) {
	if len(nacks) == 0 {
		return
	}

	log.Debug().
		Int("nackCount", len(nacks)).
		Msg("processing NACK requests")

	oldCwnd := s.cwnd
	oldSsthresh := s.ssthresh

	s.ssthresh = max(s.cwnd/2, 2)
	s.cwnd = s.ssthresh
	s.windowSize = s.cwnd

	log.Debug().
		Uint32("oldCwnd", oldCwnd).
		Uint32("newCwnd", s.cwnd).
		Uint32("oldSsthresh", oldSsthresh).
		Uint32("newSsthresh", s.ssthresh).
		Int("nackCount", len(nacks)).
		Msg("congestion detected: reduced window due to packet loss")

	for _, nackSeq := range nacks {
		if err := s.retransmitPacketLocked(nackSeq); err != nil {
			log.Warn().
				Err(err).
				Uint32("seq", nackSeq).
				Msg("retransmission failed")
		}
	}
}

// handleOptionalDelayLocked processes the choke/unchoke mechanism.
// Must be called with s.mu held.
func (s *StreamConn) handleOptionalDelayLocked(pkt *Packet) {
	if pkt.Flags&FlagDelayRequested == 0 {
		return
	}

	if pkt.OptionalDelay > 60000 {
		s.choked = true
		s.chokedUntil = time.Now().Add(time.Second)
		log.Debug().
			Uint16("delay", pkt.OptionalDelay).
			Time("chokedUntil", s.chokedUntil).
			Msg("peer is choked - pausing transmission")
	} else {
		wasChoked := s.choked
		s.choked = false
		s.chokedUntil = time.Time{}
		if wasChoked && s.sendCond != nil {
			s.sendCond.Broadcast()
		}
		if pkt.OptionalDelay > 0 {
			log.Debug().
				Uint16("delay", pkt.OptionalDelay).
				Msg("peer requests delay")
		}
	}
}

// handleAckLocked processes an incoming ACK packet.
// Updates ack tracking, RTT estimates, congestion window, and handles NACKs.
// Per I2P spec, ackThrough is always valid unless FlagNoACK is set.
// Must be called with s.mu held.
func (s *StreamConn) handleAckLocked(pkt *Packet) error {
	// Per I2P streaming spec, ignore ackThrough if NO_ACK flag is set
	if pkt.Flags&FlagNoACK != 0 {
		log.Debug().Msg("ignoring ackThrough due to NO_ACK flag")
	} else if seqGreaterThan(pkt.AckThrough, s.ackThrough) {
		oldAck := s.ackThrough
		s.ackThrough = pkt.AckThrough
		log.Debug().
			Uint32("ackThrough", s.ackThrough).
			Msg("updated ackThrough")

		s.measureRTTFromAck(pkt.AckThrough)
		s.cleanupAckedPacketsLocked(oldAck, pkt.AckThrough)
		s.updateCongestionWindow()
	}

	s.handleNACKsLocked(pkt.NACKs)
	s.handleOptionalDelayLocked(pkt)

	return nil
}

// handleDataLocked processes a data packet with selective ACK (NACK) support.
// handleBufferFullLocked handles the case when receive buffer is full.
// Stores the packet for later delivery and sends choke signal.
// Must be called with s.mu held.
func (s *StreamConn) handleBufferFullLocked(pkt *Packet, seq uint32) error {
	log.Warn().Msg("receive buffer full - buffering packet for later")
	s.outOfOrderPackets[seq] = pkt

	if !s.sendingChoke {
		if err := s.sendChokeSignalLocked(); err != nil {
			log.Warn().Err(err).Msg("failed to send choke signal")
		}
	}

	if err := s.sendAckLocked(); err != nil {
		log.Warn().Err(err).Msg("failed to send ACK during buffer full")
	}

	return nil
}

// processInSequencePacketLocked processes a packet that arrived in sequence.
// Must be called with s.mu held.
func (s *StreamConn) processInSequencePacketLocked(pkt *Packet, seq uint32) error {
	n, err := s.recvBuf.Write(pkt.Payload)
	if err != nil {
		return s.handleBufferFullLocked(pkt, seq)
	}

	log.Debug().
		Int("bytes", n).
		Uint32("seq", s.recvSeq).
		Msg("buffered payload")

	s.recvSeq++
	s.totalBytesReceived += uint64(n)
	s.removeFromNACKListLocked(seq)
	s.deliverBufferedPacketsLocked()

	// Per I2P streaming spec, ackThrough is always valid unless NO_ACK flag is set
	if pkt.Flags&FlagNoACK == 0 && seqGreaterThan(pkt.AckThrough, s.ackThrough) {
		s.ackThrough = pkt.AckThrough
	}

	s.manageChokeStateLocked()
	s.recvCond.Broadcast()

	if !s.sendingChoke || len(s.nackList) > 0 {
		if err := s.sendAckLocked(); err != nil {
			log.Warn().Err(err).Msg("failed to send ACK")
		}
	}

	return nil
}

// manageChokeStateLocked checks buffer usage and sends choke/unchoke signals.
// Must be called with s.mu held.
func (s *StreamConn) manageChokeStateLocked() {
	currentBufferUsed := s.recvBuf.TotalWritten()
	if currentBufferUsed == s.lastBufferCheck {
		return
	}

	s.lastBufferCheck = currentBufferUsed
	bufferUsage := s.calculateBufferUsage(currentBufferUsed)

	s.updateChokeStateForUsage(bufferUsage)
}

// calculateBufferUsage computes the buffer usage ratio.
func (s *StreamConn) calculateBufferUsage(currentBufferUsed int64) float64 {
	bufferSize := int64(s.recvBuf.Size())
	return float64(currentBufferUsed) / float64(bufferSize)
}

// updateChokeStateForUsage sends choke or unchoke signals based on buffer usage thresholds.
// Must be called with s.mu held.
func (s *StreamConn) updateChokeStateForUsage(bufferUsage float64) {
	if bufferUsage > 0.8 && !s.sendingChoke {
		if err := s.sendChokeSignalLocked(); err != nil {
			log.Warn().Err(err).Msg("failed to send choke signal")
		}
	} else if bufferUsage < 0.3 && s.sendingChoke {
		if err := s.sendUnchokeSignalLocked(); err != nil {
			log.Warn().Err(err).Msg("failed to send unchoke signal")
		}
	}
}

// handleOutOfOrderPacketLocked handles a packet that arrived out of order.
// Must be called with s.mu held.
func (s *StreamConn) handleOutOfOrderPacketLocked(pkt *Packet, seq uint32) error {
	log.Debug().
		Uint32("expected", s.recvSeq).
		Uint32("got", seq).
		Msg("out-of-order packet - buffering")

	s.outOfOrderPackets[seq] = pkt
	s.removeFromNACKListLocked(seq)
	s.updateNACKListLocked(seq)

	if err := s.sendAckLocked(); err != nil {
		log.Warn().Err(err).Msg("failed to send ACK with NACKs")
	}

	return nil
}

// handleDataLocked processes an incoming data packet.
// Handles in-sequence, duplicate, and out-of-order packets.
// Must be called with s.mu held.
func (s *StreamConn) handleDataLocked(pkt *Packet) error {
	if s.outOfOrderPackets == nil {
		s.outOfOrderPackets = make(map[uint32]*Packet)
	}

	seq := pkt.SequenceNum

	// Case 1: Exact sequence we need - process immediately
	if seq == s.recvSeq {
		return s.processInSequencePacketLocked(pkt, seq)
	}

	// Case 2: Duplicate or old packet - ignore
	if seqLessThan(seq, s.recvSeq) {
		log.Debug().
			Uint32("expected", s.recvSeq).
			Uint32("got", seq).
			Msg("duplicate or old packet - ignoring")
		return nil
	}

	// Case 3: Future packet - buffer it and track the gap
	return s.handleOutOfOrderPacketLocked(pkt, seq)
}

// deliverBufferedPacketsLocked attempts to deliver contiguous buffered packets.
// Must be called with s.mu held.
func (s *StreamConn) deliverBufferedPacketsLocked() {
	for {
		// Check if we have the next expected packet buffered
		pkt, exists := s.outOfOrderPackets[s.recvSeq]
		if !exists {
			// No more contiguous packets
			break
		}

		// Deliver this packet
		n, err := s.recvBuf.Write(pkt.Payload)
		if err != nil {
			log.Error().
				Err(err).
				Uint32("seq", s.recvSeq).
				Msg("receive buffer full while delivering buffered packet")
			// Can't deliver more packets now
			break
		}

		log.Debug().
			Int("bytes", n).
			Uint32("seq", s.recvSeq).
			Msg("delivered buffered packet")

		// Update state
		s.recvSeq++
		s.totalBytesReceived += uint64(n)

		// Remove from buffer
		delete(s.outOfOrderPackets, pkt.SequenceNum)

		// Remove this sequence from NACK list if present
		s.removeFromNACKListLocked(pkt.SequenceNum)
	}
}

// MaxNACKs is the maximum number of NACKs that can be stored and sent per packet.
// Per I2P streaming specification, NACK count is limited to 255.
const MaxNACKs = 255

// updateNACKListLocked updates the NACK list when receiving an out-of-order packet.
// Adds all missing sequences between recvSeq and the received sequence.
// The NACK list is bounded to MaxNACKs (255) entries to prevent unbounded memory growth
// and because only 255 NACKs can be sent per packet per I2P streaming spec.
// Prioritizes lower sequence numbers (earlier gaps) to avoid head-of-line blocking.
//
// The function limits iterations to min(gap, MaxNACKs) to prevent CPU spikes
// when receiving packets with large sequence gaps (including wrap-around cases).
// Must be called with s.mu held.
func (s *StreamConn) updateNACKListLocked(receivedSeq uint32) {
	gap := s.calculateSequenceGapLocked(receivedSeq)
	s.addMissingSequencesToNACKListLocked(gap)
}

// calculateSequenceGapLocked computes the sequence gap with wrap-around arithmetic.
// Returns the gap limited to MaxNACKs to prevent CPU spikes from malicious packets.
// Caller must hold s.mu.
func (s *StreamConn) calculateSequenceGapLocked(receivedSeq uint32) uint32 {
	// Wrap-around arithmetic gives correct distance even across wrap-around
	gap := receivedSeq - s.recvSeq

	maxIterations := uint32(MaxNACKs)
	if gap > maxIterations {
		log.Debug().
			Uint32("recvSeq", s.recvSeq).
			Uint32("receivedSeq", receivedSeq).
			Uint32("gap", gap).
			Uint32("maxIterations", maxIterations).
			Msg("large sequence gap detected, limiting NACK iteration")
		return maxIterations
	}

	return gap
}

// addMissingSequencesToNACKListLocked adds missing sequence numbers to the NACK list.
// Enforces MaxNACKs limit and skips already-buffered or already-NACKed sequences.
// Caller must hold s.mu.
func (s *StreamConn) addMissingSequencesToNACKListLocked(gap uint32) {
	for i := uint32(0); i < gap; i++ {
		seq := s.recvSeq + i

		if len(s.nackList) >= MaxNACKs {
			log.Debug().
				Int("nackCount", len(s.nackList)).
				Uint32("droppedSeq", seq).
				Msg("NACK list at capacity, dropping new entry")
			break
		}

		if s.shouldAddToNACKListLocked(seq) {
			s.nackList[seq] = struct{}{}
			log.Debug().
				Uint32("seq", seq).
				Int("nackCount", len(s.nackList)).
				Msg("added to NACK list")
		}
	}
}

// shouldAddToNACKListLocked checks if a sequence should be added to the NACK list.
// Returns false if the sequence is already buffered or already in the NACK list.
// Uses O(1) map lookup for efficiency.
// Caller must hold s.mu.
func (s *StreamConn) shouldAddToNACKListLocked(seq uint32) bool {
	if _, buffered := s.outOfOrderPackets[seq]; buffered {
		return false
	}

	// O(1) map lookup instead of O(n) slice scan
	_, exists := s.nackList[seq]
	return !exists
}

// removeFromNACKListLocked removes a sequence number from the NACK list.
// Uses O(1) map delete for efficiency.
// Must be called with s.mu held.
func (s *StreamConn) removeFromNACKListLocked(seq uint32) {
	if _, exists := s.nackList[seq]; exists {
		delete(s.nackList, seq)
		log.Debug().
			Uint32("seq", seq).
			Int("remaining", len(s.nackList)).
			Msg("removed from NACK list")
	}
}

// getNACKListSliceLocked converts the NACK map to a slice for packet building.
// Returns up to maxNacks sequence numbers. The order is not guaranteed due to
// map iteration, but this is acceptable per I2P streaming spec as NACKs just
// indicate missing sequences without ordering requirements.
// Must be called with s.mu held.
func (s *StreamConn) getNACKListSliceLocked(maxNacks int) []uint32 {
	if len(s.nackList) == 0 {
		return nil
	}

	count := len(s.nackList)
	if count > maxNacks {
		count = maxNacks
	}

	result := make([]uint32, 0, count)
	for seq := range s.nackList {
		result = append(result, seq)
		if len(result) >= count {
			break
		}
	}
	return result
}

// cleanupAckedPacketsLocked removes ACKed packets from the sent packet tracking.
// This prevents unbounded memory growth by cleaning up packets that have been acknowledged.
// Also signals sendCond to wake blocked writers waiting for window space.
// Must be called with s.mu held.
func (s *StreamConn) cleanupAckedPacketsLocked(oldAck, newAck uint32) {
	if s.sentPackets == nil {
		return
	}
	cleaned := 0
	for seq := range s.sentPackets {
		// Use wrap-around safe comparison for sequence numbers
		if seqLessThanOrEqual(seq, newAck) {
			delete(s.sentPackets, seq)
			cleaned++
		}
	}
	if cleaned > 0 {
		log.Debug().
			Uint32("oldAck", oldAck).
			Uint32("newAck", newAck).
			Int("cleaned", cleaned).
			Int("remaining", len(s.sentPackets)).
			Msg("cleaned up ACKed packets")

		// Wake any blocked writers now that window space is available
		if s.sendCond != nil {
			s.sendCond.Broadcast()
		}
	}
}

// retransmitPacketLocked retransmits a packet in response to a NACK.
// It looks up the packet data from sentPackets and resends it via the I2CP session.
// Must be called with s.mu held.
func (s *StreamConn) retransmitPacketLocked(seq uint32) error {
	info, exists := s.sentPackets[seq]
	if !exists {
		// Packet was already ACKed and cleaned up, nothing to retransmit
		log.Debug().Uint32("seq", seq).Msg("packet already ACKed, skipping retransmit")
		return nil
	}

	// Resend the marshaled packet data via I2CP
	if s.session != nil {
		stream := go_i2cp.NewStream(info.data)
		if err := s.session.SendMessage(s.dest, 6, s.localPort, s.remotePort, stream, 0); err != nil {
			return fmt.Errorf("retransmit seq %d: %w", seq, err)
		}
	}

	// Update retry tracking
	info.retryCount++
	info.sentTime = time.Now()

	log.Debug().
		Uint32("seq", seq).
		Int("retryCount", info.retryCount).
		Msg("retransmitted packet")

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

// sendAckLocked sends an ACK packet with optional NACKs for selective retransmission.
// Per I2P streaming spec: sequenceNum=0 without SYN flag = plain ACK packet.
// There is no explicit ACK flag; ackThrough is always valid.
// Must be called with s.mu held.
func (s *StreamConn) sendAckLocked() error {
	pkt := &Packet{
		SendStreamID:  s.localStreamID,  // Our stream ID
		RecvStreamID:  s.remoteStreamID, // Peer's stream ID
		SequenceNum:   0,                // seq=0 without SYN = plain ACK per spec
		AckThrough:    s.recvSeq - 1,
		Flags:         0, // No flags needed for plain ACK
		OptionalDelay: 0, // Request immediate ACK (MVP: no delay optimization)
	}

	// Include NACKs if we have any gaps in received sequences
	// Limit to MaxNACKs per packet as per I2P streaming spec
	if len(s.nackList) > 0 {
		pkt.NACKs = s.getNACKListSliceLocked(MaxNACKs)

		log.Debug().
			Int("nackCount", len(pkt.NACKs)).
			Msg("including NACKs in ACK packet")
	}

	return s.sendPacketLocked(pkt)
}

// sendChokeSignalLocked sends a choke signal to the remote peer indicating our receive buffer is full.
// Per I2P streaming spec, OptionalDelay > 60000 indicates a choked state.
// This tells the sender to pause transmission until we send an unchoke signal.
// Must be called with s.mu held.
func (s *StreamConn) sendChokeSignalLocked() error {
	pkt := &Packet{
		SendStreamID:  s.localStreamID,
		RecvStreamID:  s.remoteStreamID,
		SequenceNum:   0, // seq=0 without SYN = plain ACK per spec
		AckThrough:    s.recvSeq - 1,
		Flags:         FlagDelayRequested, // Only delay flag needed for choke
		OptionalDelay: 61000,              // >60000 = choked per I2P streaming spec
	}

	// Include NACKs if we have any gaps (even when choked, request missing packets)
	if len(s.nackList) > 0 {
		pkt.NACKs = s.getNACKListSliceLocked(MaxNACKs)
	}

	s.sendingChoke = true

	log.Debug().
		Float64("bufferUsage", float64(s.recvBuf.TotalWritten())/float64(s.recvBuf.Size())).
		Msg("sending choke signal to peer")

	return s.sendPacketLocked(pkt)
}

// sendUnchokeSignalLocked sends an unchoke signal to the remote peer indicating our receive buffer has space.
// This tells the sender they can resume transmission.
// Must be called with s.mu held.
func (s *StreamConn) sendUnchokeSignalLocked() error {
	pkt := &Packet{
		SendStreamID:  s.localStreamID,
		RecvStreamID:  s.remoteStreamID,
		SequenceNum:   0, // seq=0 without SYN = plain ACK per spec
		AckThrough:    s.recvSeq - 1,
		Flags:         FlagDelayRequested, // Only delay flag needed for unchoke
		OptionalDelay: 0,                  // 0-60000 = not choked
	}

	// Include NACKs if we have any gaps
	if len(s.nackList) > 0 {
		pkt.NACKs = s.getNACKListSliceLocked(MaxNACKs)
	}

	s.sendingChoke = false

	log.Debug().
		Float64("bufferUsage", float64(s.recvBuf.TotalWritten())/float64(s.recvBuf.Size())).
		Msg("sending unchoke signal to peer")

	return s.sendPacketLocked(pkt)
}

// sendPacketLocked marshals and sends a packet via I2CP.
// Must be called with s.mu held.
func (s *StreamConn) sendPacketLocked(pkt *Packet) error {
	data, err := pkt.Marshal()
	if err != nil {
		return fmt.Errorf("marshal packet: %w", err)
	}

	s.trackPacketForRetransmission(pkt, data)

	if err := s.sendViaI2CP(data); err != nil {
		return err
	}

	s.lastActivity = time.Now()
	s.logSentPacket(pkt)
	return nil
}

// trackPacketForRetransmission stores data packets for potential retransmission on NACK.
// Only tracks packets with payload (data packets), not control packets.
func (s *StreamConn) trackPacketForRetransmission(pkt *Packet, data []byte) {
	if len(pkt.Payload) == 0 {
		return
	}
	if s.sentPackets == nil {
		s.sentPackets = make(map[uint32]*sentPacket)
	}
	s.sentPackets[pkt.SequenceNum] = &sentPacket{
		data:       data,
		sentTime:   time.Now(),
		retryCount: 0,
	}
	log.Debug().
		Uint32("seq", pkt.SequenceNum).
		Int("tracked", len(s.sentPackets)).
		Msg("tracking sent packet for retransmission")
}

// sendViaI2CP sends marshaled packet data via the I2CP session.
func (s *StreamConn) sendViaI2CP(data []byte) error {
	if s.session == nil {
		return fmt.Errorf("cannot send packet: no I2CP session")
	}
	stream := go_i2cp.NewStream(data)
	if err := s.session.SendMessage(s.dest, 6, s.localPort, s.remotePort, stream, 0); err != nil {
		return fmt.Errorf("send message: %w", err)
	}
	return nil
}

// logSentPacket logs debug information about a sent packet.
func (s *StreamConn) logSentPacket(pkt *Packet) {
	log.Debug().
		Uint32("seq", pkt.SequenceNum).
		Uint32("ack", pkt.AckThrough).
		Uint16("flags", pkt.Flags).
		Int("payload", len(pkt.Payload)).
		Msg("sent packet")
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

	s.sendCloseIfEstablished()
	s.cleanupConnectionLocked()

	return nil
}

// sendCloseIfEstablished sends a CLOSE packet if the connection is established.
// Must be called with s.mu held.
func (s *StreamConn) sendCloseIfEstablished() {
	if s.state != StateEstablished {
		return
	}

	if err := s.sendCloseLocked(); err != nil {
		log.Warn().Err(err).Msg("failed to send CLOSE packet")
	}
	s.setState(StateClosing)
}

// cleanupConnectionLocked performs connection cleanup: unregisters from manager,
// cancels the receive loop, marks as closed, and wakes blocked goroutines.
// Must be called with s.mu held.
func (s *StreamConn) cleanupConnectionLocked() {
	if s.manager != nil {
		s.manager.UnregisterConnection(s.localPort, s.remotePort)
	}

	s.cancel()
	s.closed = true

	s.wakeBlockedGoroutines()
}

// wakeBlockedGoroutines broadcasts to wake up any blocked readers and writers.
// Must be called with s.mu held.
func (s *StreamConn) wakeBlockedGoroutines() {
	if s.recvCond != nil {
		s.recvCond.Broadcast()
	}
	if s.sendCond != nil {
		s.sendCond.Broadcast()
	}
}

// sendCloseLocked sends a CLOSE packet to initiate connection teardown.
// Must be called with s.mu held.
func (s *StreamConn) sendCloseLocked() error {
	pkt := &Packet{
		SendStreamID: s.localStreamID,  // Our stream ID
		RecvStreamID: s.remoteStreamID, // Peer's stream ID
		SequenceNum:  s.sendSeq,
		AckThrough:   s.recvSeq - 1,
		Flags:        FlagCLOSE,
	}

	// Add signature and FROM destination if session is available
	if s.session != nil {
		pkt.Flags |= FlagSignatureIncluded | FlagFromIncluded
		pkt.FromDestination = s.session.Destination()

		// Sign the CLOSE packet
		keyPair, err := s.session.SigningKeyPair()
		if err != nil {
			log.Warn().Err(err).Msg("failed to get signing key pair for CLOSE packet")
			// Continue anyway - signing is best effort for CLOSE
		} else if err := SignPacket(pkt, keyPair); err != nil {
			log.Warn().Err(err).Msg("failed to sign CLOSE packet")
			// Continue anyway - signing is best effort for CLOSE
		}
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

	// Wake up any blocked writers to check deadline
	if s.sendCond != nil {
		s.sendCond.Broadcast()
	}

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
