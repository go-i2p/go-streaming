package streaming

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

// MaxPingPayloadSize is the maximum payload size for ping/pong packets.
// Per I2P streaming spec: "The payload in the ping, up to a maximum of 32 bytes,
// is returned in the pong."
const MaxPingPayloadSize = 32

// PingResult represents the result of a ping operation.
type PingResult struct {
	// RTT is the round-trip time of the ping.
	RTT time.Duration
	// Payload is the echoed payload from the pong (up to 32 bytes).
	Payload []byte
	// Err is any error that occurred during the ping.
	Err error
}

// pendingPing tracks an outstanding ping request awaiting a pong response.
type pendingPing struct {
	streamID uint32             // The sendStreamId used in the ping
	payload  []byte             // Expected payload in pong
	sentAt   time.Time          // When the ping was sent
	resultCh chan<- *PingResult // Channel to send the result
}

// PingConfig holds configuration options for ping operations.
type PingConfig struct {
	// AnswerPings controls whether to respond to incoming ping packets.
	// Per spec: "Streaming may be configured to disable sending pongs with
	// the configuration i2p.streaming.answerPings=false."
	// Default: true
	AnswerPings bool

	// PingTimeout is the maximum time to wait for a pong response.
	// Default: 30 seconds
	PingTimeout time.Duration
}

// DefaultPingConfig returns the default ping configuration.
func DefaultPingConfig() *PingConfig {
	return &PingConfig{
		AnswerPings: true,
		PingTimeout: 30 * time.Second,
	}
}

// pingManager handles ping/pong operations for a StreamManager.
type pingManager struct {
	sm     *StreamManager
	config *PingConfig

	// Pending pings awaiting pong responses
	// Map of streamID -> *pendingPing
	pendingPings sync.Map

	mu sync.Mutex
}

// newPingManager creates a new ping manager with the given configuration.
func newPingManager(sm *StreamManager, config *PingConfig) *pingManager {
	if config == nil {
		config = DefaultPingConfig()
	}
	return &pingManager{
		sm:     sm,
		config: config,
	}
}

// Ping sends a ping packet to the specified destination and waits for a pong response.
// Per I2P streaming spec:
//   - A ping packet must have ECHO, SIGNATURE_INCLUDED, and FROM_INCLUDED flags set
//   - The sendStreamId must be greater than zero
//   - The receiveStreamId is ignored
//   - Payload up to 32 bytes is echoed back in the pong
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - dest: The destination to ping
//   - payload: Optional payload to include (max 32 bytes, will be truncated if longer)
//
// Returns:
//   - PingResult containing RTT, echoed payload, and any error
func (pm *pingManager) Ping(ctx context.Context, dest *go_i2cp.Destination, payload []byte) *PingResult {
	if err := pm.validatePingPrerequisites(dest); err != nil {
		return &PingResult{Err: err}
	}

	// Truncate payload to max size per spec
	if len(payload) > MaxPingPayloadSize {
		payload = payload[:MaxPingPayloadSize]
	}

	// Generate a random non-zero stream ID for this ping
	streamID, err := pm.generateStreamID()
	if err != nil {
		return &PingResult{Err: fmt.Errorf("generate stream ID: %w", err)}
	}

	// Create result channel
	resultCh := make(chan *PingResult, 1)

	// Register pending ping
	pending := &pendingPing{
		streamID: streamID,
		payload:  payload,
		sentAt:   time.Now(),
		resultCh: resultCh,
	}
	pm.pendingPings.Store(streamID, pending)
	defer pm.pendingPings.Delete(streamID)

	// Build and send ping packet
	if err := pm.sendPingPacket(dest, streamID, payload); err != nil {
		return &PingResult{Err: fmt.Errorf("send ping: %w", err)}
	}

	// Wait for pong or timeout
	timeout := pm.config.PingTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}

	select {
	case result := <-resultCh:
		return result
	case <-time.After(timeout):
		return &PingResult{Err: fmt.Errorf("ping timeout after %v", timeout)}
	case <-ctx.Done():
		return &PingResult{Err: ctx.Err()}
	}
}

// validatePingPrerequisites checks that the ping can be sent.
func (pm *pingManager) validatePingPrerequisites(dest *go_i2cp.Destination) error {
	if dest == nil {
		return fmt.Errorf("destination is nil")
	}
	if pm.sm.session == nil {
		return fmt.Errorf("no I2CP session")
	}
	return nil
}

// generateStreamID generates a random non-zero stream ID.
func (pm *pingManager) generateStreamID() (uint32, error) {
	var buf [4]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, err
		}
		streamID := binary.BigEndian.Uint32(buf[:])
		if streamID != 0 {
			return streamID, nil
		}
	}
}

// sendPingPacket builds and sends a ping packet.
func (pm *pingManager) sendPingPacket(dest *go_i2cp.Destination, streamID uint32, payload []byte) error {
	pkt := &Packet{
		SendStreamID:    streamID, // Must be > 0 for ping
		RecvStreamID:    0,        // Ignored for ping
		SequenceNum:     0,        // Not relevant for ping
		AckThrough:      0,        // Not relevant for ping
		Flags:           FlagECHO | FlagSignatureIncluded | FlagFromIncluded,
		FromDestination: pm.sm.session.Destination(),
		Payload:         payload,
	}

	// Sign the packet
	if err := pm.signPingPacket(pkt); err != nil {
		return err
	}

	// Send the packet
	return pm.sm.sendPacketToDest(pkt, dest, 0, 0)
}

// signPingPacket signs a ping packet.
func (pm *pingManager) signPingPacket(pkt *Packet) error {
	keyPair, err := pm.sm.session.SigningKeyPair()
	if err != nil {
		return fmt.Errorf("get signing key pair: %w", err)
	}
	return SignPacket(pkt, keyPair)
}

// handlePong processes an incoming pong packet and resolves the pending ping.
func (pm *pingManager) handlePong(pkt *Packet) {
	// Per spec: pong has sendStreamId=0 and receiveStreamId=ping's sendStreamId
	if pkt.SendStreamID != 0 {
		log.Debug().
			Uint32("sendStreamID", pkt.SendStreamID).
			Msg("ignoring ECHO packet with non-zero sendStreamID (not a valid pong)")
		return
	}

	streamID := pkt.RecvStreamID
	pendingIface, ok := pm.pendingPings.Load(streamID)
	if !ok {
		log.Debug().
			Uint32("streamID", streamID).
			Msg("received pong for unknown ping")
		return
	}

	pending := pendingIface.(*pendingPing)
	rtt := time.Since(pending.sentAt)

	result := &PingResult{
		RTT:     rtt,
		Payload: pkt.Payload,
	}

	// Send result (non-blocking in case receiver is gone)
	select {
	case pending.resultCh <- result:
		log.Debug().
			Uint32("streamID", streamID).
			Dur("rtt", rtt).
			Msg("pong received")
	default:
		log.Debug().
			Uint32("streamID", streamID).
			Msg("pong result channel full, discarding")
	}
}

// handlePing processes an incoming ping packet and sends a pong response.
// Per I2P streaming spec:
//   - A pong packet must have the ECHO flag set
//   - sendStreamId must be zero
//   - receiveStreamId is the sendStreamId from the ping
//   - Payload from ping (up to 32 bytes) is echoed back
func (pm *pingManager) handlePing(pkt *Packet, srcDest *go_i2cp.Destination, srcPort, destPort uint16) {
	if !pm.config.AnswerPings {
		log.Debug().Msg("ignoring ping (answerPings disabled)")
		return
	}

	// Validate ping packet per spec
	if pkt.SendStreamID == 0 {
		log.Debug().Msg("ignoring ECHO packet with zero sendStreamID (invalid ping)")
		return
	}

	// Build pong response
	// Per spec: sendStreamId=0, receiveStreamId=ping's sendStreamId
	payload := pkt.Payload
	if len(payload) > MaxPingPayloadSize {
		payload = payload[:MaxPingPayloadSize]
	}

	pongPkt := &Packet{
		SendStreamID: 0,                // Must be 0 for pong
		RecvStreamID: pkt.SendStreamID, // Echo back the ping's sendStreamId
		SequenceNum:  0,                // Not relevant for pong
		AckThrough:   0,                // Not relevant for pong
		Flags:        FlagECHO,         // Only ECHO flag for pong (no signature required)
		Payload:      payload,          // Echo payload back
	}

	if err := pm.sm.sendPacketToDest(pongPkt, srcDest, destPort, srcPort); err != nil {
		log.Warn().Err(err).
			Uint32("pingStreamID", pkt.SendStreamID).
			Msg("failed to send pong")
		return
	}

	log.Debug().
		Uint32("pingStreamID", pkt.SendStreamID).
		Int("payloadLen", len(payload)).
		Msg("sent pong")
}

// isPingPacket checks if a packet is a ping (ECHO with sendStreamId > 0).
func isPingPacket(pkt *Packet) bool {
	return pkt.Flags&FlagECHO != 0 && pkt.SendStreamID > 0
}

// isPongPacket checks if a packet is a pong (ECHO with sendStreamId == 0).
func isPongPacket(pkt *Packet) bool {
	return pkt.Flags&FlagECHO != 0 && pkt.SendStreamID == 0
}
