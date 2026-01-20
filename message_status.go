package streaming

import (
	"sync"
	"sync/atomic"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

// messageStatusTracker tracks outgoing messages and their delivery status.
// It correlates I2CP message nonces to streaming packet sequence numbers,
// enabling reliable delivery tracking and retransmission on failure.
type messageStatusTracker struct {
	mu sync.RWMutex

	// pendingMessages maps nonce -> pending message info
	pendingMessages map[uint32]*pendingMessageInfo

	// stats tracks delivery statistics
	stats MessageStats

	// nextNonce generates unique message identifiers
	nextNonce uint32

	// manager reference for routing status updates
	manager *StreamManager
}

// pendingMessageInfo tracks a single outgoing message awaiting status.
type pendingMessageInfo struct {
	nonce       uint32      // I2CP message nonce
	seqNum      uint32      // Streaming packet sequence number
	conn        *StreamConn // Connection that sent the packet
	sentAt      time.Time   // When the message was sent
	payloadSize int         // Payload size for stats
	isDataPkt   bool        // True if this is a data packet (vs control)
	retryCount  int         // Number of retries so far
	maxRetries  int         // Maximum retries before giving up
}

// MessageStats tracks message delivery statistics.
type MessageStats struct {
	TotalSent         uint64 // Total messages sent
	TotalDelivered    uint64 // Messages with success status
	TotalFailed       uint64 // Messages with failure status
	TotalRetried      uint64 // Messages retried after failure
	TotalExpired      uint64 // Messages expired without status
	AvgDeliveryTimeMs int64  // Average delivery time in milliseconds
	LastDeliveryMs    int64  // Last delivery time in milliseconds
}

// newMessageStatusTracker creates a new message status tracker.
func newMessageStatusTracker(manager *StreamManager) *messageStatusTracker {
	return &messageStatusTracker{
		pendingMessages: make(map[uint32]*pendingMessageInfo),
		manager:         manager,
		nextNonce:       1, // Start at 1, 0 is often used as "no nonce"
	}
}

// GenerateNonce returns a unique nonce for tracking a message.
func (t *messageStatusTracker) GenerateNonce() uint32 {
	return atomic.AddUint32(&t.nextNonce, 1)
}

// TrackMessage registers a message for status tracking.
// Returns the nonce to use when sending via I2CP.
func (t *messageStatusTracker) TrackMessage(conn *StreamConn, seqNum uint32, payloadSize int, isDataPkt bool) uint32 {
	nonce := t.GenerateNonce()

	info := &pendingMessageInfo{
		nonce:       nonce,
		seqNum:      seqNum,
		conn:        conn,
		sentAt:      time.Now(),
		payloadSize: payloadSize,
		isDataPkt:   isDataPkt,
		retryCount:  0,
		maxRetries:  3, // Default max retries
	}

	t.mu.Lock()
	t.pendingMessages[nonce] = info
	atomic.AddUint64(&t.stats.TotalSent, 1)
	t.mu.Unlock()

	log.Trace().
		Uint32("nonce", nonce).
		Uint32("seq", seqNum).
		Int("payloadSize", payloadSize).
		Bool("isDataPkt", isDataPkt).
		Msg("tracking outgoing message")

	return nonce
}

// HandleStatus processes a message status update from I2CP.
// This is called from StreamManager.handleMessageStatus.
func (t *messageStatusTracker) HandleStatus(messageId uint32, status go_i2cp.SessionMessageStatus, size, nonce uint32) {
	t.mu.Lock()
	info, exists := t.pendingMessages[messageId]
	if !exists {
		t.mu.Unlock()
		// Message not tracked - might be using nonce=0 (legacy) or already processed
		log.Trace().
			Uint32("messageId", messageId).
			Uint8("status", uint8(status)).
			Msg("received status for untracked message")
		return
	}
	delete(t.pendingMessages, messageId)
	t.mu.Unlock()

	deliveryTime := time.Since(info.sentAt)

	// Categorize the status using go-i2cp helpers
	if go_i2cp.IsMessageStatusSuccess(status) {
		t.handleSuccess(info, status, deliveryTime)
	} else if go_i2cp.IsMessageStatusFailure(status) {
		t.handleFailure(info, status, deliveryTime)
	} else {
		// Intermediate status (accepted, etc.)
		t.handleIntermediate(info, status)
	}
}

// handleSuccess processes a successful delivery status.
func (t *messageStatusTracker) handleSuccess(info *pendingMessageInfo, status go_i2cp.SessionMessageStatus, deliveryTime time.Duration) {
	atomic.AddUint64(&t.stats.TotalDelivered, 1)
	atomic.StoreInt64(&t.stats.LastDeliveryMs, deliveryTime.Milliseconds())

	// Update running average (simplified)
	avgMs := atomic.LoadInt64(&t.stats.AvgDeliveryTimeMs)
	newAvg := (avgMs*7 + deliveryTime.Milliseconds()) / 8 // Exponential moving average
	atomic.StoreInt64(&t.stats.AvgDeliveryTimeMs, newAvg)

	category := go_i2cp.GetMessageStatusCategory(status)

	log.Debug().
		Uint32("nonce", info.nonce).
		Uint32("seq", info.seqNum).
		Str("status", category).
		Dur("deliveryTime", deliveryTime).
		Msg("message delivered successfully")

	// Notify the connection if it's a data packet
	if info.isDataPkt && info.conn != nil {
		info.conn.handleMessageDelivered(info.seqNum)
	}
}

// handleFailure processes a failed delivery status.
func (t *messageStatusTracker) handleFailure(info *pendingMessageInfo, status go_i2cp.SessionMessageStatus, deliveryTime time.Duration) {
	atomic.AddUint64(&t.stats.TotalFailed, 1)

	category := go_i2cp.GetMessageStatusCategory(status)
	retriable := go_i2cp.IsMessageStatusRetriable(status)

	log.Warn().
		Uint32("nonce", info.nonce).
		Uint32("seq", info.seqNum).
		Uint8("status", uint8(status)).
		Str("category", category).
		Bool("retriable", retriable).
		Int("retryCount", info.retryCount).
		Dur("afterTime", deliveryTime).
		Msg("message delivery failed")

	// For retriable failures, trigger retransmission
	if retriable && info.retryCount < info.maxRetries && info.isDataPkt && info.conn != nil {
		atomic.AddUint64(&t.stats.TotalRetried, 1)
		info.conn.handleMessageFailed(info.seqNum, true)
	} else if info.isDataPkt && info.conn != nil {
		// Non-retriable or max retries exceeded
		info.conn.handleMessageFailed(info.seqNum, false)
	}
}

// handleIntermediate processes intermediate status (accepted, etc.).
func (t *messageStatusTracker) handleIntermediate(info *pendingMessageInfo, status go_i2cp.SessionMessageStatus) {
	category := go_i2cp.GetMessageStatusCategory(status)

	log.Trace().
		Uint32("nonce", info.nonce).
		Uint32("seq", info.seqNum).
		Str("status", category).
		Msg("message status update (intermediate)")

	// Re-add to pending for final status
	// Note: go-i2cp's PendingMessage tracking handles this internally
}

// GetStats returns a copy of the current message statistics.
func (t *messageStatusTracker) GetStats() MessageStats {
	return MessageStats{
		TotalSent:         atomic.LoadUint64(&t.stats.TotalSent),
		TotalDelivered:    atomic.LoadUint64(&t.stats.TotalDelivered),
		TotalFailed:       atomic.LoadUint64(&t.stats.TotalFailed),
		TotalRetried:      atomic.LoadUint64(&t.stats.TotalRetried),
		TotalExpired:      atomic.LoadUint64(&t.stats.TotalExpired),
		AvgDeliveryTimeMs: atomic.LoadInt64(&t.stats.AvgDeliveryTimeMs),
		LastDeliveryMs:    atomic.LoadInt64(&t.stats.LastDeliveryMs),
	}
}

// PendingCount returns the number of messages awaiting status.
func (t *messageStatusTracker) PendingCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.pendingMessages)
}

// CleanupExpired removes stale pending messages that never received status.
// Returns the number of expired messages removed.
func (t *messageStatusTracker) CleanupExpired(maxAge time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	expired := 0

	for nonce, info := range t.pendingMessages {
		if now.Sub(info.sentAt) > maxAge {
			delete(t.pendingMessages, nonce)
			expired++
			atomic.AddUint64(&t.stats.TotalExpired, 1)

			log.Warn().
				Uint32("nonce", nonce).
				Uint32("seq", info.seqNum).
				Dur("age", now.Sub(info.sentAt)).
				Msg("message expired without status")

			// Treat as failure for data packets
			if info.isDataPkt && info.conn != nil {
				info.conn.handleMessageFailed(info.seqNum, false)
			}
		}
	}

	return expired
}

// Clear removes all pending messages. Used during shutdown.
func (t *messageStatusTracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pendingMessages = make(map[uint32]*pendingMessageInfo)
}
