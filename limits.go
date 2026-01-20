package streaming

import (
	"fmt"
	"sync"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

// LimitAction specifies what action to take when connection limits are exceeded.
type LimitAction int

const (
	// LimitActionReset sends a RESET packet to the peer (default)
	LimitActionReset LimitAction = iota
	// LimitActionDrop silently drops the connection without response
	LimitActionDrop
	// LimitActionHTTP sends an HTTP 429 response before closing
	LimitActionHTTP
)

// ConnectionLimitsConfig configures connection rate limiting.
// All limit values of 0 mean disabled (unlimited).
// This implements the i2p.streaming.* connection limiting options from the spec.
type ConnectionLimitsConfig struct {
	// MaxConcurrentStreams is the total limit for incoming and outgoing streams combined.
	// 0 or negative means unlimited.
	MaxConcurrentStreams int

	// Per-peer incoming connection limits
	MaxConnsPerMinute int // Max incoming connections per minute from a single peer
	MaxConnsPerHour   int // Max incoming connections per hour from a single peer
	MaxConnsPerDay    int // Max incoming connections per day from a single peer

	// Total incoming connection limits (all peers combined)
	MaxTotalConnsPerMinute int
	MaxTotalConnsPerHour   int
	MaxTotalConnsPerDay    int

	// LimitAction specifies what to do when limits are exceeded
	LimitAction LimitAction

	// DisableRejectLogging disables log warnings when connections are rejected
	DisableRejectLogging bool
}

// DefaultConnectionLimitsConfig returns the default (unlimited) configuration.
// Per I2P spec, all limits are disabled by default.
func DefaultConnectionLimitsConfig() *ConnectionLimitsConfig {
	return &ConnectionLimitsConfig{
		MaxConcurrentStreams:   -1, // Unlimited
		MaxConnsPerMinute:      0,  // Disabled
		MaxConnsPerHour:        0,  // Disabled
		MaxConnsPerDay:         0,  // Disabled
		MaxTotalConnsPerMinute: 0,  // Disabled
		MaxTotalConnsPerHour:   0,  // Disabled
		MaxTotalConnsPerDay:    0,  // Disabled
		LimitAction:            LimitActionReset,
		DisableRejectLogging:   false,
	}
}

// connectionLimiter tracks and enforces connection limits.
// It maintains per-peer and total connection counters with time-based windows.
type connectionLimiter struct {
	config *ConnectionLimitsConfig
	mu     sync.Mutex

	// Current concurrent stream count (checked against MaxConcurrentStreams)
	activeStreams int

	// Per-peer connection history: peerHash -> connection timestamps
	peerHistory map[string]*connectionHistory

	// Total connection timestamps across all peers
	totalHistory *connectionHistory
}

// connectionHistory tracks connection timestamps for rate limiting.
type connectionHistory struct {
	mu         sync.Mutex
	timestamps []time.Time
}

// newConnectionLimiter creates a new connection limiter with the given config.
func newConnectionLimiter(config *ConnectionLimitsConfig) *connectionLimiter {
	if config == nil {
		config = DefaultConnectionLimitsConfig()
	}
	return &connectionLimiter{
		config:       config,
		peerHistory:  make(map[string]*connectionHistory),
		totalHistory: &connectionHistory{},
	}
}

// SetConfig updates the limiter configuration.
func (cl *connectionLimiter) SetConfig(config *ConnectionLimitsConfig) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if config == nil {
		config = DefaultConnectionLimitsConfig()
	}
	cl.config = config
}

// GetConfig returns a copy of the current configuration.
func (cl *connectionLimiter) GetConfig() *ConnectionLimitsConfig {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return &ConnectionLimitsConfig{
		MaxConcurrentStreams:   cl.config.MaxConcurrentStreams,
		MaxConnsPerMinute:      cl.config.MaxConnsPerMinute,
		MaxConnsPerHour:        cl.config.MaxConnsPerHour,
		MaxConnsPerDay:         cl.config.MaxConnsPerDay,
		MaxTotalConnsPerMinute: cl.config.MaxTotalConnsPerMinute,
		MaxTotalConnsPerHour:   cl.config.MaxTotalConnsPerHour,
		MaxTotalConnsPerDay:    cl.config.MaxTotalConnsPerDay,
		LimitAction:            cl.config.LimitAction,
		DisableRejectLogging:   cl.config.DisableRejectLogging,
	}
}

// ActiveStreams returns the current number of active streams.
func (cl *connectionLimiter) ActiveStreams() int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.activeStreams
}

// CheckAndRecordConnection checks if a new connection from the peer is allowed.
// If allowed, it records the connection and returns nil.
// If not allowed, it returns an error describing which limit was exceeded.
func (cl *connectionLimiter) CheckAndRecordConnection(peerDest *go_i2cp.Destination) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	log.WithField("activeStreams", cl.activeStreams).Debug("checking connection limits")

	now := time.Now()

	// Check concurrent streams limit
	if err := cl.checkConcurrentLimitLocked(); err != nil {
		log.WithError(err).Debug("concurrent streams limit exceeded")
		return err
	}

	// Check total rate limits
	if err := cl.checkTotalRateLimitsLocked(now); err != nil {
		log.WithError(err).Debug("total rate limit exceeded")
		return err
	}

	// Check per-peer rate limits
	if err := cl.checkPeerRateLimitsLocked(peerDest, now); err != nil {
		log.WithError(err).Debug("per-peer rate limit exceeded")
		return err
	}

	// All checks passed - record the connection
	cl.recordConnectionLocked(peerDest, now)
	log.WithField("activeStreams", cl.activeStreams).Debug("connection recorded")
	return nil
}

// checkConcurrentLimitLocked checks if adding a new stream would exceed the concurrent limit.
// Must be called with cl.mu held.
func (cl *connectionLimiter) checkConcurrentLimitLocked() error {
	if cl.config.MaxConcurrentStreams > 0 && cl.activeStreams >= cl.config.MaxConcurrentStreams {
		log.WithFields(map[string]interface{}{
			"active": cl.activeStreams,
			"max":    cl.config.MaxConcurrentStreams,
		}).Debug("concurrent streams limit check failed")
		return fmt.Errorf("max concurrent streams limit exceeded (%d)", cl.config.MaxConcurrentStreams)
	}
	return nil
}

// checkTotalRateLimitsLocked checks if total rate limits would be exceeded.
// Must be called with cl.mu held.
func (cl *connectionLimiter) checkTotalRateLimitsLocked(now time.Time) error {
	cl.totalHistory.pruneOldEntriesLocked(now)

	if cl.config.MaxTotalConnsPerMinute > 0 {
		count := cl.totalHistory.countSinceLocked(now.Add(-time.Minute))
		if count >= cl.config.MaxTotalConnsPerMinute {
			return fmt.Errorf("total connections per minute limit exceeded (%d)", cl.config.MaxTotalConnsPerMinute)
		}
	}

	if cl.config.MaxTotalConnsPerHour > 0 {
		count := cl.totalHistory.countSinceLocked(now.Add(-time.Hour))
		if count >= cl.config.MaxTotalConnsPerHour {
			return fmt.Errorf("total connections per hour limit exceeded (%d)", cl.config.MaxTotalConnsPerHour)
		}
	}

	if cl.config.MaxTotalConnsPerDay > 0 {
		count := cl.totalHistory.countSinceLocked(now.Add(-24 * time.Hour))
		if count >= cl.config.MaxTotalConnsPerDay {
			return fmt.Errorf("total connections per day limit exceeded (%d)", cl.config.MaxTotalConnsPerDay)
		}
	}

	return nil
}

// checkPeerRateLimitsLocked checks if per-peer rate limits would be exceeded.
// Must be called with cl.mu held.
func (cl *connectionLimiter) checkPeerRateLimitsLocked(peerDest *go_i2cp.Destination, now time.Time) error {
	if peerDest == nil {
		return nil // Can't check per-peer limits without a destination
	}

	// Skip per-peer checks if all limits are disabled
	if cl.config.MaxConnsPerMinute <= 0 && cl.config.MaxConnsPerHour <= 0 && cl.config.MaxConnsPerDay <= 0 {
		return nil
	}

	peerHash := getPeerHash(peerDest)
	history := cl.getOrCreatePeerHistoryLocked(peerHash)

	history.mu.Lock()
	defer history.mu.Unlock()

	history.pruneOldEntriesLocked(now)

	if cl.config.MaxConnsPerMinute > 0 {
		count := history.countSinceLocked(now.Add(-time.Minute))
		if count >= cl.config.MaxConnsPerMinute {
			return fmt.Errorf("connections per minute from peer exceeded (%d)", cl.config.MaxConnsPerMinute)
		}
	}

	if cl.config.MaxConnsPerHour > 0 {
		count := history.countSinceLocked(now.Add(-time.Hour))
		if count >= cl.config.MaxConnsPerHour {
			return fmt.Errorf("connections per hour from peer exceeded (%d)", cl.config.MaxConnsPerHour)
		}
	}

	if cl.config.MaxConnsPerDay > 0 {
		count := history.countSinceLocked(now.Add(-24 * time.Hour))
		if count >= cl.config.MaxConnsPerDay {
			return fmt.Errorf("connections per day from peer exceeded (%d)", cl.config.MaxConnsPerDay)
		}
	}

	return nil
}

// recordConnectionLocked records a new connection in both total and per-peer history.
// Must be called with cl.mu held.
func (cl *connectionLimiter) recordConnectionLocked(peerDest *go_i2cp.Destination, now time.Time) {
	// Increment active streams
	cl.activeStreams++

	// Record in total history
	cl.totalHistory.mu.Lock()
	cl.totalHistory.timestamps = append(cl.totalHistory.timestamps, now)
	cl.totalHistory.mu.Unlock()

	// Record in per-peer history if we have a destination
	if peerDest != nil {
		peerHash := getPeerHash(peerDest)
		history := cl.getOrCreatePeerHistoryLocked(peerHash)
		history.mu.Lock()
		history.timestamps = append(history.timestamps, now)
		history.mu.Unlock()
	}
}

// ConnectionClosed should be called when a stream closes to decrement the active count.
func (cl *connectionLimiter) ConnectionClosed() {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.activeStreams > 0 {
		cl.activeStreams--
		log.WithField("activeStreams", cl.activeStreams).Debug("connection closed, decremented active streams")
	}
}

// getOrCreatePeerHistoryLocked gets or creates a connection history for the peer.
// Must be called with cl.mu held.
func (cl *connectionLimiter) getOrCreatePeerHistoryLocked(peerHash string) *connectionHistory {
	if history, exists := cl.peerHistory[peerHash]; exists {
		return history
	}
	history := &connectionHistory{}
	cl.peerHistory[peerHash] = history
	return history
}

// getPeerHash returns a string identifier for a destination.
// Uses the destination's serialized form as the unique identifier.
func getPeerHash(dest *go_i2cp.Destination) string {
	if dest == nil {
		return ""
	}
	// Serialize the destination to bytes
	stream := go_i2cp.NewStream(make([]byte, 0, 512))
	if err := dest.WriteToStream(stream); err != nil {
		return ""
	}
	return string(stream.Bytes())
}

// pruneOldEntriesLocked removes entries older than 24 hours to prevent memory growth.
// Must be called with h.mu held.
func (h *connectionHistory) pruneOldEntriesLocked(now time.Time) {
	cutoff := now.Add(-24 * time.Hour)
	newTimestamps := make([]time.Time, 0, len(h.timestamps))
	for _, ts := range h.timestamps {
		if ts.After(cutoff) {
			newTimestamps = append(newTimestamps, ts)
		}
	}
	h.timestamps = newTimestamps
}

// countSinceLocked counts timestamps after the given time.
// Must be called with h.mu held.
func (h *connectionHistory) countSinceLocked(since time.Time) int {
	count := 0
	for _, ts := range h.timestamps {
		if ts.After(since) {
			count++
		}
	}
	return count
}

// logLimitExceeded logs a warning about a rejected connection.
func logLimitExceeded(config *ConnectionLimitsConfig, peerDest *go_i2cp.Destination, reason string) {
	if config.DisableRejectLogging {
		return
	}

	peerID := "unknown"
	if peerDest != nil {
		// Serialize destination and use first 8 bytes as identifier
		stream := go_i2cp.NewStream(make([]byte, 0, 512))
		if err := peerDest.WriteToStream(stream); err == nil && stream.Len() >= 8 {
			peerID = fmt.Sprintf("%x...", stream.Bytes()[:8])
		}
	}

	log.WithFields(map[string]interface{}{
		"peer":   peerID,
		"reason": reason,
	}).Warn("incoming connection rejected due to rate limit")
}

// CleanupStaleHistory removes old peer history entries that haven't had activity in 24+ hours.
// This should be called periodically (e.g., every hour) to prevent memory leaks.
func (cl *connectionLimiter) CleanupStaleHistory() {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	log.WithField("peerCount", len(cl.peerHistory)).Debug("cleaning up stale connection history")

	now := time.Now()
	cutoff := now.Add(-24 * time.Hour)
	removedCount := 0

	for peerHash, history := range cl.peerHistory {
		history.mu.Lock()
		history.pruneOldEntriesLocked(now)
		// Remove empty histories
		if len(history.timestamps) == 0 {
			history.mu.Unlock()
			delete(cl.peerHistory, peerHash)
			removedCount++
			continue
		}

		// Check if all entries are older than cutoff (shouldn't happen after prune, but check anyway)
		hasRecent := false
		for _, ts := range history.timestamps {
			if ts.After(cutoff) {
				hasRecent = true
				break
			}
		}
		history.mu.Unlock()

		if !hasRecent {
			delete(cl.peerHistory, peerHash)
			removedCount++
		}
	}

	log.WithFields(map[string]interface{}{
		"removed":   removedCount,
		"remaining": len(cl.peerHistory),
	}).Debug("stale history cleanup complete")
}
