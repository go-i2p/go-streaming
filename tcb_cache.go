// Package streaming provides TCP-like reliable streams over I2P.
package streaming

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

// TCB Cache (Transport Control Block) implements RFC 2140 control block sharing.
// This shares RTT, RTT variance, and window size estimates between connections
// to the same remote peer, reducing slow-start latency for subsequent connections.

// TCBCacheConfig holds configuration for TCB cache behavior.
// Dampening factors control how much cached values influence new connections.
// Per I2P spec defaults: all dampening factors = 0.75
type TCBCacheConfig struct {
	// RTTDampening controls how much to dampen RTT when sharing (0.0-1.0)
	// Cached RTT is multiplied by this factor when applied to new connections.
	// Default: 0.75 per I2P streaming spec
	RTTDampening float64

	// RTTDevDampening controls how much to dampen RTT variance (0.0-1.0)
	// Default: 0.75 per I2P streaming spec
	RTTDevDampening float64

	// WindowDampening controls how much to dampen window size (0.0-1.0)
	// Default: 0.75 per I2P streaming spec
	WindowDampening float64

	// EntryTTL is how long cache entries remain valid after last update
	// Default: 5 minutes per I2P spec "expires after a few minutes"
	EntryTTL time.Duration

	// Enabled controls whether TCB sharing is active
	// Default: true
	Enabled bool
}

// DefaultTCBCacheConfig returns the default TCB cache configuration per I2P spec.
func DefaultTCBCacheConfig() TCBCacheConfig {
	return TCBCacheConfig{
		RTTDampening:    0.75,
		RTTDevDampening: 0.75,
		WindowDampening: 0.75,
		EntryTTL:        5 * time.Minute,
		Enabled:         true,
	}
}

// tcbEntry holds cached control block data for a single remote peer.
type tcbEntry struct {
	// Cached RTT estimate
	rtt time.Duration
	// Cached RTT variance
	rttVariance time.Duration
	// Cached window size (cwnd)
	windowSize uint32
	// When this entry was last updated
	lastUpdate time.Time
	// Number of connections that have contributed to this entry
	sampleCount int
}

// tcbCache manages cached control block data for multiple remote peers.
// Thread-safe for concurrent access from multiple connections.
type tcbCache struct {
	config  TCBCacheConfig
	entries map[string]*tcbEntry // Key: destination hash (hex-encoded)
	mu      sync.RWMutex
}

// newTCBCache creates a new TCB cache with the given configuration.
func newTCBCache(config TCBCacheConfig) *tcbCache {
	return &tcbCache{
		config:  config,
		entries: make(map[string]*tcbEntry),
	}
}

// getDestKey returns a unique key for the given destination.
// Uses SHA-256 hash of destination bytes, hex-encoded for map key.
func getDestKey(dest *go_i2cp.Destination) string {
	if dest == nil {
		return ""
	}
	hash, err := hashDestination(dest)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hash[:8]) // First 8 bytes is sufficient for uniqueness
}

// Get retrieves cached TCB data for a destination, applying dampening factors.
// Returns (rtt, rttVariance, windowSize, found).
// If not found or expired, returns zeros and found=false.
func (c *tcbCache) Get(dest *go_i2cp.Destination) (time.Duration, time.Duration, uint32, bool) {
	if !c.config.Enabled {
		return 0, 0, 0, false
	}

	key := getDestKey(dest)
	if key == "" {
		return 0, 0, 0, false
	}

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return 0, 0, 0, false
	}

	// Check if entry has expired
	if time.Since(entry.lastUpdate) > c.config.EntryTTL {
		// Entry expired, delete it
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return 0, 0, 0, false
	}

	// Apply dampening factors per RFC 2140 / I2P spec
	dampedRTT := time.Duration(float64(entry.rtt) * c.config.RTTDampening)
	dampedRTTVar := time.Duration(float64(entry.rttVariance) * c.config.RTTDevDampening)
	dampedWindow := uint32(float64(entry.windowSize) * c.config.WindowDampening)

	// Ensure minimum values
	if dampedWindow < 1 {
		dampedWindow = 1
	}

	log.Debug().
		Str("dest", key[:8]).
		Dur("rtt", dampedRTT).
		Dur("rttvar", dampedRTTVar).
		Uint32("window", dampedWindow).
		Msg("TCB cache hit - applying cached connection parameters")

	return dampedRTT, dampedRTTVar, dampedWindow, true
}

// Put stores TCB data for a destination when a connection closes.
// Called at connection close time per RFC 2140 "temporal" sharing.
func (c *tcbCache) Put(dest *go_i2cp.Destination, rtt, rttVariance time.Duration, windowSize uint32) {
	if !c.config.Enabled {
		return
	}

	key := getDestKey(dest)
	if key == "" {
		return
	}

	// Skip caching if values are at defaults (no useful data learned)
	if rtt == 0 && rttVariance == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[key]
	if exists {
		// Weighted average with existing entry per RFC 2140
		// This provides smoothing across multiple connection samples
		weight := 0.5 // Equal weight to old and new
		entry.rtt = time.Duration(float64(entry.rtt)*weight + float64(rtt)*(1-weight))
		entry.rttVariance = time.Duration(float64(entry.rttVariance)*weight + float64(rttVariance)*(1-weight))
		entry.windowSize = uint32(float64(entry.windowSize)*weight + float64(windowSize)*(1-weight))
		entry.lastUpdate = time.Now()
		entry.sampleCount++
	} else {
		// New entry
		c.entries[key] = &tcbEntry{
			rtt:         rtt,
			rttVariance: rttVariance,
			windowSize:  windowSize,
			lastUpdate:  time.Now(),
			sampleCount: 1,
		}
	}

	log.Debug().
		Str("dest", key[:8]).
		Dur("rtt", rtt).
		Dur("rttvar", rttVariance).
		Uint32("window", windowSize).
		Bool("updated", exists).
		Msg("TCB cache update - stored connection parameters")
}

// Size returns the number of entries in the cache.
func (c *tcbCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Clear removes all entries from the cache.
func (c *tcbCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*tcbEntry)
}

// CleanupExpired removes expired entries from the cache.
// Should be called periodically to prevent memory growth.
func (c *tcbCache) CleanupExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0
	for key, entry := range c.entries {
		if now.Sub(entry.lastUpdate) > c.config.EntryTTL {
			delete(c.entries, key)
			removed++
		}
	}

	if removed > 0 {
		log.Debug().
			Int("removed", removed).
			Int("remaining", len(c.entries)).
			Msg("TCB cache cleanup - removed expired entries")
	}

	return removed
}

// GetConfig returns the current cache configuration.
func (c *tcbCache) GetConfig() TCBCacheConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config
}

// SetConfig updates the cache configuration.
func (c *tcbCache) SetConfig(config TCBCacheConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = config
}

// TCBData holds the control block parameters that can be applied to a new connection.
type TCBData struct {
	RTT         time.Duration
	RTTVariance time.Duration
	WindowSize  uint32
	FromCache   bool
}

// applyTCBDataToConnection applies cached TCB data to a new connection.
// This is called during connection initialization if cached data is available.
func applyTCBDataToConnection(conn *StreamConn, data TCBData) {
	if !data.FromCache {
		return
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Apply cached RTT if available and better than default
	if data.RTT > 0 {
		conn.srtt = data.RTT
		conn.rtt = data.RTT
	}

	// Apply cached RTT variance
	if data.RTTVariance > 0 {
		conn.rttVariance = data.RTTVariance
	}

	// Apply cached window size (subject to dampening already applied)
	if data.WindowSize > 0 && data.WindowSize > conn.cwnd {
		// Start with larger window if cache suggests it
		conn.cwnd = data.WindowSize
		// Also set ssthresh based on cached window
		conn.ssthresh = data.WindowSize * 2
		if conn.ssthresh > MaxWindowSize {
			conn.ssthresh = MaxWindowSize
		}
	}

	// Recalculate RTO based on cached RTT data
	if data.RTT > 0 || data.RTTVariance > 0 {
		conn.rto = calculateRTOFromValues(conn.srtt, conn.rttVariance)
	}

	log.Debug().
		Uint32("localStreamID", conn.localStreamID).
		Dur("rtt", conn.srtt).
		Dur("rttvar", conn.rttVariance).
		Uint32("cwnd", conn.cwnd).
		Uint32("ssthresh", conn.ssthresh).
		Dur("rto", conn.rto).
		Msg("Applied TCB cache data to new connection")
}

// calculateRTOFromValues computes RTO from RTT values per RFC 6298.
// RTO = SRTT + max(G, 4*RTTVAR) where G is clock granularity (1ms)
func calculateRTOFromValues(srtt, rttVariance time.Duration) time.Duration {
	const granularity = time.Millisecond

	k := rttVariance * 4
	if k < granularity {
		k = granularity
	}

	rto := srtt + k

	// Clamp to [MinRTO, MaxRTO]
	if rto < MinRTO {
		rto = MinRTO
	}
	if rto > MaxRTO {
		rto = MaxRTO
	}

	return rto
}

// saveTCBDataFromConnection extracts TCB data from a closing connection.
// This is called during connection cleanup to cache parameters for future connections.
func saveTCBDataFromConnection(conn *StreamConn) TCBData {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	return TCBData{
		RTT:         conn.srtt,
		RTTVariance: conn.rttVariance,
		WindowSize:  conn.cwnd,
		FromCache:   true,
	}
}

// getDestKeyFromHash returns a cache key from a raw destination hash.
func getDestKeyFromHash(hash []byte) string {
	if len(hash) < 8 {
		return ""
	}
	return hex.EncodeToString(hash[:8])
}

// hashDestinationForCache computes the destination hash for cache key generation.
// Exported for testing purposes.
func hashDestinationForCache(dest *go_i2cp.Destination) ([]byte, error) {
	if dest == nil {
		return nil, nil
	}
	stream := go_i2cp.NewStream(make([]byte, 0, 512))
	if err := dest.WriteToStream(stream); err != nil {
		return nil, err
	}
	hash := sha256.Sum256(stream.Bytes())
	return hash[:], nil
}
