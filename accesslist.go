package streaming

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

// AccessListMode specifies how the access list is used.
type AccessListMode int

const (
	// AccessListModeDisabled means no access list filtering (default)
	AccessListModeDisabled AccessListMode = iota
	// AccessListModeWhitelist allows only listed destinations
	AccessListModeWhitelist
	// AccessListModeBlacklist blocks listed destinations
	AccessListModeBlacklist
)

// AccessListConfig configures destination-based access filtering.
// This implements the i2cp.accessList, i2cp.enableAccessList, and
// i2cp.enableBlackList options from the I2P streaming specification.
type AccessListConfig struct {
	// Mode specifies how the access list is used
	Mode AccessListMode

	// Hashes contains the list of destination hashes (Base64 encoded or raw 32-byte hashes)
	// Per spec: "Comma- or space-separated list of Base64 peer Hashes"
	Hashes []string

	// DisableRejectLogging disables log warnings when connections are rejected
	DisableRejectLogging bool
}

// DefaultAccessListConfig returns the default (disabled) configuration.
// Per I2P spec, access list filtering is disabled by default.
func DefaultAccessListConfig() *AccessListConfig {
	return &AccessListConfig{
		Mode:                 AccessListModeDisabled,
		Hashes:               nil,
		DisableRejectLogging: false,
	}
}

// accessFilter implements destination-based access filtering.
type accessFilter struct {
	config *AccessListConfig
	mu     sync.RWMutex

	// hashSet is a set of normalized hashes for O(1) lookup
	// Keys are Base64-encoded 32-byte SHA-256 hashes
	hashSet map[string]struct{}
}

// newAccessFilter creates a new access filter with the given config.
func newAccessFilter(config *AccessListConfig) *accessFilter {
	if config == nil {
		config = DefaultAccessListConfig()
	}
	af := &accessFilter{
		config:  config,
		hashSet: make(map[string]struct{}),
	}
	af.rebuildHashSet()
	return af
}

// SetConfig updates the filter configuration and rebuilds the hash set.
func (af *accessFilter) SetConfig(config *AccessListConfig) {
	af.mu.Lock()
	defer af.mu.Unlock()
	if config == nil {
		config = DefaultAccessListConfig()
	}
	af.config = config
	af.rebuildHashSet()
}

// GetConfig returns a copy of the current configuration.
func (af *accessFilter) GetConfig() *AccessListConfig {
	af.mu.RLock()
	defer af.mu.RUnlock()
	hashesCopy := make([]string, len(af.config.Hashes))
	copy(hashesCopy, af.config.Hashes)
	return &AccessListConfig{
		Mode:                 af.config.Mode,
		Hashes:               hashesCopy,
		DisableRejectLogging: af.config.DisableRejectLogging,
	}
}

// rebuildHashSet rebuilds the hash set from the config.
// Must be called with af.mu held.
func (af *accessFilter) rebuildHashSet() {
	af.hashSet = make(map[string]struct{})
	for _, hash := range af.config.Hashes {
		normalized := normalizeHash(hash)
		if normalized != "" {
			af.hashSet[normalized] = struct{}{}
		}
	}
}

// normalizeHash converts a hash to a standard Base64 format.
// Accepts both Base64-encoded hashes and raw byte hashes.
func normalizeHash(hash string) string {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return ""
	}

	// If it looks like Base64 (32-byte hash = 44 chars in Base64 with padding, or 43 without)
	if len(hash) >= 43 && len(hash) <= 44 {
		// Validate it's valid Base64
		decoded, err := base64.StdEncoding.DecodeString(hash)
		if err != nil {
			// Try URL-safe Base64 (I2P uses this)
			decoded, err = base64.RawStdEncoding.DecodeString(hash)
			if err != nil {
				log.Warn().Str("hash", hash).Msg("invalid Base64 hash in access list")
				return ""
			}
		}
		// Re-encode to standard Base64 for consistent lookup
		return base64.StdEncoding.EncodeToString(decoded)
	}

	// For other formats, just use as-is (might be truncated hash for display)
	return hash
}

// IsAllowed checks if a connection from the given destination should be allowed.
// Returns true if the connection should be accepted, false if it should be rejected.
func (af *accessFilter) IsAllowed(dest *go_i2cp.Destination) bool {
	af.mu.RLock()
	defer af.mu.RUnlock()

	// If disabled, allow all
	if af.config.Mode == AccessListModeDisabled {
		return true
	}

	// If no destination provided, we can't check - allow by default
	if dest == nil {
		return true
	}

	// Get the destination hash
	destHash := hashDestinationForAccessList(dest)
	if destHash == "" {
		// Couldn't hash destination - allow by default
		return true
	}

	// Check if hash is in the set
	_, inList := af.hashSet[destHash]

	switch af.config.Mode {
	case AccessListModeWhitelist:
		// Whitelist: only allow if in list
		return inList
	case AccessListModeBlacklist:
		// Blacklist: allow if NOT in list
		return !inList
	default:
		return true
	}
}

// CheckAndLog checks if a destination is allowed and logs if rejected.
// Returns nil if allowed, or an error describing why rejected.
func (af *accessFilter) CheckAndLog(dest *go_i2cp.Destination) error {
	if af.IsAllowed(dest) {
		return nil
	}

	af.mu.RLock()
	config := af.config
	af.mu.RUnlock()

	reason := "destination in blacklist"
	if config.Mode == AccessListModeWhitelist {
		reason = "destination not in whitelist"
	}

	if !config.DisableRejectLogging {
		logDestinationRejected(dest, reason)
	}

	return &AccessDeniedError{Reason: reason}
}

// AccessDeniedError is returned when a connection is rejected due to access list.
type AccessDeniedError struct {
	Reason string
}

func (e *AccessDeniedError) Error() string {
	return "access denied: " + e.Reason
}

// hashDestinationForAccessList creates a Base64-encoded SHA-256 hash of a destination.
func hashDestinationForAccessList(dest *go_i2cp.Destination) string {
	if dest == nil {
		return ""
	}

	// Serialize the destination to bytes
	stream := go_i2cp.NewStream(make([]byte, 0, 512))
	if err := dest.WriteToStream(stream); err != nil {
		return ""
	}

	// Hash the serialized destination
	hash := sha256.Sum256(stream.Bytes())
	return base64.StdEncoding.EncodeToString(hash[:])
}

// logDestinationRejected logs a warning about a rejected connection.
func logDestinationRejected(dest *go_i2cp.Destination, reason string) {
	peerID := "unknown"
	if dest != nil {
		hash := hashDestinationForAccessList(dest)
		if len(hash) > 12 {
			peerID = hash[:12] + "..."
		}
	}

	log.Warn().
		Str("peer", peerID).
		Str("reason", reason).
		Msg("incoming connection rejected by access list")
}

// AddHash adds a hash to the access list.
func (af *accessFilter) AddHash(hash string) {
	af.mu.Lock()
	defer af.mu.Unlock()

	normalized := normalizeHash(hash)
	if normalized == "" {
		return
	}

	// Add to config
	af.config.Hashes = append(af.config.Hashes, hash)
	// Add to hash set
	af.hashSet[normalized] = struct{}{}
}

// RemoveHash removes a hash from the access list.
func (af *accessFilter) RemoveHash(hash string) {
	af.mu.Lock()
	defer af.mu.Unlock()

	normalized := normalizeHash(hash)
	if normalized == "" {
		return
	}

	// Remove from hash set
	delete(af.hashSet, normalized)

	// Remove from config (rebuild to avoid index issues)
	newHashes := make([]string, 0, len(af.config.Hashes))
	for _, h := range af.config.Hashes {
		if normalizeHash(h) != normalized {
			newHashes = append(newHashes, h)
		}
	}
	af.config.Hashes = newHashes
}

// Clear removes all hashes from the access list.
func (af *accessFilter) Clear() {
	af.mu.Lock()
	defer af.mu.Unlock()

	af.config.Hashes = nil
	af.hashSet = make(map[string]struct{})
}

// Count returns the number of hashes in the access list.
func (af *accessFilter) Count() int {
	af.mu.RLock()
	defer af.mu.RUnlock()
	return len(af.hashSet)
}

// ParseHashList parses a comma or space-separated list of hashes.
// Per I2P spec: "Comma- or space-separated list of Base64 peer Hashes"
func ParseHashList(list string) []string {
	if list == "" {
		return nil
	}

	// Replace commas with spaces for uniform splitting
	list = strings.ReplaceAll(list, ",", " ")

	// Split on whitespace
	parts := strings.Fields(list)

	// Filter out empty strings
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}

	return result
}
