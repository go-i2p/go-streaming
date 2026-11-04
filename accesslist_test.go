package streaming

import (
	"testing"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

// createAccessListTestDestination creates a test destination with random key material.
func createAccessListTestDestination(t *testing.T) *go_i2cp.Destination {
	t.Helper()
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	if err != nil {
		t.Fatalf("failed to generate destination: %v", err)
	}
	return dest
}

// createAccessListTestDestination2 creates a second test destination with different key material.
func createAccessListTestDestination2(t *testing.T) *go_i2cp.Destination {
	t.Helper()
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	if err != nil {
		t.Fatalf("failed to generate destination: %v", err)
	}
	return dest
}

// TestDefaultAccessListConfig verifies the default config is disabled.
func TestDefaultAccessListConfig(t *testing.T) {
	config := DefaultAccessListConfig()

	if config.Mode != AccessListModeDisabled {
		t.Errorf("expected default mode to be disabled, got %v", config.Mode)
	}
	if len(config.Hashes) != 0 {
		t.Errorf("expected no default hashes, got %d", len(config.Hashes))
	}
	if config.DisableRejectLogging {
		t.Error("expected reject logging to be enabled by default")
	}
}

// TestAccessFilterDisabled verifies that a disabled filter allows all connections.
func TestAccessFilterDisabled(t *testing.T) {
	filter := newAccessFilter(DefaultAccessListConfig())

	dest1 := createAccessListTestDestination(t)
	dest2 := createAccessListTestDestination2(t)

	// All destinations should be allowed when disabled
	if !filter.IsAllowed(dest1) {
		t.Error("expected dest1 to be allowed when filter is disabled")
	}
	if !filter.IsAllowed(dest2) {
		t.Error("expected dest2 to be allowed when filter is disabled")
	}
	if !filter.IsAllowed(nil) {
		t.Error("expected nil destination to be allowed when filter is disabled")
	}
}

// TestAccessFilterWhitelistMode verifies whitelist behavior.
func TestAccessFilterWhitelistMode(t *testing.T) {
	dest1 := createAccessListTestDestination(t)
	dest2 := createAccessListTestDestination2(t)

	// Get the hash for dest1
	hash1 := hashDestinationForAccessList(dest1)
	if hash1 == "" {
		t.Fatal("failed to hash dest1")
	}

	config := &AccessListConfig{
		Mode:                 AccessListModeWhitelist,
		Hashes:               []string{hash1},
		DisableRejectLogging: true, // Suppress logs in tests
	}
	filter := newAccessFilter(config)

	// dest1 should be allowed (in whitelist)
	if !filter.IsAllowed(dest1) {
		t.Error("expected dest1 to be allowed (in whitelist)")
	}

	// dest2 should NOT be allowed (not in whitelist)
	if filter.IsAllowed(dest2) {
		t.Error("expected dest2 to be rejected (not in whitelist)")
	}
}

// TestAccessFilterBlacklistMode verifies blacklist behavior.
func TestAccessFilterBlacklistMode(t *testing.T) {
	dest1 := createAccessListTestDestination(t)
	dest2 := createAccessListTestDestination2(t)

	// Get the hash for dest1
	hash1 := hashDestinationForAccessList(dest1)
	if hash1 == "" {
		t.Fatal("failed to hash dest1")
	}

	config := &AccessListConfig{
		Mode:                 AccessListModeBlacklist,
		Hashes:               []string{hash1},
		DisableRejectLogging: true,
	}
	filter := newAccessFilter(config)

	// dest1 should NOT be allowed (in blacklist)
	if filter.IsAllowed(dest1) {
		t.Error("expected dest1 to be rejected (in blacklist)")
	}

	// dest2 should be allowed (not in blacklist)
	if !filter.IsAllowed(dest2) {
		t.Error("expected dest2 to be allowed (not in blacklist)")
	}
}

// TestAccessFilterAddRemoveHash verifies adding and removing hashes dynamically.
func TestAccessFilterAddRemoveHash(t *testing.T) {
	dest := createAccessListTestDestination(t)
	hash := hashDestinationForAccessList(dest)

	config := &AccessListConfig{
		Mode:                 AccessListModeBlacklist,
		DisableRejectLogging: true,
	}
	filter := newAccessFilter(config)

	// Initially dest should be allowed (empty blacklist)
	if !filter.IsAllowed(dest) {
		t.Error("expected dest to be allowed initially")
	}

	// Add to blacklist
	filter.AddHash(hash)

	// Now dest should be blocked
	if filter.IsAllowed(dest) {
		t.Error("expected dest to be blocked after adding to blacklist")
	}

	// Check count
	if filter.Count() != 1 {
		t.Errorf("expected count to be 1, got %d", filter.Count())
	}

	// Remove from blacklist
	filter.RemoveHash(hash)

	// Now dest should be allowed again
	if !filter.IsAllowed(dest) {
		t.Error("expected dest to be allowed after removing from blacklist")
	}

	// Check count
	if filter.Count() != 0 {
		t.Errorf("expected count to be 0, got %d", filter.Count())
	}
}

// TestAccessFilterClear verifies clearing all hashes.
func TestAccessFilterClear(t *testing.T) {
	dest1 := createAccessListTestDestination(t)
	dest2 := createAccessListTestDestination2(t)

	config := &AccessListConfig{
		Mode: AccessListModeWhitelist,
		Hashes: []string{
			hashDestinationForAccessList(dest1),
			hashDestinationForAccessList(dest2),
		},
		DisableRejectLogging: true,
	}
	filter := newAccessFilter(config)

	if filter.Count() != 2 {
		t.Errorf("expected count to be 2, got %d", filter.Count())
	}

	filter.Clear()

	if filter.Count() != 0 {
		t.Errorf("expected count to be 0 after clear, got %d", filter.Count())
	}

	// In whitelist mode with empty list, all should be rejected
	if filter.IsAllowed(dest1) {
		t.Error("expected dest1 to be rejected after clear (empty whitelist)")
	}
}

// TestAccessFilterSetConfig verifies reconfiguring the filter.
func TestAccessFilterSetConfig(t *testing.T) {
	dest := createAccessListTestDestination(t)
	hash := hashDestinationForAccessList(dest)

	filter := newAccessFilter(DefaultAccessListConfig())

	// Initially allowed (disabled mode)
	if !filter.IsAllowed(dest) {
		t.Error("expected dest to be allowed when disabled")
	}

	// Switch to blacklist mode with dest blocked
	filter.SetConfig(&AccessListConfig{
		Mode:                 AccessListModeBlacklist,
		Hashes:               []string{hash},
		DisableRejectLogging: true,
	})

	// Now should be blocked
	if filter.IsAllowed(dest) {
		t.Error("expected dest to be blocked after reconfiguring to blacklist")
	}

	// Switch back to disabled
	filter.SetConfig(DefaultAccessListConfig())

	// Should be allowed again
	if !filter.IsAllowed(dest) {
		t.Error("expected dest to be allowed after reconfiguring to disabled")
	}
}

// TestAccessFilterCheckAndLog verifies the CheckAndLog method.
func TestAccessFilterCheckAndLog(t *testing.T) {
	dest := createAccessListTestDestination(t)
	hash := hashDestinationForAccessList(dest)

	config := &AccessListConfig{
		Mode:                 AccessListModeBlacklist,
		Hashes:               []string{hash},
		DisableRejectLogging: true,
	}
	filter := newAccessFilter(config)

	// Check blocked destination
	err := filter.CheckAndLog(dest)
	if err == nil {
		t.Error("expected error for blocked destination")
	}

	// Verify it's an AccessDeniedError
	if _, ok := err.(*AccessDeniedError); !ok {
		t.Errorf("expected AccessDeniedError, got %T", err)
	}

	// Check allowed destination
	dest2 := createAccessListTestDestination2(t)
	err = filter.CheckAndLog(dest2)
	if err != nil {
		t.Errorf("expected no error for allowed destination, got %v", err)
	}
}

// TestAccessFilterNilDestination verifies handling of nil destinations.
func TestAccessFilterNilDestination(t *testing.T) {
	config := &AccessListConfig{
		Mode:                 AccessListModeWhitelist,
		Hashes:               []string{"some-hash"},
		DisableRejectLogging: true,
	}
	filter := newAccessFilter(config)

	// nil destination should be rejected for security (prevent bypass of whitelist/blacklist)
	if filter.IsAllowed(nil) {
		t.Error("expected nil destination to be rejected")
	}
}

// TestAccessFilterConcurrentAccess verifies thread-safe access.
func TestAccessFilterConcurrentAccess(t *testing.T) {
	config := &AccessListConfig{
		Mode:                 AccessListModeBlacklist,
		DisableRejectLogging: true,
	}
	filter := newAccessFilter(config)

	done := make(chan struct{})

	// Concurrent writers
	go func() {
		for i := 0; i < 100; i++ {
			filter.AddHash("hash-" + string(rune('a'+i%26)))
		}
		done <- struct{}{}
	}()

	// Concurrent readers
	go func() {
		for i := 0; i < 100; i++ {
			dest := createAccessListTestDestination(t)
			filter.IsAllowed(dest)
		}
		done <- struct{}{}
	}()

	// Concurrent config changes
	go func() {
		for i := 0; i < 100; i++ {
			filter.GetConfig()
		}
		done <- struct{}{}
	}()

	// Wait for all goroutines
	<-done
	<-done
	<-done
}

// TestParseHashList verifies parsing comma/space-separated hash lists.
func TestParseHashList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty", "", 0},
		{"single", "abc123", 1},
		{"comma-separated", "abc,def,ghi", 3},
		{"space-separated", "abc def ghi", 3},
		{"mixed-separators", "abc, def ghi,jkl", 4},
		{"extra-whitespace", "  abc   def  ", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseHashList(tt.input)
			if len(result) != tt.expected {
				t.Errorf("expected %d hashes, got %d: %v", tt.expected, len(result), result)
			}
		})
	}
}

// TestAccessDeniedError verifies the error type.
func TestAccessDeniedError(t *testing.T) {
	err := &AccessDeniedError{Reason: "test reason"}

	expected := "access denied: test reason"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

// TestHashDestinationForAccessList verifies destination hashing.
func TestHashDestinationForAccessList(t *testing.T) {
	dest1 := createAccessListTestDestination(t)
	dest2 := createAccessListTestDestination2(t)

	hash1 := hashDestinationForAccessList(dest1)
	hash2 := hashDestinationForAccessList(dest2)

	// Hashes should be non-empty
	if hash1 == "" {
		t.Error("expected non-empty hash for dest1")
	}
	if hash2 == "" {
		t.Error("expected non-empty hash for dest2")
	}

	// Different destinations should have different hashes
	if hash1 == hash2 {
		t.Error("expected different hashes for different destinations")
	}

	// Same destination should have consistent hash
	hash1Again := hashDestinationForAccessList(dest1)
	if hash1 != hash1Again {
		t.Error("expected consistent hash for same destination")
	}

	// nil destination should return empty hash
	nilHash := hashDestinationForAccessList(nil)
	if nilHash != "" {
		t.Error("expected empty hash for nil destination")
	}
}

// TestStreamManagerAccessListAPI verifies the StreamManager access list API.
func TestStreamManagerAccessListAPI(t *testing.T) {
	// Create a mock manager (we'll just test the API, not full integration)
	// Note: This test doesn't require a real I2CP connection

	// Test the config types are correct
	config := DefaultAccessListConfig()
	if config == nil {
		t.Fatal("expected non-nil default config")
	}

	// Test config fields
	if config.Mode != AccessListModeDisabled {
		t.Errorf("expected disabled mode, got %v", config.Mode)
	}

	// Test creating filter
	filter := newAccessFilter(config)
	if filter == nil {
		t.Fatal("expected non-nil filter")
	}

	// Test get config returns copy
	config2 := filter.GetConfig()
	if config2 == config {
		t.Error("expected GetConfig to return a copy, not same pointer")
	}
}

// TestAccessListModeConstants verifies the mode constants.
func TestAccessListModeConstants(t *testing.T) {
	// Verify modes are distinct
	modes := []AccessListMode{
		AccessListModeDisabled,
		AccessListModeWhitelist,
		AccessListModeBlacklist,
	}

	seen := make(map[AccessListMode]bool)
	for _, mode := range modes {
		if seen[mode] {
			t.Errorf("duplicate mode value: %v", mode)
		}
		seen[mode] = true
	}
}

// TestNormalizeHash verifies hash normalization.
func TestNormalizeHash(t *testing.T) {
	// Valid Base64 hash (44 chars with padding)
	validHash := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	normalized := normalizeHash(validHash)
	if normalized == "" {
		t.Error("expected valid Base64 hash to be accepted")
	}

	// Empty string
	if normalizeHash("") != "" {
		t.Error("expected empty string to return empty")
	}

	// Whitespace only
	if normalizeHash("   ") != "" {
		t.Error("expected whitespace-only to return empty")
	}

	// Short hash (used as-is)
	shortHash := normalizeHash("abc123")
	if shortHash != "abc123" {
		t.Errorf("expected short hash to be returned as-is, got %q", shortHash)
	}
}

// TestAccessFilterWhitelistEmpty verifies empty whitelist behavior.
func TestAccessFilterWhitelistEmpty(t *testing.T) {
	// Empty whitelist should reject all
	config := &AccessListConfig{
		Mode:                 AccessListModeWhitelist,
		Hashes:               nil,
		DisableRejectLogging: true,
	}
	filter := newAccessFilter(config)

	dest := createAccessListTestDestination(t)
	if filter.IsAllowed(dest) {
		t.Error("expected rejection with empty whitelist")
	}
}

// TestAccessFilterBlacklistEmpty verifies empty blacklist behavior.
func TestAccessFilterBlacklistEmpty(t *testing.T) {
	// Empty blacklist should allow all
	config := &AccessListConfig{
		Mode:                 AccessListModeBlacklist,
		Hashes:               nil,
		DisableRejectLogging: true,
	}
	filter := newAccessFilter(config)

	dest := createAccessListTestDestination(t)
	if !filter.IsAllowed(dest) {
		t.Error("expected allowance with empty blacklist")
	}
}
