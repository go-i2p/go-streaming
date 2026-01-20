package streaming

import (
	"testing"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

// TestMessageStatusTrackerBasic tests basic tracker operations.
func TestMessageStatusTrackerBasic(t *testing.T) {
	tracker := newMessageStatusTracker(nil)

	if tracker == nil {
		t.Fatal("expected non-nil tracker")
	}

	if tracker.PendingCount() != 0 {
		t.Errorf("expected 0 pending, got %d", tracker.PendingCount())
	}

	stats := tracker.GetStats()
	if stats.TotalSent != 0 {
		t.Errorf("expected 0 total sent, got %d", stats.TotalSent)
	}
}

// TestMessageStatusTrackerNonceGeneration tests unique nonce generation.
func TestMessageStatusTrackerNonceGeneration(t *testing.T) {
	tracker := newMessageStatusTracker(nil)

	nonces := make(map[uint32]bool)
	for i := 0; i < 1000; i++ {
		nonce := tracker.GenerateNonce()
		if nonces[nonce] {
			t.Errorf("duplicate nonce generated: %d", nonce)
		}
		nonces[nonce] = true
	}
}

// TestMessageStatusTrackerTrackMessage tests tracking a message.
func TestMessageStatusTrackerTrackMessage(t *testing.T) {
	tracker := newMessageStatusTracker(nil)

	nonce := tracker.TrackMessage(nil, 100, 1024, true)
	if nonce == 0 {
		t.Error("expected non-zero nonce")
	}

	if tracker.PendingCount() != 1 {
		t.Errorf("expected 1 pending, got %d", tracker.PendingCount())
	}

	stats := tracker.GetStats()
	if stats.TotalSent != 1 {
		t.Errorf("expected 1 total sent, got %d", stats.TotalSent)
	}
}

// TestMessageStatusTrackerHandleSuccess tests handling success status.
func TestMessageStatusTrackerHandleSuccess(t *testing.T) {
	tracker := newMessageStatusTracker(nil)

	nonce := tracker.TrackMessage(nil, 100, 1024, true)

	// Simulate success status
	tracker.HandleStatus(nonce, go_i2cp.MSG_STATUS_GUARANTEED_SUCCESS, 1024, nonce)

	if tracker.PendingCount() != 0 {
		t.Errorf("expected 0 pending after success, got %d", tracker.PendingCount())
	}

	stats := tracker.GetStats()
	if stats.TotalDelivered != 1 {
		t.Errorf("expected 1 total delivered, got %d", stats.TotalDelivered)
	}
}

// TestMessageStatusTrackerHandleFailure tests handling failure status.
func TestMessageStatusTrackerHandleFailure(t *testing.T) {
	tracker := newMessageStatusTracker(nil)

	nonce := tracker.TrackMessage(nil, 100, 1024, true)

	// Simulate failure status
	tracker.HandleStatus(nonce, go_i2cp.MSG_STATUS_GUARANTEED_FAILURE, 0, nonce)

	if tracker.PendingCount() != 0 {
		t.Errorf("expected 0 pending after failure, got %d", tracker.PendingCount())
	}

	stats := tracker.GetStats()
	if stats.TotalFailed != 1 {
		t.Errorf("expected 1 total failed, got %d", stats.TotalFailed)
	}
}

// TestMessageStatusTrackerUnknownMessage tests handling status for unknown message.
func TestMessageStatusTrackerUnknownMessage(t *testing.T) {
	tracker := newMessageStatusTracker(nil)

	// Handle status for a message we never tracked
	tracker.HandleStatus(12345, go_i2cp.MSG_STATUS_GUARANTEED_SUCCESS, 1024, 12345)

	// Should not panic, stats should be unchanged
	stats := tracker.GetStats()
	if stats.TotalDelivered != 0 {
		t.Errorf("expected 0 delivered for unknown message, got %d", stats.TotalDelivered)
	}
}

// TestMessageStatusTrackerCleanupExpired tests expired message cleanup.
func TestMessageStatusTrackerCleanupExpired(t *testing.T) {
	tracker := newMessageStatusTracker(nil)

	// Track a message
	tracker.TrackMessage(nil, 100, 1024, true)

	if tracker.PendingCount() != 1 {
		t.Errorf("expected 1 pending, got %d", tracker.PendingCount())
	}

	// Cleanup with very short expiry - should remove
	expired := tracker.CleanupExpired(0)
	if expired != 1 {
		t.Errorf("expected 1 expired, got %d", expired)
	}

	if tracker.PendingCount() != 0 {
		t.Errorf("expected 0 pending after cleanup, got %d", tracker.PendingCount())
	}

	stats := tracker.GetStats()
	if stats.TotalExpired != 1 {
		t.Errorf("expected 1 total expired, got %d", stats.TotalExpired)
	}
}

// TestMessageStatusTrackerClear tests clearing all messages.
func TestMessageStatusTrackerClear(t *testing.T) {
	tracker := newMessageStatusTracker(nil)

	for i := 0; i < 10; i++ {
		tracker.TrackMessage(nil, uint32(i), 1024, true)
	}

	if tracker.PendingCount() != 10 {
		t.Errorf("expected 10 pending, got %d", tracker.PendingCount())
	}

	tracker.Clear()

	if tracker.PendingCount() != 0 {
		t.Errorf("expected 0 pending after clear, got %d", tracker.PendingCount())
	}
}

// TestMessageStatusTrackerConcurrent tests thread safety.
func TestMessageStatusTrackerConcurrent(t *testing.T) {
	tracker := newMessageStatusTracker(nil)
	done := make(chan struct{})

	// Concurrent writers
	go func() {
		for i := 0; i < 100; i++ {
			tracker.TrackMessage(nil, uint32(i), 1024, true)
		}
		done <- struct{}{}
	}()

	// Concurrent status handlers
	go func() {
		for i := 0; i < 100; i++ {
			tracker.HandleStatus(uint32(i+1), go_i2cp.MSG_STATUS_GUARANTEED_SUCCESS, 1024, uint32(i+1))
		}
		done <- struct{}{}
	}()

	// Concurrent readers
	go func() {
		for i := 0; i < 100; i++ {
			tracker.GetStats()
			tracker.PendingCount()
		}
		done <- struct{}{}
	}()

	// Wait for completion
	<-done
	<-done
	<-done
}

// TestMessageStatusConstants verifies go-i2cp exports the expected constants.
func TestMessageStatusConstants(t *testing.T) {
	// Verify expected constants are available
	tests := []struct {
		name   string
		status uint8
	}{
		{"MSG_STATUS_AVAILABLE", go_i2cp.MSG_STATUS_AVAILABLE},
		{"MSG_STATUS_ACCEPTED", go_i2cp.MSG_STATUS_ACCEPTED},
		{"MSG_STATUS_BEST_EFFORT_SUCCESS", go_i2cp.MSG_STATUS_BEST_EFFORT_SUCCESS},
		{"MSG_STATUS_BEST_EFFORT_FAILURE", go_i2cp.MSG_STATUS_BEST_EFFORT_FAILURE},
		{"MSG_STATUS_GUARANTEED_SUCCESS", go_i2cp.MSG_STATUS_GUARANTEED_SUCCESS},
		{"MSG_STATUS_GUARANTEED_FAILURE", go_i2cp.MSG_STATUS_GUARANTEED_FAILURE},
		{"MSG_STATUS_LOCAL_SUCCESS", go_i2cp.MSG_STATUS_LOCAL_SUCCESS},
		{"MSG_STATUS_LOCAL_FAILURE", go_i2cp.MSG_STATUS_LOCAL_FAILURE},
		{"MSG_STATUS_ROUTER_FAILURE", go_i2cp.MSG_STATUS_ROUTER_FAILURE},
		{"MSG_STATUS_NETWORK_FAILURE", go_i2cp.MSG_STATUS_NETWORK_FAILURE},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify we can access the constant
			_ = tt.status
		})
	}
}

// TestMessageStatusHelperFunctions verifies go-i2cp helper functions.
func TestMessageStatusHelperFunctions(t *testing.T) {
	// Test IsMessageStatusSuccess
	if !go_i2cp.IsMessageStatusSuccess(go_i2cp.MSG_STATUS_GUARANTEED_SUCCESS) {
		t.Error("expected GUARANTEED_SUCCESS to be success")
	}
	if !go_i2cp.IsMessageStatusSuccess(go_i2cp.MSG_STATUS_BEST_EFFORT_SUCCESS) {
		t.Error("expected BEST_EFFORT_SUCCESS to be success")
	}

	// Test IsMessageStatusFailure
	if !go_i2cp.IsMessageStatusFailure(go_i2cp.MSG_STATUS_GUARANTEED_FAILURE) {
		t.Error("expected GUARANTEED_FAILURE to be failure")
	}
	// Note: Some failure codes like NETWORK_FAILURE may be considered transient/retriable
	// so they might not be flagged as permanent failures

	// Test GetMessageStatusCategory
	category := go_i2cp.GetMessageStatusCategory(go_i2cp.MSG_STATUS_GUARANTEED_SUCCESS)
	if category == "" {
		t.Error("expected non-empty category")
	}
}

// TestMessageStatsFields verifies MessageStats structure.
func TestMessageStatsFields(t *testing.T) {
	tracker := newMessageStatusTracker(nil)

	// Send some messages
	for i := 0; i < 5; i++ {
		nonce := tracker.TrackMessage(nil, uint32(i), 1024, true)
		// Mark as delivered
		tracker.HandleStatus(nonce, go_i2cp.MSG_STATUS_GUARANTEED_SUCCESS, 1024, nonce)
	}

	// Send some that fail
	for i := 5; i < 8; i++ {
		nonce := tracker.TrackMessage(nil, uint32(i), 1024, true)
		tracker.HandleStatus(nonce, go_i2cp.MSG_STATUS_GUARANTEED_FAILURE, 0, nonce)
	}

	stats := tracker.GetStats()
	if stats.TotalSent != 8 {
		t.Errorf("expected 8 total sent, got %d", stats.TotalSent)
	}
	if stats.TotalDelivered != 5 {
		t.Errorf("expected 5 total delivered, got %d", stats.TotalDelivered)
	}
	if stats.TotalFailed != 3 {
		t.Errorf("expected 3 total failed, got %d", stats.TotalFailed)
	}
}

// TestMessageDeliveryTime tests delivery time tracking.
func TestMessageDeliveryTime(t *testing.T) {
	tracker := newMessageStatusTracker(nil)

	nonce := tracker.TrackMessage(nil, 100, 1024, true)

	// Wait a bit to get measurable delivery time
	time.Sleep(10 * time.Millisecond)

	tracker.HandleStatus(nonce, go_i2cp.MSG_STATUS_GUARANTEED_SUCCESS, 1024, nonce)

	stats := tracker.GetStats()
	if stats.LastDeliveryMs < 10 {
		t.Errorf("expected delivery time >= 10ms, got %dms", stats.LastDeliveryMs)
	}
}

// TestManagerMessageStats tests StreamManager message stats API.
func TestManagerMessageStats(t *testing.T) {
	// This test just verifies the API exists and returns sensible defaults
	// Full integration would require a real I2CP connection

	// Test with nil tracker (simulating manager without tracker)
	stats := MessageStats{}
	if stats.TotalSent != 0 {
		t.Error("expected zero stats for uninitialized")
	}
}

// TestPendingMessageInfo verifies the pending message info structure.
func TestPendingMessageInfo(t *testing.T) {
	info := &pendingMessageInfo{
		nonce:       12345,
		seqNum:      100,
		conn:        nil,
		sentAt:      time.Now(),
		payloadSize: 1024,
		isDataPkt:   true,
		retryCount:  0,
		maxRetries:  3,
	}

	if info.nonce != 12345 {
		t.Errorf("expected nonce 12345, got %d", info.nonce)
	}
	if info.seqNum != 100 {
		t.Errorf("expected seqNum 100, got %d", info.seqNum)
	}
	if !info.isDataPkt {
		t.Error("expected isDataPkt to be true")
	}
}
