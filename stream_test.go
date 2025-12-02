package streaming

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestConnStateString verifies that ConnState.String() returns expected values.
// This is a simple sanity check for the state machine representation.
func TestConnStateString(t *testing.T) {
	tests := []struct {
		state ConnState
		want  string
	}{
		{StateInit, "INIT"},
		{StateSynSent, "SYN_SENT"},
		{StateSynRcvd, "SYN_RCVD"},
		{StateEstablished, "ESTABLISHED"},
		{StateCloseWait, "CLOSE_WAIT"},
		{StateClosing, "CLOSING"},
		{StateClosed, "CLOSED"},
		{ConnState(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.state.String()
			assert.Equal(t, tt.want, got, "ConnState.String()")
		})
	}
}

// TestConstants verifies that protocol constants match I2P streaming spec.
func TestConstants(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"DefaultMTU", DefaultMTU, 1730},
		{"ECIESMTU", ECIESMTU, 1812},
		{"MinMTU", MinMTU, 512},
		{"DefaultWindowSize", DefaultWindowSize, 6},
		{"MaxWindowSize", MaxWindowSize, 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.got, tt.name)
		})
	}
}

// Note: I2CP session creation tests require a running I2P router.
// These will be added in Phase 1 when we implement actual I2CP operations.
// For now, we verify that the basic types and constants are correct.
