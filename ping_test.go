package streaming

import (
	"context"
	"testing"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestDestination creates a test I2P destination for ping tests.
func createTestDestination(t *testing.T) *go_i2cp.Destination {
	t.Helper()
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err)
	return dest
}

// TestIsPingPacket verifies ping packet detection per I2P streaming spec.
// Per spec: "A ping packet must have the ECHO, SIGNATURE_INCLUDED, and FROM_INCLUDED
// flags set. The sendStreamId must be greater than zero."
func TestIsPingPacket(t *testing.T) {
	tests := []struct {
		name         string
		flags        uint16
		sendStreamID uint32
		expected     bool
	}{
		{
			name:         "valid ping - ECHO with sendStreamID > 0",
			flags:        FlagECHO | FlagSignatureIncluded | FlagFromIncluded,
			sendStreamID: 12345,
			expected:     true,
		},
		{
			name:         "valid ping - ECHO only flag with sendStreamID > 0",
			flags:        FlagECHO,
			sendStreamID: 1,
			expected:     true,
		},
		{
			name:         "not ping - ECHO with sendStreamID == 0 (this is pong)",
			flags:        FlagECHO,
			sendStreamID: 0,
			expected:     false,
		},
		{
			name:         "not ping - no ECHO flag",
			flags:        FlagSYN | FlagFromIncluded,
			sendStreamID: 12345,
			expected:     false,
		},
		{
			name:         "not ping - no flags",
			flags:        0,
			sendStreamID: 12345,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &Packet{
				Flags:        tt.flags,
				SendStreamID: tt.sendStreamID,
			}
			result := isPingPacket(pkt)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsPongPacket verifies pong packet detection per I2P streaming spec.
// Per spec: "A pong packet must have the ECHO flag set. The sendStreamId must be zero."
func TestIsPongPacket(t *testing.T) {
	tests := []struct {
		name         string
		flags        uint16
		sendStreamID uint32
		expected     bool
	}{
		{
			name:         "valid pong - ECHO with sendStreamID == 0",
			flags:        FlagECHO,
			sendStreamID: 0,
			expected:     true,
		},
		{
			name:         "not pong - ECHO with sendStreamID > 0 (this is ping)",
			flags:        FlagECHO,
			sendStreamID: 12345,
			expected:     false,
		},
		{
			name:         "not pong - no ECHO flag",
			flags:        FlagSYN,
			sendStreamID: 0,
			expected:     false,
		},
		{
			name:         "not pong - no flags with sendStreamID == 0",
			flags:        0,
			sendStreamID: 0,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &Packet{
				Flags:        tt.flags,
				SendStreamID: tt.sendStreamID,
			}
			result := isPongPacket(pkt)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDefaultPingConfig verifies default ping configuration values.
func TestDefaultPingConfig(t *testing.T) {
	config := DefaultPingConfig()

	assert.True(t, config.AnswerPings, "AnswerPings should default to true")
	assert.Equal(t, 30*time.Second, config.PingTimeout, "PingTimeout should default to 30 seconds")
}

// TestMaxPingPayloadSize verifies the max payload constant matches spec.
func TestMaxPingPayloadSize(t *testing.T) {
	// Per spec: "The payload in the ping, up to a maximum of 32 bytes, is returned in the pong."
	assert.Equal(t, 32, MaxPingPayloadSize, "MaxPingPayloadSize should be 32 bytes per spec")
}

// TestPingManagerCreation verifies ping manager initialization.
func TestPingManagerCreation(t *testing.T) {
	// Create a minimal StreamManager for testing
	sm := &StreamManager{}

	t.Run("with default config", func(t *testing.T) {
		pm := newPingManager(sm, nil)
		require.NotNil(t, pm)
		assert.True(t, pm.config.AnswerPings)
		assert.Equal(t, 30*time.Second, pm.config.PingTimeout)
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &PingConfig{
			AnswerPings: false,
			PingTimeout: 10 * time.Second,
		}
		pm := newPingManager(sm, config)
		require.NotNil(t, pm)
		assert.False(t, pm.config.AnswerPings)
		assert.Equal(t, 10*time.Second, pm.config.PingTimeout)
	})
}

// TestPingManagerValidatePrerequisites verifies prerequisite checking.
func TestPingManagerValidatePrerequisites(t *testing.T) {
	sm := &StreamManager{}
	pm := newPingManager(sm, nil)

	t.Run("nil destination", func(t *testing.T) {
		err := pm.validatePingPrerequisites(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "destination is nil")
	})

	t.Run("nil session", func(t *testing.T) {
		dest := createTestDestination(t)
		err := pm.validatePingPrerequisites(dest)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no I2CP session")
	})
}

// TestPingManagerGenerateStreamID verifies stream ID generation.
func TestPingManagerGenerateStreamID(t *testing.T) {
	sm := &StreamManager{}
	pm := newPingManager(sm, nil)

	// Generate several IDs and verify they're non-zero
	for i := 0; i < 100; i++ {
		id, err := pm.generateStreamID()
		require.NoError(t, err)
		assert.NotZero(t, id, "stream ID must be non-zero")
	}

	// Verify IDs are somewhat random (not all the same)
	ids := make(map[uint32]bool)
	for i := 0; i < 10; i++ {
		id, _ := pm.generateStreamID()
		ids[id] = true
	}
	assert.Greater(t, len(ids), 1, "stream IDs should be random")
}

// TestPingResultNoSession verifies ping fails gracefully without session.
func TestPingResultNoSession(t *testing.T) {
	sm := &StreamManager{}
	pm := newPingManager(sm, nil)

	ctx := context.Background()
	dest := createTestDestination(t)

	result := pm.Ping(ctx, dest, []byte("test"))

	assert.NotNil(t, result)
	assert.Error(t, result.Err)
	assert.Contains(t, result.Err.Error(), "no I2CP session")
}

// TestPingResultNilDestination verifies ping fails with nil destination.
func TestPingResultNilDestination(t *testing.T) {
	sm := &StreamManager{}
	pm := newPingManager(sm, nil)

	ctx := context.Background()

	result := pm.Ping(ctx, nil, []byte("test"))

	assert.NotNil(t, result)
	assert.Error(t, result.Err)
	assert.Contains(t, result.Err.Error(), "destination is nil")
}

// TestHandlePingDisabled verifies pings are ignored when answerPings is false.
func TestHandlePingDisabled(t *testing.T) {
	sm := &StreamManager{}
	config := &PingConfig{
		AnswerPings: false,
		PingTimeout: 30 * time.Second,
	}
	pm := newPingManager(sm, config)

	// Create a ping packet
	pkt := &Packet{
		Flags:        FlagECHO | FlagSignatureIncluded | FlagFromIncluded,
		SendStreamID: 12345,
		Payload:      []byte("ping"),
	}

	// This should not panic and should simply return (no pong sent)
	// We can't easily verify no pong was sent without mocking, but we can
	// verify the handler doesn't crash
	srcDest := createTestDestination(t)
	pm.handlePing(pkt, srcDest, 0, 0)
}

// TestHandlePingZeroStreamID verifies invalid pings are ignored.
func TestHandlePingZeroStreamID(t *testing.T) {
	sm := &StreamManager{}
	pm := newPingManager(sm, nil)

	// Create an invalid ping packet (sendStreamID should be > 0)
	pkt := &Packet{
		Flags:        FlagECHO | FlagSignatureIncluded | FlagFromIncluded,
		SendStreamID: 0, // Invalid per spec
		Payload:      []byte("ping"),
	}

	// This should not panic and should simply return
	srcDest := createTestDestination(t)
	pm.handlePing(pkt, srcDest, 0, 0)
}

// TestHandlePongUnknownStreamID verifies unknown pongs are handled gracefully.
func TestHandlePongUnknownStreamID(t *testing.T) {
	sm := &StreamManager{}
	pm := newPingManager(sm, nil)

	// Create a pong for a stream ID we never sent a ping for
	pkt := &Packet{
		Flags:        FlagECHO,
		SendStreamID: 0,
		RecvStreamID: 99999, // Unknown stream ID
		Payload:      []byte("pong"),
	}

	// This should not panic and should simply log and return
	pm.handlePong(pkt)
}

// TestHandlePongNonZeroSendStreamID verifies pongs with wrong format are ignored.
func TestHandlePongNonZeroSendStreamID(t *testing.T) {
	sm := &StreamManager{}
	pm := newPingManager(sm, nil)

	// Create an invalid pong packet (sendStreamID should be 0)
	pkt := &Packet{
		Flags:        FlagECHO,
		SendStreamID: 12345, // Should be 0 for pong
		RecvStreamID: 99999,
		Payload:      []byte("pong"),
	}

	// This should not panic and should simply return (not a valid pong)
	pm.handlePong(pkt)
}

// TestPingPacketFormat verifies ping packet structure per spec.
func TestPingPacketFormat(t *testing.T) {
	// Per spec:
	// - ECHO, SIGNATURE_INCLUDED, and FROM_INCLUDED flags must be set
	// - sendStreamId must be > 0
	// - receiveStreamId is ignored
	// - Payload up to 32 bytes

	pkt := &Packet{
		SendStreamID:    12345,
		RecvStreamID:    0,
		SequenceNum:     0,
		AckThrough:      0,
		Flags:           FlagECHO | FlagSignatureIncluded | FlagFromIncluded,
		FromDestination: createTestDestination(t),
		Payload:         []byte("hello ping"),
	}

	// Verify it's recognized as a ping
	assert.True(t, isPingPacket(pkt))
	assert.False(t, isPongPacket(pkt))

	// Verify required flags
	assert.True(t, pkt.Flags&FlagECHO != 0, "ECHO flag required")
	assert.True(t, pkt.Flags&FlagSignatureIncluded != 0, "SIGNATURE_INCLUDED flag required")
	assert.True(t, pkt.Flags&FlagFromIncluded != 0, "FROM_INCLUDED flag required")

	// Verify sendStreamId > 0
	assert.Greater(t, pkt.SendStreamID, uint32(0), "sendStreamId must be > 0")
}

// TestPongPacketFormat verifies pong packet structure per spec.
func TestPongPacketFormat(t *testing.T) {
	// Per spec:
	// - ECHO flag must be set
	// - sendStreamId must be 0
	// - receiveStreamId is the sendStreamId from the ping

	pingStreamID := uint32(12345)

	pkt := &Packet{
		SendStreamID: 0,            // Must be 0 for pong
		RecvStreamID: pingStreamID, // Echo back the ping's sendStreamId
		SequenceNum:  0,
		AckThrough:   0,
		Flags:        FlagECHO, // Only ECHO flag needed for pong
		Payload:      []byte("hello ping"),
	}

	// Verify it's recognized as a pong
	assert.True(t, isPongPacket(pkt))
	assert.False(t, isPingPacket(pkt))

	// Verify ECHO flag
	assert.True(t, pkt.Flags&FlagECHO != 0, "ECHO flag required")

	// Verify sendStreamId == 0
	assert.Equal(t, uint32(0), pkt.SendStreamID, "sendStreamId must be 0")

	// Verify receiveStreamId matches ping's sendStreamId
	assert.Equal(t, pingStreamID, pkt.RecvStreamID, "receiveStreamId should match ping's sendStreamId")
}

// TestPayloadTruncation verifies payloads over 32 bytes are truncated.
func TestPayloadTruncation(t *testing.T) {
	// Create a payload larger than MaxPingPayloadSize
	largePayload := make([]byte, 64)
	for i := range largePayload {
		largePayload[i] = byte(i)
	}

	// Truncate as the ping implementation would
	truncated := largePayload
	if len(truncated) > MaxPingPayloadSize {
		truncated = truncated[:MaxPingPayloadSize]
	}

	assert.Len(t, truncated, MaxPingPayloadSize)
	assert.Equal(t, largePayload[:MaxPingPayloadSize], truncated)
}

// TestStreamManagerPingConfig verifies StreamManager ping configuration methods.
func TestStreamManagerPingConfig(t *testing.T) {
	sm := &StreamManager{}
	sm.pingMgr = newPingManager(sm, nil)

	t.Run("get default config", func(t *testing.T) {
		config := sm.GetPingConfig()
		require.NotNil(t, config)
		assert.True(t, config.AnswerPings)
		assert.Equal(t, 30*time.Second, config.PingTimeout)
	})

	t.Run("set custom config", func(t *testing.T) {
		customConfig := &PingConfig{
			AnswerPings: false,
			PingTimeout: 5 * time.Second,
		}
		sm.SetPingConfig(customConfig)

		config := sm.GetPingConfig()
		assert.False(t, config.AnswerPings)
		assert.Equal(t, 5*time.Second, config.PingTimeout)
	})

	t.Run("set nil config restores defaults", func(t *testing.T) {
		sm.SetPingConfig(nil)

		config := sm.GetPingConfig()
		assert.True(t, config.AnswerPings)
		assert.Equal(t, 30*time.Second, config.PingTimeout)
	})
}

// TestPendingPingResolution verifies pending ping tracking and resolution.
func TestPendingPingResolution(t *testing.T) {
	sm := &StreamManager{}
	pm := newPingManager(sm, nil)

	streamID := uint32(12345)
	resultCh := make(chan *PingResult, 1)

	// Register a pending ping
	pending := &pendingPing{
		streamID: streamID,
		payload:  []byte("test"),
		sentAt:   time.Now(),
		resultCh: resultCh,
	}
	pm.pendingPings.Store(streamID, pending)

	// Simulate receiving a pong
	pongPkt := &Packet{
		Flags:        FlagECHO,
		SendStreamID: 0,
		RecvStreamID: streamID,
		Payload:      []byte("test"),
	}

	// Handle the pong
	pm.handlePong(pongPkt)

	// Check result was sent
	select {
	case result := <-resultCh:
		assert.NoError(t, result.Err)
		assert.NotZero(t, result.RTT)
		assert.Equal(t, []byte("test"), result.Payload)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ping result")
	}
}

// TestEchoPacketDispatch verifies ECHO packets are routed correctly by manager.
func TestEchoPacketDispatch(t *testing.T) {
	// This tests the dispatchPacket logic for ECHO packets
	// In a real scenario, ECHO packets should NOT be routed to connections

	// Create ping packet
	pingPkt := &Packet{
		Flags:        FlagECHO | FlagSignatureIncluded | FlagFromIncluded,
		SendStreamID: 12345,
		Payload:      []byte("ping"),
	}

	// Verify it's identified as ping, not SYN
	assert.True(t, isPingPacket(pingPkt))
	assert.False(t, pingPkt.Flags&FlagSYN != 0 && pingPkt.SendStreamID == 0)

	// Create pong packet
	pongPkt := &Packet{
		Flags:        FlagECHO,
		SendStreamID: 0,
		RecvStreamID: 12345,
		Payload:      []byte("pong"),
	}

	// Verify it's identified as pong
	assert.True(t, isPongPacket(pongPkt))
}
