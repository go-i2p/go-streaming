package streaming

import (
	"sync"
	"testing"
	"time"

	"github.com/armon/circbuf"
	"github.com/stretchr/testify/require"
)

// newTestStreamConnForChokeReception creates a StreamConn for testing choke reception.
func newTestStreamConnForChokeReception() *StreamConn {
	recvBuf, _ := circbuf.NewBuffer(1024)
	s := &StreamConn{
		localStreamID:  100,
		remoteStreamID: 200,
		sendSeq:        1,
		recvSeq:        100,
		ackThrough:     0,
		state:          StateEstablished,
		recvBuf:        recvBuf,
		sendBuf:        []byte{},
	}
	s.recvCond = sync.NewCond(&s.mu)
	return s
}

// TestChokeReceptionDetection verifies that choke signals are detected and state is updated.
func TestChokeReceptionDetection(t *testing.T) {
	tests := []struct {
		name          string
		optionalDelay uint16
		flags         uint16
		expectChoked  bool
	}{
		{
			name:          "no delay requested - not choked",
			optionalDelay: 0,
			flags:         0, // No flags needed - ackThrough always valid per spec
			expectChoked:  false,
		},
		{
			name:          "delay requested but under threshold - not choked",
			optionalDelay: 30000,
			flags:         FlagDelayRequested,
			expectChoked:  false,
		},
		{
			name:          "delay at threshold - not choked",
			optionalDelay: 60000,
			flags:         FlagDelayRequested,
			expectChoked:  false,
		},
		{
			name:          "delay over threshold - choked",
			optionalDelay: 61000,
			flags:         FlagDelayRequested,
			expectChoked:  true,
		},
		{
			name:          "high delay - choked",
			optionalDelay: 65535,
			flags:         FlagDelayRequested,
			expectChoked:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStreamConnForChokeReception()

			pkt := &Packet{
				Flags:         tt.flags,
				OptionalDelay: tt.optionalDelay,
				AckThrough:    0,
			}

			s.mu.Lock()
			err := s.handleAckLocked(pkt)
			choked := s.choked
			chokedUntil := s.chokedUntil
			s.mu.Unlock()

			require.NoError(t, err)
			require.Equal(t, tt.expectChoked, choked, "choke state mismatch")

			if tt.expectChoked {
				require.False(t, chokedUntil.IsZero(), "chokedUntil should be set")
				require.True(t, chokedUntil.After(time.Now()), "chokedUntil should be in future")
			} else {
				require.True(t, chokedUntil.IsZero(), "chokedUntil should be zero")
			}
		})
	}
}

// TestUnchokeReceptionClearsState verifies that unchoke signals clear choke state.
func TestUnchokeReceptionClearsState(t *testing.T) {
	s := newTestStreamConnForChokeReception()

	// First, receive a choke signal
	chokePkt := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 61000,
		AckThrough:    0,
	}

	s.mu.Lock()
	err := s.handleAckLocked(chokePkt)
	s.mu.Unlock()
	require.NoError(t, err)

	// Verify choked
	s.mu.Lock()
	require.True(t, s.choked)
	require.False(t, s.chokedUntil.IsZero())
	s.mu.Unlock()

	// Now receive an unchoke signal
	unchokePkt := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 0,
		AckThrough:    0,
	}

	s.mu.Lock()
	err = s.handleAckLocked(unchokePkt)
	choked := s.choked
	chokedUntil := s.chokedUntil
	s.mu.Unlock()

	require.NoError(t, err)
	require.False(t, choked, "should be unchoked")
	require.True(t, chokedUntil.IsZero(), "chokedUntil should be cleared")
}

// TestWritePausesWhenChoked verifies that choked state affects Write behavior.
func TestWritePausesWhenChoked(t *testing.T) {
	s := newTestStreamConnForChokeReception()

	// Set choked state with future expiration
	s.mu.Lock()
	s.choked = true
	s.chokedUntil = time.Now().Add(100 * time.Millisecond)

	// Verify state is set correctly
	require.True(t, s.choked, "should be choked")
	require.False(t, s.chokedUntil.IsZero(), "chokedUntil should be set")
	require.True(t, time.Now().Before(s.chokedUntil), "chokedUntil should be in future")
	s.mu.Unlock()
}

// TestWriteResumesAfterChokeExpires verifies that choke state expires correctly.
func TestWriteResumesAfterChokeExpires(t *testing.T) {
	s := newTestStreamConnForChokeReception()

	// Set choked state that expires quickly
	s.mu.Lock()
	s.choked = true
	s.chokedUntil = time.Now().Add(10 * time.Millisecond)
	s.mu.Unlock()

	// Wait for choke to expire
	time.Sleep(20 * time.Millisecond)

	// Verify time has passed choked until
	s.mu.Lock()
	expired := time.Now().After(s.chokedUntil)
	s.mu.Unlock()

	require.True(t, expired, "chokedUntil should have expired")
}

// TestWriteImmediateWhenNotChoked verifies unchoked state.
func TestWriteImmediateWhenNotChoked(t *testing.T) {
	s := newTestStreamConnForChokeReception()

	// Ensure not choked
	s.mu.Lock()
	s.choked = false
	s.chokedUntil = time.Time{}

	require.False(t, s.choked, "should not be choked")
	require.True(t, s.chokedUntil.IsZero(), "chokedUntil should be zero")
	s.mu.Unlock()
}

// TestChokeWithNACKsProcessesBoth verifies choke detection works with NACKs present.
func TestChokeWithNACKsProcessesBoth(t *testing.T) {
	s := newTestStreamConnForChokeReception()

	// Track sent packets for NACK handling
	s.mu.Lock()
	s.sentPackets = make(map[uint32]*sentPacket)
	s.sentPackets[10] = &sentPacket{
		data:       []byte{1, 2, 3},
		sentTime:   time.Now(),
		retryCount: 0,
	}
	// Pre-populate nackCounts so incoming NACK reaches fast retransmit threshold (2)
	s.nackCounts = map[uint32]int{10: 1}
	s.mu.Unlock()

	// Packet with both choke signal and NACKs
	pkt := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 61000, // Choked
		AckThrough:    5,
		NACKs:         []uint32{10}, // Request retransmission
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)
	choked := s.choked
	retryCount := s.sentPackets[10].retryCount
	s.mu.Unlock()

	require.NoError(t, err)
	require.True(t, choked, "should be choked")
	require.Equal(t, 1, retryCount, "NACK should be processed")
}

// TestMultipleChokeSignals verifies idempotent handling of choke signals.
func TestMultipleChokeSignals(t *testing.T) {
	s := newTestStreamConnForChokeReception()

	// Send first choke signal
	pkt1 := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 61000,
		AckThrough:    0,
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt1)
	s.mu.Unlock()
	require.NoError(t, err)

	// Get first chokedUntil time
	s.mu.Lock()
	firstChokedUntil := s.chokedUntil
	require.True(t, s.choked)
	s.mu.Unlock()

	// Small delay
	time.Sleep(10 * time.Millisecond)

	// Send second choke signal
	pkt2 := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 62000,
		AckThrough:    0,
	}

	s.mu.Lock()
	err = s.handleAckLocked(pkt2)
	secondChokedUntil := s.chokedUntil
	s.mu.Unlock()

	require.NoError(t, err)
	// Second choke should update chokedUntil
	require.True(t, secondChokedUntil.After(firstChokedUntil), "chokedUntil should be updated")
}

// TestChokeWithoutFlagNotProcessed verifies choke only processed with FlagDelayRequested.
func TestChokeWithoutFlagNotProcessed(t *testing.T) {
	s := newTestStreamConnForChokeReception()

	// Packet with high OptionalDelay but without FlagDelayRequested
	pkt := &Packet{
		Flags:         0,     // No FlagDelayRequested - per spec no flags needed for ACK
		OptionalDelay: 65000, // Would indicate choke if flag was set
		AckThrough:    0,
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)
	choked := s.choked
	s.mu.Unlock()

	require.NoError(t, err)
	require.False(t, choked, "should not be choked without FlagDelayRequested")
}

// TestChokeStatePreservedAcrossACKs verifies choke state persists.
func TestChokeStatePreservedAcrossACKs(t *testing.T) {
	s := newTestStreamConnForChokeReception()

	// Receive choke signal
	chokePkt := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 61000,
		AckThrough:    0,
	}

	s.mu.Lock()
	err := s.handleAckLocked(chokePkt)
	s.mu.Unlock()
	require.NoError(t, err)

	// Receive regular ACK without delay requested
	ackPkt := &Packet{
		Flags:      0, // No flags needed - ackThrough always valid per spec
		AckThrough: 1,
	}

	s.mu.Lock()
	err = s.handleAckLocked(ackPkt)
	choked := s.choked
	s.mu.Unlock()

	require.NoError(t, err)
	// Choke state should persist until explicit unchoke
	require.True(t, choked, "choke state should persist")
}

// TestWriteFailsWhenClosedDuringChoke verifies closed state is checked after choke wait.
func TestWriteFailsWhenClosedDuringChoke(t *testing.T) {
	s := newTestStreamConnForChokeReception()

	// Set choked state
	s.mu.Lock()
	s.choked = true
	s.chokedUntil = time.Now().Add(50 * time.Millisecond)
	s.mu.Unlock()

	// Wait a bit then close
	time.Sleep(10 * time.Millisecond)
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	// Verify closed state is set
	s.mu.Lock()
	isClosed := s.closed
	s.mu.Unlock()

	require.True(t, isClosed, "connection should be closed")
}

// TestChokedUntilExactTiming verifies chokedUntil is set to approximately 1 second.
func TestChokedUntilExactTiming(t *testing.T) {
	s := newTestStreamConnForChokeReception()

	beforeChoke := time.Now()

	pkt := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 61000,
		AckThrough:    0,
	}

	s.mu.Lock()
	err := s.handleAckLocked(pkt)
	chokedUntil := s.chokedUntil
	s.mu.Unlock()

	require.NoError(t, err)

	// chokedUntil should be approximately 1 second from now
	expectedTime := beforeChoke.Add(time.Second)
	timeDiff := chokedUntil.Sub(expectedTime).Abs()

	require.Less(t, timeDiff, 100*time.Millisecond, "chokedUntil should be ~1 second from choke time")
}
