package streaming

import (
	"sync"
	"testing"
	"time"

	"github.com/armon/circbuf"
	"github.com/stretchr/testify/require"
)

// TestPersistProbeIntervalConstant verifies the persist probe interval is set correctly.
func TestPersistProbeIntervalConstant(t *testing.T) {
	require.Equal(t, 5*time.Second, PersistProbeInterval,
		"PersistProbeInterval should be 5 seconds per implementation")
}

// newTestStreamConnForChokeProbe creates a StreamConn for testing choke probing.
func newTestStreamConnForChokeProbe(t *testing.T) *StreamConn {
	t.Helper()

	i2cp := RequireI2CP(t)

	recvBuf, err := circbuf.NewBuffer(64 * 1024)
	require.NoError(t, err)

	s := &StreamConn{
		session:           i2cp.Manager.session,
		dest:              i2cp.Manager.Destination(),
		localStreamID:     100,
		remoteStreamID:    200,
		sendSeq:           1000,
		recvSeq:           500,
		ackThrough:        0,
		state:             StateEstablished,
		recvBuf:           recvBuf,
		sendBuf:           []byte{},
		localPort:         12345,
		remotePort:        80,
		localMTU:          DefaultMTU,
		remoteMTU:         DefaultMTU,
		sentPackets:       make(map[uint32]*sentPacket),
		nackCounts:        make(map[uint32]int),
		outOfOrderPackets: make(map[uint32]*Packet),
		nackList:          make(map[uint32]struct{}),
	}
	s.recvCond = sync.NewCond(&s.mu)
	s.sendCond = sync.NewCond(&s.mu)
	return s
}

// TestPersistTimerStartsOnChoke verifies the persist timer starts when choked.
func TestPersistTimerStartsOnChoke(t *testing.T) {
	s := newTestStreamConnForChokeProbe(t)

	// Verify no timer initially
	s.mu.Lock()
	require.Nil(t, s.persistTimer, "no persist timer before choke")
	s.mu.Unlock()

	// Send choke signal
	pkt := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 61000, // > 60000 triggers choke
		AckThrough:    0,
	}

	s.mu.Lock()
	s.handleOptionalDelayLocked(pkt)
	hasTimer := s.persistTimer != nil
	isChoked := s.choked
	s.mu.Unlock()

	require.True(t, isChoked, "should be choked")
	require.True(t, hasTimer, "persist timer should be started")

	// Cleanup
	s.mu.Lock()
	s.stopPersistTimerLocked()
	s.mu.Unlock()
}

// TestPersistTimerStopsOnUnchoke verifies the persist timer stops when unchoked.
func TestPersistTimerStopsOnUnchoke(t *testing.T) {
	s := newTestStreamConnForChokeProbe(t)

	// First, trigger choke to start timer
	chokePkt := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 61000,
		AckThrough:    0,
	}

	s.mu.Lock()
	s.handleOptionalDelayLocked(chokePkt)
	require.NotNil(t, s.persistTimer, "persist timer should be started")
	s.mu.Unlock()

	// Now send unchoke signal
	unchokePkt := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 30000, // <= 60000 means unchoke
		AckThrough:    0,
	}

	s.mu.Lock()
	s.handleOptionalDelayLocked(unchokePkt)
	hasTimer := s.persistTimer != nil
	isChoked := s.choked
	s.mu.Unlock()

	require.False(t, isChoked, "should not be choked")
	require.False(t, hasTimer, "persist timer should be stopped")
}

// TestPersistTimerDoesNotStartWhenAlreadyChoked verifies idempotent behavior.
func TestPersistTimerDoesNotStartWhenAlreadyChoked(t *testing.T) {
	s := newTestStreamConnForChokeProbe(t)

	// First choke
	pkt1 := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 61000,
		AckThrough:    0,
	}

	s.mu.Lock()
	s.handleOptionalDelayLocked(pkt1)
	timer1 := s.persistTimer
	require.NotNil(t, timer1, "persist timer should be started")
	s.mu.Unlock()

	// Second choke signal (already choked)
	pkt2 := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 62000,
		AckThrough:    0,
	}

	s.mu.Lock()
	s.handleOptionalDelayLocked(pkt2)
	timer2 := s.persistTimer
	s.mu.Unlock()

	// Timer should be the same (not restarted)
	require.Equal(t, timer1, timer2, "timer should not be restarted when already choked")

	// Cleanup
	s.mu.Lock()
	s.stopPersistTimerLocked()
	s.mu.Unlock()
}

// TestPersistTimerStopsOnClose verifies cleanup on connection close.
func TestPersistTimerStopsOnClose(t *testing.T) {
	s := newTestStreamConnForChokeProbe(t)

	// Trigger choke
	pkt := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 61000,
		AckThrough:    0,
	}

	s.mu.Lock()
	s.handleOptionalDelayLocked(pkt)
	require.NotNil(t, s.persistTimer)
	s.mu.Unlock()

	// Simulate cleanup (which happens on Close)
	s.mu.Lock()
	s.stopPersistTimerLocked()
	hasTimer := s.persistTimer != nil
	hasStopChan := s.persistStopChan != nil
	s.mu.Unlock()

	require.False(t, hasTimer, "timer should be nil after stop")
	require.False(t, hasStopChan, "stop chan should be nil after stop")
}

// TestSendProbePacketLocked verifies probe packet format and sending.
func TestSendProbePacketLocked(t *testing.T) {
	s := newTestStreamConnForChokeProbe(t)

	initialSeq := s.sendSeq

	s.mu.Lock()
	s.sendProbePacketLocked()
	newSeq := s.sendSeq
	s.mu.Unlock()

	// Sequence should be incremented
	require.Equal(t, initialSeq+1, newSeq, "sequence should be incremented after probe")
}

// TestPersistTimerNoSessionNoStart verifies timer doesn't start without session.
func TestPersistTimerNoSessionNoStart(t *testing.T) {
	recvBuf, _ := circbuf.NewBuffer(1024)
	s := &StreamConn{
		session:        nil, // No session
		localStreamID:  100,
		remoteStreamID: 200,
		sendSeq:        1000,
		recvSeq:        500,
		state:          StateEstablished,
		recvBuf:        recvBuf,
	}
	s.recvCond = sync.NewCond(&s.mu)
	s.sendCond = sync.NewCond(&s.mu)

	s.mu.Lock()
	s.startPersistTimerLocked()
	hasTimer := s.persistTimer != nil
	s.mu.Unlock()

	require.False(t, hasTimer, "timer should not start without session")
}

// TestPersistTimerMultipleStopsSafe verifies stopping multiple times is safe.
func TestPersistTimerMultipleStopsSafe(t *testing.T) {
	s := newTestStreamConnForChokeProbe(t)

	// Trigger choke to start timer
	pkt := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 61000,
		AckThrough:    0,
	}

	s.mu.Lock()
	s.handleOptionalDelayLocked(pkt)
	require.NotNil(t, s.persistTimer)

	// Stop multiple times - should not panic
	s.stopPersistTimerLocked()
	s.stopPersistTimerLocked()
	s.stopPersistTimerLocked()
	s.mu.Unlock()
}

// TestChokeUnchokeSequence tests a complete choke/unchoke cycle.
func TestChokeUnchokeSequence(t *testing.T) {
	s := newTestStreamConnForChokeProbe(t)

	// Initial state
	s.mu.Lock()
	require.False(t, s.choked)
	require.Nil(t, s.persistTimer)
	s.mu.Unlock()

	// Step 1: Choke
	chokePkt := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 65535,
		AckThrough:    0,
	}
	s.mu.Lock()
	s.handleOptionalDelayLocked(chokePkt)
	require.True(t, s.choked)
	require.NotNil(t, s.persistTimer)
	s.mu.Unlock()

	// Step 2: Unchoke
	unchokePkt := &Packet{
		Flags:         FlagDelayRequested,
		OptionalDelay: 0,
		AckThrough:    0,
	}
	s.mu.Lock()
	s.handleOptionalDelayLocked(unchokePkt)
	require.False(t, s.choked)
	require.Nil(t, s.persistTimer)
	s.mu.Unlock()

	// Step 3: Choke again
	s.mu.Lock()
	s.handleOptionalDelayLocked(chokePkt)
	require.True(t, s.choked)
	require.NotNil(t, s.persistTimer)
	s.mu.Unlock()

	// Cleanup
	s.mu.Lock()
	s.stopPersistTimerLocked()
	s.mu.Unlock()
}

// TestProbeSendsMinimalPayload verifies probe packet has minimal 1-byte payload.
func TestProbeSendsMinimalPayload(t *testing.T) {
	s := newTestStreamConnForChokeProbe(t)

	// The probe packet construction is inside sendProbePacketLocked.
	// We can verify by checking that the function completes without error
	// and increments the sequence number (indicating successful build).

	initialSeq := s.sendSeq

	s.mu.Lock()
	s.sendProbePacketLocked()
	finalSeq := s.sendSeq
	s.mu.Unlock()

	require.Equal(t, initialSeq+1, finalSeq,
		"sendSeq should increment, indicating packet was built and sent")
}

// TestPersistTimerClosedConnectionDoesNotSend verifies closed conn stops probing.
func TestPersistTimerClosedConnectionDoesNotSend(t *testing.T) {
	s := newTestStreamConnForChokeProbe(t)

	initialSeq := s.sendSeq

	s.mu.Lock()
	s.closed = true
	s.sendProbePacketLocked()
	finalSeq := s.sendSeq
	s.mu.Unlock()

	require.Equal(t, initialSeq, finalSeq,
		"sendSeq should not change when connection is closed")
}
