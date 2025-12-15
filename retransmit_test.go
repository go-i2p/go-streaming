package streaming

import (
	"sync"
	"testing"

	"github.com/armon/circbuf"
	"github.com/stretchr/testify/require"
)

// newTestStreamConnForRetransmit creates a minimal StreamConn for testing retransmission.
func newTestStreamConnForRetransmit() *StreamConn {
	recvBuf, _ := circbuf.NewBuffer(1024)
	s := &StreamConn{
		sendSeq:           1,
		recvBuf:           recvBuf,
		outOfOrderPackets: make(map[uint32]*Packet),
		nackList:          []uint32{},
	}
	s.recvCond = sync.NewCond(&s.mu)
	return s
}

// TestSentPacketTracking verifies that packets are tracked in sentPackets map when sent.
func TestSentPacketTracking(t *testing.T) {
	tests := []struct {
		name          string
		hasPayload    bool
		expectTracked bool
	}{
		{
			name:          "data packet is tracked",
			hasPayload:    true,
			expectTracked: true,
		},
		{
			name:          "control packet not tracked",
			hasPayload:    false,
			expectTracked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStreamConnForRetransmit()

			// Create packet with or without payload
			pkt := &Packet{
				SequenceNum: 1,
				Flags:       FlagSYN,
			}
			if tt.hasPayload {
				pkt.Payload = []byte("test data")
			}

			// Send packet
			s.mu.Lock()
			err := s.sendPacketLocked(pkt)
			tracked := s.sentPackets != nil && s.sentPackets[pkt.SequenceNum] != nil
			s.mu.Unlock()

			require.NoError(t, err)
			require.Equal(t, tt.expectTracked, tracked, "packet tracking state")

			// Verify tracked packet has required fields
			if tt.expectTracked {
				s.mu.Lock()
				info := s.sentPackets[pkt.SequenceNum]
				s.mu.Unlock()

				require.NotNil(t, info, "packet should be tracked")
				require.NotEmpty(t, info.data, "tracked packet should have data")
				require.False(t, info.sentTime.IsZero(), "tracked packet should have sentTime")
				require.Equal(t, 0, info.retryCount, "initial retryCount should be 0")
			}
		})
	}
}

// TestNACKRetransmission verifies that packets are retransmitted when NACKs are received.
func TestNACKRetransmission(t *testing.T) {
	s := newTestStreamConnForRetransmit()

	// Send a data packet that will be tracked
	pkt := &Packet{
		SequenceNum: 10,
		Payload:     []byte("test data"),
	}

	s.mu.Lock()
	err := s.sendPacketLocked(pkt)
	s.mu.Unlock()
	require.NoError(t, err)

	// Verify packet is tracked
	s.mu.Lock()
	require.NotNil(t, s.sentPackets, "sentPackets map should exist")
	require.NotNil(t, s.sentPackets[10], "packet should be tracked")
	initialRetryCount := s.sentPackets[10].retryCount
	s.mu.Unlock()

	// Simulate receiving a NACK for this packet
	s.mu.Lock()
	err = s.retransmitPacketLocked(10)
	s.mu.Unlock()
	require.NoError(t, err)

	// Verify retry count incremented
	s.mu.Lock()
	info := s.sentPackets[10]
	s.mu.Unlock()

	require.NotNil(t, info, "packet should still be tracked")
	require.Equal(t, initialRetryCount+1, info.retryCount, "retryCount should increment")
}

// TestMultipleRetransmissions verifies retry count increments correctly.
func TestMultipleRetransmissions(t *testing.T) {
	s := newTestStreamConnForRetransmit()

	// Send and track a packet
	pkt := &Packet{
		SequenceNum: 20,
		Payload:     []byte("test"),
	}

	s.mu.Lock()
	err := s.sendPacketLocked(pkt)
	s.mu.Unlock()
	require.NoError(t, err)

	// Retransmit multiple times
	for i := 1; i <= 3; i++ {
		s.mu.Lock()
		err = s.retransmitPacketLocked(20)
		retryCount := s.sentPackets[20].retryCount
		s.mu.Unlock()

		require.NoError(t, err)
		require.Equal(t, i, retryCount, "retryCount after %d retransmits", i)
	}
}

// TestAckedPacketCleanup verifies that ACKed packets are removed from tracking.
func TestAckedPacketCleanup(t *testing.T) {
	s := newTestStreamConnForRetransmit()

	// Send several packets
	for seq := uint32(1); seq <= 5; seq++ {
		pkt := &Packet{
			SequenceNum: seq,
			Payload:     []byte("test"),
		}
		s.mu.Lock()
		err := s.sendPacketLocked(pkt)
		s.mu.Unlock()
		require.NoError(t, err)
	}

	// Verify all 5 packets are tracked
	s.mu.Lock()
	require.Equal(t, 5, len(s.sentPackets), "all packets should be tracked")
	s.mu.Unlock()

	// ACK through packet 3
	s.mu.Lock()
	s.cleanupAckedPacketsLocked(0, 3)
	remaining := len(s.sentPackets)
	s.mu.Unlock()

	// Verify packets 1-3 removed, 4-5 remain
	require.Equal(t, 2, remaining, "packets 4-5 should remain")

	s.mu.Lock()
	for seq := uint32(1); seq <= 3; seq++ {
		require.Nil(t, s.sentPackets[seq], "packet %d should be cleaned up", seq)
	}
	for seq := uint32(4); seq <= 5; seq++ {
		require.NotNil(t, s.sentPackets[seq], "packet %d should still be tracked", seq)
	}
	s.mu.Unlock()

	// ACK through packet 5
	s.mu.Lock()
	s.cleanupAckedPacketsLocked(3, 5)
	remaining = len(s.sentPackets)
	s.mu.Unlock()

	require.Equal(t, 0, remaining, "all packets should be cleaned up")
}

// TestCleanupWithNoTrackedPackets verifies cleanup handles empty state gracefully.
func TestCleanupWithNoTrackedPackets(t *testing.T) {
	s := newTestStreamConnForRetransmit()

	// Call cleanup with no tracked packets
	s.mu.Lock()
	s.cleanupAckedPacketsLocked(0, 10)
	s.mu.Unlock()

	// Should not panic or error
}

// TestRetransmitMissingPacket verifies handling of NACK for non-existent packet.
func TestRetransmitMissingPacket(t *testing.T) {
	s := newTestStreamConnForRetransmit()

	// Try to retransmit a packet that was never sent
	s.mu.Lock()
	err := s.retransmitPacketLocked(999)
	s.mu.Unlock()

	// Should return nil (already ACKed case)
	require.NoError(t, err, "retransmit missing packet should not error")
}

// TestMultipleNACKsInOneACK verifies handling of multiple NACKs in a single ACK packet.
func TestMultipleNACKsInOneACK(t *testing.T) {
	s := newTestStreamConnForRetransmit()

	// Send packets 10, 11, 12
	for seq := uint32(10); seq <= 12; seq++ {
		pkt := &Packet{
			SequenceNum: seq,
			Payload:     []byte("test"),
		}
		s.mu.Lock()
		err := s.sendPacketLocked(pkt)
		s.mu.Unlock()
		require.NoError(t, err)
	}

	// Simulate receiving ACK with multiple NACKs
	nacks := []uint32{10, 11, 12}
	s.mu.Lock()
	for _, nack := range nacks {
		err := s.retransmitPacketLocked(nack)
		require.NoError(t, err)
	}

	// Verify all packets were retransmitted
	for _, seq := range nacks {
		info := s.sentPackets[seq]
		require.NotNil(t, info, "packet %d should be tracked", seq)
		require.Equal(t, 1, info.retryCount, "packet %d should be retransmitted once", seq)
	}
	s.mu.Unlock()
}

// TestNACKAfterPartialACK verifies NACK handling when some packets are ACKed.
func TestNACKAfterPartialACK(t *testing.T) {
	s := newTestStreamConnForRetransmit()

	// Send packets 1-5
	for seq := uint32(1); seq <= 5; seq++ {
		pkt := &Packet{
			SequenceNum: seq,
			Payload:     []byte("test"),
		}
		s.mu.Lock()
		err := s.sendPacketLocked(pkt)
		s.mu.Unlock()
		require.NoError(t, err)
	}

	// ACK through packet 2, NACK packet 1 (should already be cleaned)
	s.mu.Lock()
	s.cleanupAckedPacketsLocked(0, 2)
	err := s.retransmitPacketLocked(1) // Already ACKed
	s.mu.Unlock()

	// Should not error (returns nil for missing packet)
	require.NoError(t, err, "retransmit already ACKed packet should not error")

	// NACK packet 3 (should still be tracked)
	s.mu.Lock()
	err = s.retransmitPacketLocked(3)
	retryCount := 0
	if s.sentPackets[3] != nil {
		retryCount = s.sentPackets[3].retryCount
	}
	s.mu.Unlock()

	require.NoError(t, err)
	require.Equal(t, 1, retryCount, "packet 3 should be retransmitted once")
}

// TestSentPacketDataIntegrity verifies that stored packet data can be retransmitted.
func TestSentPacketDataIntegrity(t *testing.T) {
	s := newTestStreamConnForRetransmit()

	payload := []byte("important data")
	pkt := &Packet{
		SequenceNum: 100,
		Payload:     payload,
	}

	// Send packet
	s.mu.Lock()
	err := s.sendPacketLocked(pkt)
	s.mu.Unlock()
	require.NoError(t, err)

	// Verify stored data is marshalable packet
	s.mu.Lock()
	info := s.sentPackets[100]
	s.mu.Unlock()

	require.NotNil(t, info, "packet should be tracked")
	require.NotEmpty(t, info.data, "stored packet data should not be empty")

	// Verify we can unmarshal the stored data
	var unmarshaled Packet
	err = unmarshaled.Unmarshal(info.data)
	require.NoError(t, err)

	// Verify unmarshaled packet matches original
	require.Equal(t, pkt.SequenceNum, unmarshaled.SequenceNum, "sequence number should match")
	require.Equal(t, payload, unmarshaled.Payload, "payload should match")
}
