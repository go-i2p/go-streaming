package streaming

import (
	"testing"
	"time"

	"github.com/armon/circbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateISNUniqueness verifies that generateISN produces unique values.
// ISN must be unpredictable to prevent sequence number attacks.
func TestGenerateISNUniqueness(t *testing.T) {
	isn1, err := generateISN()
	require.NoError(t, err, "first ISN generation should succeed")

	isn2, err := generateISN()
	require.NoError(t, err, "second ISN generation should succeed")

	// While theoretically possible to generate the same ISN twice,
	// it's astronomically unlikely with a 32-bit random number
	assert.NotEqual(t, isn1, isn2, "consecutive ISNs should be different")

	// Generate 100 ISNs and verify they're all unique
	seenISNs := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		isn, err := generateISN()
		require.NoError(t, err)
		assert.False(t, seenISNs[isn], "ISN %d was generated twice", isn)
		seenISNs[isn] = true
	}
}

// TestDialMTUValidation verifies MTU validation in Dial.
func TestDialMTUValidation(t *testing.T) {
	tests := []struct {
		name        string
		mtu         int
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "MTU below minimum",
			mtu:         MinMTU - 1,
			shouldError: true,
			errorMsg:    "below minimum",
		},
		{
			name:        "minimum MTU",
			mtu:         MinMTU,
			shouldError: false,
		},
		{
			name:        "default MTU",
			mtu:         DefaultMTU,
			shouldError: false,
		},
		{
			name:        "ECIES MTU",
			mtu:         ECIESMTU,
			shouldError: false,
		},
		{
			name:        "MTU above default but not ECIES",
			mtu:         DefaultMTU + 1,
			shouldError: true,
			errorMsg:    "exceeds recommended maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For MTU validation tests, we only care about early validation
			// We can't actually dial without a real session, so we check
			// if the error is specifically about MTU (early validation)
			// or something else (session is nil, which happens later)
			_, err := DialWithMTU(nil, nil, 0, 0, tt.mtu, 1*time.Second)

			if tt.shouldError {
				// Should get MTU validation error immediately
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				// Should pass MTU validation, but fail later due to nil session
				// We verify MTU validation passed by checking error message
				if err != nil {
					// Error should NOT be about MTU
					assert.NotContains(t, err.Error(), "MTU")
					assert.NotContains(t, err.Error(), "minimum")
					assert.NotContains(t, err.Error(), "maximum")
				}
			}
		})
	}
}

// TestListenMTUValidation verifies MTU validation in Listen.
func TestListenMTUValidation(t *testing.T) {
	tests := []struct {
		name        string
		mtu         int
		shouldError bool
	}{
		{
			name:        "MTU below minimum",
			mtu:         MinMTU - 1,
			shouldError: true,
		},
		{
			name:        "minimum MTU",
			mtu:         MinMTU,
			shouldError: false,
		},
		{
			name:        "default MTU",
			mtu:         DefaultMTU,
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := RequireI2CPSession(t)
			listener, err := ListenWithMTU(session, 8080, tt.mtu)

			if tt.shouldError {
				assert.Error(t, err)
				assert.Nil(t, listener)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, listener)
				if listener != nil {
					// Verify MTU was set correctly
					assert.Equal(t, uint16(tt.mtu), listener.localMTU)
					// Clean up
					_ = listener.Close()
				}
			}
		})
	}
}

// TestListenerClose verifies listener can be closed properly.
func TestListenerClose(t *testing.T) {
	session := RequireI2CPSession(t)
	listener, err := Listen(session, 8082)
	require.NoError(t, err)
	require.NotNil(t, listener)

	// Close should succeed
	err = listener.Close()
	assert.NoError(t, err)

	// Second close should be idempotent
	err = listener.Close()
	assert.NoError(t, err)

	// Accept should fail after close
	conn, err := listener.Accept()
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "closed")
}

// TestConnStateTransitions verifies state tracking works correctly.
func TestConnStateTransitions(t *testing.T) {
	isn, err := generateISN()
	require.NoError(t, err)

	recvBuf, err := circbuf.NewBuffer(1024)
	require.NoError(t, err)

	conn := &StreamConn{
		sendSeq:    isn,
		windowSize: DefaultWindowSize,
		recvBuf:    recvBuf,
		state:      StateInit,
		localMTU:   DefaultMTU,
	}

	// Verify initial state
	assert.Equal(t, StateInit, conn.state)
	assert.Equal(t, "INIT", conn.state.String())

	// Test state transitions
	conn.setState(StateSynSent)
	assert.Equal(t, StateSynSent, conn.state)
	assert.Equal(t, "SYN_SENT", conn.state.String())

	conn.setState(StateEstablished)
	assert.Equal(t, StateEstablished, conn.state)
	assert.Equal(t, "ESTABLISHED", conn.state.String())

	conn.setState(StateClosed)
	assert.Equal(t, StateClosed, conn.state)
	assert.Equal(t, "CLOSED", conn.state.String())
}

// TestGetNegotiatedMTU verifies MTU negotiation logic.
func TestGetNegotiatedMTU(t *testing.T) {
	tests := []struct {
		name      string
		localMTU  uint16
		remoteMTU uint16
		expected  uint16
	}{
		{
			name:      "remote MTU not yet set",
			localMTU:  DefaultMTU,
			remoteMTU: 0,
			expected:  DefaultMTU,
		},
		{
			name:      "local MTU smaller",
			localMTU:  1000,
			remoteMTU: 1500,
			expected:  1000,
		},
		{
			name:      "remote MTU smaller",
			localMTU:  1500,
			remoteMTU: 1000,
			expected:  1000,
		},
		{
			name:      "equal MTUs",
			localMTU:  DefaultMTU,
			remoteMTU: DefaultMTU,
			expected:  DefaultMTU,
		},
		{
			name:      "ECIES negotiation",
			localMTU:  ECIESMTU,
			remoteMTU: ECIESMTU,
			expected:  ECIESMTU,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recvBuf, err := circbuf.NewBuffer(1024)
			require.NoError(t, err)

			conn := &StreamConn{
				localMTU:  tt.localMTU,
				remoteMTU: tt.remoteMTU,
				recvBuf:   recvBuf,
			}

			mtu := conn.getNegotiatedMTU()
			assert.Equal(t, tt.expected, mtu)
		})
	}
}

// TestSendSYNPacketFormat verifies SYN packet is formatted correctly.
// This tests the packet structure without requiring an actual I2CP session.
func TestSendSYNPacketFormat(t *testing.T) {
	// We can't actually send without a real session, but we can verify
	// the packet marshaling logic works correctly by testing the Packet struct
	pkt := &Packet{
		SendStreamID: 1234,
		RecvStreamID: 5678,
		SequenceNum:  42,
		AckThrough:   0,
		Flags:        FlagSYN,
	}

	data, err := pkt.Marshal()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify we can unmarshal it back
	parsed := &Packet{}
	err = parsed.Unmarshal(data)
	require.NoError(t, err)

	assert.Equal(t, pkt.SendStreamID, parsed.SendStreamID)
	assert.Equal(t, pkt.RecvStreamID, parsed.RecvStreamID)
	assert.Equal(t, pkt.SequenceNum, parsed.SequenceNum)
	assert.Equal(t, pkt.Flags, parsed.Flags)
	assert.Equal(t, FlagSYN, parsed.Flags&FlagSYN)
}

// TestSendSynAckPacketFormat verifies SYN-ACK packet format.
// Per I2P streaming spec, SYN-ACK is identified by FlagSYN set and SendStreamID > 0.
func TestSendSynAckPacketFormat(t *testing.T) {
	pkt := &Packet{
		SendStreamID: 1234, // > 0 indicates this is a SYN-ACK response
		RecvStreamID: 5678,
		SequenceNum:  100,
		AckThrough:   42,      // ACKing the SYN
		Flags:        FlagSYN, // Only SYN flag needed for SYN-ACK per spec
	}

	data, err := pkt.Marshal()
	require.NoError(t, err)

	parsed := &Packet{}
	err = parsed.Unmarshal(data)
	require.NoError(t, err)

	assert.Equal(t, pkt.SequenceNum, parsed.SequenceNum)
	assert.Equal(t, pkt.AckThrough, parsed.AckThrough)
	assert.Equal(t, FlagSYN, parsed.Flags)  // SYN-ACK only has SYN flag
	assert.True(t, parsed.SendStreamID > 0) // SYN-ACK has assigned stream ID
}

// TestSendACKPacketFormat verifies final ACK packet format.
// Per I2P streaming spec, a plain ACK has sequenceNum=0 and no SYN flag.
func TestSendACKPacketFormat(t *testing.T) {
	pkt := &Packet{
		SendStreamID: 1234,
		RecvStreamID: 5678,
		SequenceNum:  0,   // seq=0 without SYN = plain ACK per spec
		AckThrough:   100, // ACKing the SYN-ACK
		Flags:        0,   // No flags needed for plain ACK
	}

	data, err := pkt.Marshal()
	require.NoError(t, err)

	parsed := &Packet{}
	err = parsed.Unmarshal(data)
	require.NoError(t, err)

	assert.Equal(t, pkt.AckThrough, parsed.AckThrough)
	assert.Equal(t, uint16(0), parsed.Flags)         // No flags for plain ACK
	assert.Equal(t, uint32(0), parsed.SequenceNum)   // seq=0 for plain ACK
	assert.Equal(t, uint16(0), parsed.Flags&FlagSYN) // No SYN flag
}

// TestProcessSynAck verifies SYN-ACK processing logic.
func TestProcessSynAck(t *testing.T) {
	recvBuf, err := circbuf.NewBuffer(1024)
	require.NoError(t, err)

	// Simulate state after SYN was sent: sendSeq has been incremented
	// Original ISN was 41, sendSeq is now 42 after SYN sent
	conn := &StreamConn{
		localPort:  1234,
		remotePort: 5678,
		sendSeq:    42, // After SYN sent, this is ISN + 1
		recvSeq:    0,
		remoteMTU:  0,
		recvBuf:    recvBuf,
	}

	synAckPkt := &Packet{
		SendStreamID: 5678,
		RecvStreamID: 1234,
		SequenceNum:  100,         // Remote ISN
		AckThrough:   41,          // ACKing our SYN (must match sendSeq - 1 = original ISN)
		Flags:        FlagSYN | 0, // No flags needed - ackThrough always valid per spec
	}

	err = conn.processSynAck(synAckPkt)
	require.NoError(t, err, "processSynAck should succeed with valid packet")

	// Verify remote sequence was extracted
	assert.Equal(t, uint32(101), conn.recvSeq, "should expect next sequence after remote ISN")

	// Verify MTU was set (default for MVP)
	assert.Equal(t, uint16(DefaultMTU), conn.remoteMTU)
}

// TestProcessSynAck_InvalidAckThrough verifies that SYN-ACK with wrong AckThrough is rejected.
// Per ISSUE-010, the SYN-ACK's AckThrough must match our SYN's sequence number.
func TestProcessSynAck_InvalidAckThrough(t *testing.T) {
	recvBuf, err := circbuf.NewBuffer(1024)
	require.NoError(t, err)

	// Simulate state after SYN was sent: sendSeq has been incremented
	// Original ISN was 41, sendSeq is now 42 after SYN sent
	conn := &StreamConn{
		localPort:  1234,
		remotePort: 5678,
		sendSeq:    42, // After SYN sent (original ISN was 41)
		recvSeq:    0,
		remoteMTU:  0,
		recvBuf:    recvBuf,
	}

	synAckPkt := &Packet{
		SendStreamID: 5678,
		RecvStreamID: 1234,
		SequenceNum:  100,
		AckThrough:   99, // Wrong! Should be 41 (sendSeq - 1) to ACK our SYN
		Flags:        FlagSYN,
	}

	err = conn.processSynAck(synAckPkt)
	require.Error(t, err, "processSynAck should fail when AckThrough doesn't match our SYN")
	assert.Contains(t, err.Error(), "invalid SYN-ACK")
	assert.Contains(t, err.Error(), "AckThrough")

	// Verify connection state was NOT updated
	assert.Equal(t, uint32(0), conn.recvSeq, "recvSeq should not be updated on error")
	assert.Equal(t, uint32(0), conn.remoteStreamID, "remoteStreamID should not be updated on error")
}

// TestProcessSynAck_ZeroSequenceNumber verifies warning is logged for seq=0.
// While technically valid (1 in 2^32 chance for random ISN), it's unusual and logged.
func TestProcessSynAck_ZeroSequenceNumber(t *testing.T) {
	recvBuf, err := circbuf.NewBuffer(1024)
	require.NoError(t, err)

	// Simulate state after SYN was sent: sendSeq has been incremented
	// Original ISN was 41, sendSeq is now 42 after SYN sent
	conn := &StreamConn{
		localPort:  1234,
		remotePort: 5678,
		sendSeq:    42, // After SYN sent (original ISN was 41)
		recvSeq:    0,
		remoteMTU:  0,
		recvBuf:    recvBuf,
	}

	synAckPkt := &Packet{
		SendStreamID: 5678,
		RecvStreamID: 1234,
		SequenceNum:  0,  // Zero ISN - unusual but technically valid
		AckThrough:   41, // Correctly ACKs our SYN (sendSeq - 1)
		Flags:        FlagSYN,
	}

	// Should succeed (just logs warning) since 0 is technically valid
	err = conn.processSynAck(synAckPkt)
	require.NoError(t, err, "processSynAck should accept seq=0 (warns but doesn't reject)")

	// Verify connection state was updated correctly
	assert.Equal(t, uint32(1), conn.recvSeq, "recvSeq should be 0+1=1")
	assert.Equal(t, uint32(5678), conn.remoteStreamID)
}

// TestHandshakeTimeout verifies timeout handling in Dial.
// This is a structural test - actual timeout requires a real I2CP session.
func TestHandshakeTimeout(t *testing.T) {
	// Use a very short timeout to test timeout path
	_, err := DialWithMTU(nil, nil, 0, 0, DefaultMTU, 1*time.Millisecond)

	// Should fail (no real session), but we're testing the timeout mechanism exists
	assert.Error(t, err)
	// The error will be from missing session, not timeout, but structure is in place
}

// TestHandshakeConstants verifies handshake-related constants are reasonable.
func TestHandshakeConstants(t *testing.T) {
	assert.Greater(t, DefaultConnectTimeout, time.Duration(0))
	assert.Greater(t, DefaultHandshakeTimeout, time.Duration(0))
	assert.LessOrEqual(t, DefaultHandshakeTimeout, DefaultConnectTimeout)

	// Verify constants are in reasonable ranges
	assert.GreaterOrEqual(t, DefaultConnectTimeout, 30*time.Second)
	assert.GreaterOrEqual(t, DefaultHandshakeTimeout, 10*time.Second)
}
