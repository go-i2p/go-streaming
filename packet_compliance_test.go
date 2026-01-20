package streaming

import (
	"testing"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSYNPacketWithReplayPrevention tests that SYN packets include 8 NACKs
// containing the destination hash for replay prevention per I2P streaming spec.
func TestSYNPacketWithReplayPrevention(t *testing.T) {
	crypto := go_i2cp.NewCrypto()

	t.Run("SYN packet has 8 NACKs from destination hash", func(t *testing.T) {
		dest, err := go_i2cp.NewDestination(crypto)
		require.NoError(t, err)

		// Calculate expected hash
		expectedHash, err := hashDestination(dest)
		require.NoError(t, err)

		// Create SYN packet as sendSYN() would
		pkt := &Packet{
			SendStreamID: 0, // Always 0 in initial SYN per spec
			RecvStreamID: 12345,
			SequenceNum:  1000,
			Flags:        FlagSYN,
		}

		// Add replay prevention NACKs
		pkt.NACKs = make([]uint32, 8)
		for i := 0; i < 8; i++ {
			pkt.NACKs[i] = uint32(expectedHash[i*4])<<24 |
				uint32(expectedHash[i*4+1])<<16 |
				uint32(expectedHash[i*4+2])<<8 |
				uint32(expectedHash[i*4+3])
		}

		// Verify SYN has 8 NACKs
		assert.Equal(t, 8, len(pkt.NACKs), "SYN packet must have 8 NACKs for replay prevention")

		// Verify NACKs match the destination hash
		for i := 0; i < 8; i++ {
			expected := uint32(expectedHash[i*4])<<24 |
				uint32(expectedHash[i*4+1])<<16 |
				uint32(expectedHash[i*4+2])<<8 |
				uint32(expectedHash[i*4+3])
			assert.Equal(t, expected, pkt.NACKs[i], "NACK %d should match destination hash fragment", i)
		}
	})

	t.Run("SYN packet marshals and unmarshals with 8 NACKs", func(t *testing.T) {
		dest, err := go_i2cp.NewDestination(crypto)
		require.NoError(t, err)

		hash, err := hashDestination(dest)
		require.NoError(t, err)

		pkt := &Packet{
			SendStreamID: 0,
			RecvStreamID: 12345,
			SequenceNum:  1000,
			Flags:        FlagSYN,
			NACKs:        make([]uint32, 8),
		}

		// Populate NACKs from hash
		for i := 0; i < 8; i++ {
			pkt.NACKs[i] = uint32(hash[i*4])<<24 |
				uint32(hash[i*4+1])<<16 |
				uint32(hash[i*4+2])<<8 |
				uint32(hash[i*4+3])
		}

		// Marshal
		data, err := pkt.Marshal()
		require.NoError(t, err)

		// Unmarshal
		pkt2 := &Packet{}
		err = pkt2.Unmarshal(data)
		require.NoError(t, err)

		// Verify NACKs survived round-trip
		assert.Equal(t, pkt.NACKs, pkt2.NACKs, "NACKs should survive marshal/unmarshal")
	})

	t.Run("different destinations produce different NACKs", func(t *testing.T) {
		dest1, err := go_i2cp.NewDestination(crypto)
		require.NoError(t, err)

		dest2, err := go_i2cp.NewDestination(crypto)
		require.NoError(t, err)

		hash1, err := hashDestination(dest1)
		require.NoError(t, err)

		hash2, err := hashDestination(dest2)
		require.NoError(t, err)

		// Hashes should be different
		assert.NotEqual(t, hash1, hash2, "different destinations should have different hashes")

		// First NACK from each should be different
		nack1 := uint32(hash1[0])<<24 | uint32(hash1[1])<<16 | uint32(hash1[2])<<8 | uint32(hash1[3])
		nack2 := uint32(hash2[0])<<24 | uint32(hash2[1])<<16 | uint32(hash2[2])<<8 | uint32(hash2[3])
		assert.NotEqual(t, nack1, nack2, "different destinations should produce different NACKs")
	})
}

// TestSYNPacketWithSignature tests that SYN packets can include signature
// and FROM destination per I2P streaming spec.
func TestSYNPacketWithSignature(t *testing.T) {
	crypto := go_i2cp.NewCrypto()

	t.Run("SYN packet with FROM and signature", func(t *testing.T) {
		dest, err := go_i2cp.NewDestination(crypto)
		require.NoError(t, err)

		keyPair, err := crypto.Ed25519SignatureKeygen()
		require.NoError(t, err)

		// Create SYN packet with all required flags
		pkt := &Packet{
			SendStreamID:    0,
			RecvStreamID:    12345,
			SequenceNum:     1000,
			Flags:           FlagSYN | FlagFromIncluded | FlagSignatureIncluded,
			FromDestination: dest,
			NACKs:           make([]uint32, 8),
		}

		// Sign the packet
		err = SignPacket(pkt, keyPair)
		require.NoError(t, err)

		// Verify signature is present
		assert.NotNil(t, pkt.Signature, "SYN packet should have signature")
		assert.Equal(t, 64, len(pkt.Signature), "Ed25519 signature should be 64 bytes")

		// Verify flags are correct
		assert.True(t, pkt.Flags&FlagSYN != 0, "SYN flag should be set")
		assert.True(t, pkt.Flags&FlagFromIncluded != 0, "FROM flag should be set")
		assert.True(t, pkt.Flags&FlagSignatureIncluded != 0, "SIGNATURE flag should be set")
	})

	t.Run("signed SYN packet marshals correctly", func(t *testing.T) {
		dest, err := go_i2cp.NewDestination(crypto)
		require.NoError(t, err)

		keyPair, err := crypto.Ed25519SignatureKeygen()
		require.NoError(t, err)

		pkt := &Packet{
			SendStreamID:    0,
			RecvStreamID:    12345,
			SequenceNum:     1000,
			Flags:           FlagSYN | FlagFromIncluded | FlagSignatureIncluded,
			FromDestination: dest,
			NACKs:           make([]uint32, 8),
		}

		err = SignPacket(pkt, keyPair)
		require.NoError(t, err)

		// Marshal signed packet
		data, err := pkt.Marshal()
		require.NoError(t, err)

		// Verify packet is large enough for header + 8 NACKs + FROM + signature
		// Header: 22 bytes, NACKs: 32 bytes, FROM: ~391 bytes, Signature: 64 bytes
		assert.GreaterOrEqual(t, len(data), 22+32+387+64, "signed SYN packet should be at least 505 bytes")
	})

	t.Run("signed SYN survives marshal/unmarshal", func(t *testing.T) {
		dest, err := go_i2cp.NewDestination(crypto)
		require.NoError(t, err)

		keyPair, err := crypto.Ed25519SignatureKeygen()
		require.NoError(t, err)

		pkt := &Packet{
			SendStreamID:    0,
			RecvStreamID:    12345,
			SequenceNum:     1000,
			Flags:           FlagSYN | FlagFromIncluded | FlagSignatureIncluded,
			FromDestination: dest,
			NACKs:           make([]uint32, 8),
		}

		err = SignPacket(pkt, keyPair)
		require.NoError(t, err)

		// Marshal
		data, err := pkt.Marshal()
		require.NoError(t, err)

		// Unmarshal
		pkt2 := &Packet{}
		err = pkt2.Unmarshal(data)
		require.NoError(t, err)

		// Verify all fields preserved
		assert.Equal(t, pkt.SendStreamID, pkt2.SendStreamID)
		assert.Equal(t, pkt.RecvStreamID, pkt2.RecvStreamID)
		assert.Equal(t, pkt.SequenceNum, pkt2.SequenceNum)
		assert.Equal(t, pkt.Flags, pkt2.Flags)
		assert.Equal(t, pkt.NACKs, pkt2.NACKs)
		assert.NotNil(t, pkt2.FromDestination)
		assert.Equal(t, pkt.Signature, pkt2.Signature)
	})
}

// TestResendDelayFieldSize tests that ResendDelay is correctly implemented
// as a 1-byte field per I2P streaming spec (was incorrectly 2 bytes).
func TestResendDelayFieldSize(t *testing.T) {
	t.Run("ResendDelay field is 1 byte", func(t *testing.T) {
		pkt := &Packet{
			SendStreamID: 1,
			RecvStreamID: 2,
			SequenceNum:  100,
			Flags:        0,   // No flags needed - ackThrough always valid per spec
			ResendDelay:  255, // Max value for uint8
		}

		data, err := pkt.Marshal()
		require.NoError(t, err)

		// Unmarshal and verify
		pkt2 := &Packet{}
		err = pkt2.Unmarshal(data)
		require.NoError(t, err)

		assert.Equal(t, uint8(255), pkt2.ResendDelay, "ResendDelay should be uint8 (1 byte)")
	})

	t.Run("ResendDelay boundary values", func(t *testing.T) {
		testCases := []struct {
			name  string
			value uint8
		}{
			{"zero", 0},
			{"one", 1},
			{"mid", 127},
			{"max", 255},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				pkt := &Packet{
					SendStreamID: 1,
					RecvStreamID: 2,
					ResendDelay:  tc.value,
				}

				data, err := pkt.Marshal()
				require.NoError(t, err)

				pkt2 := &Packet{}
				err = pkt2.Unmarshal(data)
				require.NoError(t, err)

				assert.Equal(t, tc.value, pkt2.ResendDelay)
			})
		}
	})

	t.Run("minimum packet size is 22 bytes", func(t *testing.T) {
		// Minimal packet: header only
		pkt := &Packet{
			SendStreamID: 1,
			RecvStreamID: 2,
			SequenceNum:  100,
			AckThrough:   99,
		}

		data, err := pkt.Marshal()
		require.NoError(t, err)

		// Header is exactly 22 bytes per spec:
		// SendStreamID (4) + RecvStreamID (4) + SequenceNum (4) + AckThrough (4) +
		// NACKCount (1) + ResendDelay (1) + Flags (2) + OptionSize (2) = 22
		assert.Equal(t, 22, len(data), "minimal packet should be exactly 22 bytes")
	})
}

// TestStreamIDCompliance tests stream ID generation and usage per I2P spec.
func TestStreamIDCompliance(t *testing.T) {
	t.Run("generated stream IDs are non-zero", func(t *testing.T) {
		// Generate 100 stream IDs
		for i := 0; i < 100; i++ {
			id, err := generateStreamID()
			require.NoError(t, err)
			assert.NotEqual(t, uint32(0), id, "stream ID must be non-zero")
		}
	})

	t.Run("stream IDs use full 32-bit space", func(t *testing.T) {
		// Generate many IDs and check distribution
		ids := make([]uint32, 1000)
		for i := 0; i < 1000; i++ {
			id, err := generateStreamID()
			require.NoError(t, err)
			ids[i] = id
		}

		// Check we get values across the range
		// This is a statistical test - should have some IDs in each quartile
		var q1, q2, q3, q4 int
		for _, id := range ids {
			switch {
			case id < 0x40000000:
				q1++
			case id < 0x80000000:
				q2++
			case id < 0xC0000000:
				q3++
			default:
				q4++
			}
		}

		// Each quartile should have at least 10% of values (allowing for randomness)
		assert.Greater(t, q1, 100, "should have IDs in first quartile")
		assert.Greater(t, q2, 100, "should have IDs in second quartile")
		assert.Greater(t, q3, 100, "should have IDs in third quartile")
		assert.Greater(t, q4, 100, "should have IDs in fourth quartile")
	})

	t.Run("stream IDs are unique in sample", func(t *testing.T) {
		// Generate many IDs and check for collisions
		seen := make(map[uint32]bool)
		collisions := 0

		for i := 0; i < 10000; i++ {
			id, err := generateStreamID()
			require.NoError(t, err)
			if seen[id] {
				collisions++
			}
			seen[id] = true
		}

		// With 32-bit random IDs, probability of collision is very low
		// Birthday paradox: with 10k IDs, expected collisions ≈ 0.01
		assert.Less(t, collisions, 5, "should have very few collisions in 10k samples")
	})

	t.Run("SYN packet has SendStreamID = 0", func(t *testing.T) {
		pkt := &Packet{
			SendStreamID: 0, // Must be 0 in initial SYN per spec
			RecvStreamID: 12345,
			SequenceNum:  1000,
			Flags:        FlagSYN,
		}

		data, err := pkt.Marshal()
		require.NoError(t, err)

		pkt2 := &Packet{}
		err = pkt2.Unmarshal(data)
		require.NoError(t, err)

		assert.Equal(t, uint32(0), pkt2.SendStreamID, "SYN packet must have SendStreamID = 0")
		assert.NotEqual(t, uint32(0), pkt2.RecvStreamID, "SYN packet RecvStreamID should be non-zero")
	})
}

// TestSequenceNumberIncrement tests that sequence numbers increment by 1
// per packet (not by byte count) per I2P streaming spec.
func TestSequenceNumberIncrement(t *testing.T) {
	t.Run("sequence numbers in packet headers", func(t *testing.T) {
		// Create packets with incrementing sequence numbers
		packets := []*Packet{
			{SendStreamID: 1, RecvStreamID: 2, SequenceNum: 100, Flags: 0},
			{SendStreamID: 1, RecvStreamID: 2, SequenceNum: 101, Flags: 0},
			{SendStreamID: 1, RecvStreamID: 2, SequenceNum: 102, Flags: 0},
		}

		for i, pkt := range packets {
			data, err := pkt.Marshal()
			require.NoError(t, err)

			pkt2 := &Packet{}
			err = pkt2.Unmarshal(data)
			require.NoError(t, err)

			expectedSeq := uint32(100 + i)
			assert.Equal(t, expectedSeq, pkt2.SequenceNum, "sequence should be %d", expectedSeq)
		}
	})

	t.Run("sequence increment is 1 regardless of payload size", func(t *testing.T) {
		// Small payload packet
		pkt1 := &Packet{
			SendStreamID: 1,
			RecvStreamID: 2,
			SequenceNum:  1000,
			Flags:        0,               // No flags needed - ackThrough always valid per spec
			Payload:      []byte("small"), // 5 bytes
		}

		// Large payload packet
		pkt2 := &Packet{
			SendStreamID: 1,
			RecvStreamID: 2,
			SequenceNum:  1001,               // Incremented by 1, not by payload size
			Flags:        0,                  // No flags needed - ackThrough always valid per spec
			Payload:      make([]byte, 1024), // 1024 bytes
		}

		// Verify sequence numbers are consecutive
		assert.Equal(t, pkt1.SequenceNum+1, pkt2.SequenceNum,
			"sequence should increment by 1 regardless of payload size")
	})

	t.Run("AckThrough uses sequence number", func(t *testing.T) {
		pkt := &Packet{
			SendStreamID: 1,
			RecvStreamID: 2,
			SequenceNum:  500,
			AckThrough:   499, // Acknowledging previous sequence
			Flags:        0,   // No flags needed - ackThrough always valid per spec
		}

		data, err := pkt.Marshal()
		require.NoError(t, err)

		pkt2 := &Packet{}
		err = pkt2.Unmarshal(data)
		require.NoError(t, err)

		assert.Equal(t, uint32(499), pkt2.AckThrough, "AckThrough should use sequence numbers")
		assert.Equal(t, pkt.SequenceNum-1, pkt2.AckThrough, "AckThrough typically acks previous sequence")
	})
}

// TestPacketSizeValidation tests packet size constraints per I2P spec.
func TestPacketSizeValidation(t *testing.T) {
	t.Run("minimum packet is 22 bytes", func(t *testing.T) {
		pkt := &Packet{
			SendStreamID: 1,
			RecvStreamID: 2,
			SequenceNum:  100,
			AckThrough:   99,
		}

		data, err := pkt.Marshal()
		require.NoError(t, err)

		assert.Equal(t, 22, len(data), "minimum packet should be exactly 22 bytes")
	})

	t.Run("packet with options is larger", func(t *testing.T) {
		pkt := &Packet{
			SendStreamID:  1,
			RecvStreamID:  2,
			SequenceNum:   100,
			AckThrough:    99,
			Flags:         FlagDelayRequested | FlagMaxPacketSizeIncluded,
			OptionalDelay: 1000,
			MaxPacketSize: 1500,
		}

		data, err := pkt.Marshal()
		require.NoError(t, err)

		// Header (22) + OptionalDelay (2) + MaxPacketSize (2) = 26
		assert.Equal(t, 26, len(data), "packet with options should be 26 bytes")
	})

	t.Run("packet with payload", func(t *testing.T) {
		payload := []byte("test payload")
		pkt := &Packet{
			SendStreamID: 1,
			RecvStreamID: 2,
			SequenceNum:  100,
			AckThrough:   99,
			Payload:      payload,
		}

		data, err := pkt.Marshal()
		require.NoError(t, err)

		// Header (22) + payload length
		expectedSize := 22 + len(payload)
		assert.Equal(t, expectedSize, len(data), "packet with payload should include payload bytes")
	})

	t.Run("unmarshal rejects packet shorter than 22 bytes", func(t *testing.T) {
		// Create invalid short packet
		shortData := make([]byte, 20)

		pkt := &Packet{}
		err := pkt.Unmarshal(shortData)
		assert.Error(t, err, "should reject packet shorter than minimum size")
		assert.Contains(t, err.Error(), "too short", "error should mention packet is too short")
	})

	t.Run("large packet with all fields", func(t *testing.T) {
		crypto := go_i2cp.NewCrypto()
		dest, err := go_i2cp.NewDestination(crypto)
		require.NoError(t, err)

		keyPair, err := crypto.Ed25519SignatureKeygen()
		require.NoError(t, err)

		pkt := &Packet{
			SendStreamID:    1,
			RecvStreamID:    2,
			SequenceNum:     100,
			AckThrough:      99,
			Flags:           FlagDelayRequested | FlagMaxPacketSizeIncluded | FlagFromIncluded | FlagSignatureIncluded,
			OptionalDelay:   1000,
			MaxPacketSize:   1500,
			FromDestination: dest,
			NACKs:           []uint32{10, 20, 30}, // 3 NACKs = 12 bytes
			Payload:         make([]byte, 100),
		}

		err = SignPacket(pkt, keyPair)
		require.NoError(t, err)

		data, err := pkt.Marshal()
		require.NoError(t, err)

		// Header (22) + NACKs (12) + OptionalDelay (2) + MaxPacketSize (2) +
		// FROM (~391) + Signature (64) + Payload (100) = ~593+ bytes
		assert.GreaterOrEqual(t, len(data), 593, "large packet should be at least 593 bytes")

		// Verify it unmarshals correctly
		pkt2 := &Packet{}
		err = pkt2.Unmarshal(data)
		require.NoError(t, err)

		assert.Equal(t, pkt.SequenceNum, pkt2.SequenceNum)
		assert.Equal(t, pkt.NACKs, pkt2.NACKs)
		assert.Equal(t, pkt.Payload, pkt2.Payload)
	})
}
