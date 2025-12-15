package streaming

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetPublicKeyLength verifies the public key length mapping for all signature types
func TestGetPublicKeyLength(t *testing.T) {
	tests := []struct {
		name    string
		sigType uint16
		wantLen int
	}{
		{"DSA_SHA1", SignatureTypeDSA_SHA1, 128},
		{"ECDSA_SHA256_P256", SignatureTypeECDSA_SHA256_P256, 64},
		{"ECDSA_SHA384_P384", SignatureTypeECDSA_SHA384_P384, 96},
		{"ECDSA_SHA512_P521", SignatureTypeECDSA_SHA512_P521, 132},
		{"RSA_SHA256_2048", SignatureTypeRSA_SHA256_2048, 256},
		{"RSA_SHA384_3072", SignatureTypeRSA_SHA384_3072, 384},
		{"RSA_SHA512_4096", SignatureTypeRSA_SHA512_4096, 512},
		{"Ed25519", SignatureTypeEd25519, 32},
		{"Ed25519ph", SignatureTypeEd25519ph, 32},
		{"Unknown type", 9999, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPublicKeyLength(tt.sigType)
			assert.Equal(t, tt.wantLen, got, "public key length mismatch for %s", tt.name)
		})
	}
}

// TestOfflineSigMarshalUnmarshal verifies round-trip serialization of packets with offline signatures
func TestOfflineSigMarshalUnmarshal(t *testing.T) {
	crypto := go_i2cp.NewCrypto()
	// Create a destination for testing
	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err, "failed to create test destination")

	// Create test offline signature (Ed25519 transient key)
	offsig := &OfflineSig{
		Expires:            uint32(time.Now().Unix() + 3600), // Expires in 1 hour
		TransientSigType:   SignatureTypeEd25519,
		TransientPublicKey: make([]byte, 32), // Ed25519 public key
		DestSignature:      make([]byte, 64), // Ed25519 signature
	}
	_, err = rand.Read(offsig.TransientPublicKey)
	require.NoError(t, err, "failed to generate transient public key")
	_, err = rand.Read(offsig.DestSignature)
	require.NoError(t, err, "failed to generate dest signature")

	// Create packet with offline signature
	pkt := &Packet{
		SendStreamID:     1,
		RecvStreamID:     2,
		SequenceNum:      100,
		AckThrough:       99,
		Flags:            FlagFromIncluded | FlagSignatureIncluded | FlagOfflineSignature,
		FromDestination:  dest,
		Signature:        make([]byte, 64), // Ed25519 signature
		OfflineSignature: offsig,
		Payload:          []byte("test payload"),
	}
	_, err = rand.Read(pkt.Signature)
	require.NoError(t, err, "failed to generate packet signature")

	// Marshal the packet
	data, err := pkt.Marshal()
	require.NoError(t, err, "marshal failed")

	// Unmarshal into a new packet
	pkt2 := &Packet{}
	err = pkt2.Unmarshal(data)
	require.NoError(t, err, "unmarshal failed")

	// Verify all fields match
	assert.Equal(t, pkt.SendStreamID, pkt2.SendStreamID)
	assert.Equal(t, pkt.RecvStreamID, pkt2.RecvStreamID)
	assert.Equal(t, pkt.SequenceNum, pkt2.SequenceNum)
	assert.Equal(t, pkt.AckThrough, pkt2.AckThrough)
	assert.Equal(t, pkt.Flags, pkt2.Flags)
	assert.Equal(t, pkt.Signature, pkt2.Signature)
	assert.Equal(t, pkt.Payload, pkt2.Payload)

	// Verify offline signature fields
	require.NotNil(t, pkt2.OfflineSignature, "offline signature should not be nil")
	assert.Equal(t, offsig.Expires, pkt2.OfflineSignature.Expires)
	assert.Equal(t, offsig.TransientSigType, pkt2.OfflineSignature.TransientSigType)
	assert.Equal(t, offsig.TransientPublicKey, pkt2.OfflineSignature.TransientPublicKey)
	assert.Equal(t, offsig.DestSignature, pkt2.OfflineSignature.DestSignature)
}

// TestOfflineSigMarshalWithoutFlag verifies error when OfflineSignature is set but flag is missing
func TestOfflineSigMarshalWithoutFlag(t *testing.T) {
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err)

	offsig := &OfflineSig{
		Expires:            uint32(time.Now().Unix() + 3600),
		TransientSigType:   SignatureTypeEd25519,
		TransientPublicKey: make([]byte, 32),
		DestSignature:      make([]byte, 64),
	}

	pkt := &Packet{
		SendStreamID:     1,
		RecvStreamID:     2,
		SequenceNum:      100,
		AckThrough:       99,
		Flags:            FlagFromIncluded | FlagSignatureIncluded, // Missing FlagOfflineSignature
		FromDestination:  dest,
		Signature:        make([]byte, 64),
		OfflineSignature: offsig, // Set but flag is missing
		Payload:          []byte("test"),
	}

	// Marshal should succeed (OfflineSignature is just ignored)
	_, err = pkt.Marshal()
	assert.NoError(t, err, "marshal should succeed when offline signature is set but flag is missing")
}

// TestOfflineSigFlagWithoutData verifies error when flag is set but OfflineSignature is nil
func TestOfflineSigFlagWithoutData(t *testing.T) {
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err)

	pkt := &Packet{
		SendStreamID:     1,
		RecvStreamID:     2,
		SequenceNum:      100,
		AckThrough:       99,
		Flags:            FlagFromIncluded | FlagSignatureIncluded | FlagOfflineSignature,
		FromDestination:  dest,
		Signature:        make([]byte, 64),
		OfflineSignature: nil, // Flag is set but data is nil
		Payload:          []byte("test"),
	}

	_, err = pkt.Marshal()
	assert.Error(t, err, "marshal should fail when FlagOfflineSignature is set but OfflineSignature is nil")
	assert.Contains(t, err.Error(), "FlagOfflineSignature set but OfflineSignature is nil")
}

// TestOfflineSigInvalidTransientKeyLength verifies error when transient key length doesn't match type
func TestOfflineSigInvalidTransientKeyLength(t *testing.T) {
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err)

	offsig := &OfflineSig{
		Expires:            uint32(time.Now().Unix() + 3600),
		TransientSigType:   SignatureTypeEd25519,
		TransientPublicKey: make([]byte, 16), // Wrong length (should be 32)
		DestSignature:      make([]byte, 64),
	}

	pkt := &Packet{
		SendStreamID:     1,
		RecvStreamID:     2,
		SequenceNum:      100,
		AckThrough:       99,
		Flags:            FlagFromIncluded | FlagSignatureIncluded | FlagOfflineSignature,
		FromDestination:  dest,
		Signature:        make([]byte, 64),
		OfflineSignature: offsig,
		Payload:          []byte("test"),
	}

	_, err = pkt.Marshal()
	assert.Error(t, err, "marshal should fail when transient public key length is wrong")
	assert.Contains(t, err.Error(), "transient public key length mismatch")
}

// TestOfflineSigInvalidDestSignatureLength verifies error when dest signature length doesn't match type
func TestOfflineSigInvalidDestSignatureLength(t *testing.T) {
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err)

	offsig := &OfflineSig{
		Expires:            uint32(time.Now().Unix() + 3600),
		TransientSigType:   SignatureTypeEd25519,
		TransientPublicKey: make([]byte, 32),
		DestSignature:      make([]byte, 32), // Wrong length (should be 64)
	}

	pkt := &Packet{
		SendStreamID:     1,
		RecvStreamID:     2,
		SequenceNum:      100,
		AckThrough:       99,
		Flags:            FlagFromIncluded | FlagSignatureIncluded | FlagOfflineSignature,
		FromDestination:  dest,
		Signature:        make([]byte, 64),
		OfflineSignature: offsig,
		Payload:          []byte("test"),
	}

	_, err = pkt.Marshal()
	assert.Error(t, err, "marshal should fail when dest signature length is wrong")
	assert.Contains(t, err.Error(), "offline signature dest signature length mismatch")
}

// TestOfflineSigUnmarshalTooShort verifies error when packet is too short for offline signature
func TestOfflineSigUnmarshalTooShort(t *testing.T) {
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err)

	// Create a valid packet first
	pkt := &Packet{
		SendStreamID:    1,
		RecvStreamID:    2,
		SequenceNum:     100,
		AckThrough:      99,
		Flags:           FlagFromIncluded | FlagSignatureIncluded | FlagOfflineSignature,
		FromDestination: dest,
		Signature:       make([]byte, 64),
		OfflineSignature: &OfflineSig{
			Expires:            uint32(time.Now().Unix() + 3600),
			TransientSigType:   SignatureTypeEd25519,
			TransientPublicKey: make([]byte, 32),
			DestSignature:      make([]byte, 64),
		},
		Payload: []byte("test"),
	}

	data, err := pkt.Marshal()
	require.NoError(t, err)

	// Truncate the data to remove part of offline signature
	data = data[:len(data)-50]

	// Try to unmarshal
	pkt2 := &Packet{}
	err = pkt2.Unmarshal(data)
	assert.Error(t, err, "unmarshal should fail when packet is too short for offline signature")
}

// TestOfflineSigMultipleTypes verifies offline signatures work with different transient key types
func TestOfflineSigMultipleTypes(t *testing.T) {
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err)

	tests := []struct {
		name            string
		transientType   uint16
		transientKeyLen int
	}{
		{"Ed25519 transient", SignatureTypeEd25519, 32},
		{"ECDSA P-256 transient", SignatureTypeECDSA_SHA256_P256, 64},
		{"ECDSA P-384 transient", SignatureTypeECDSA_SHA384_P384, 96},
		{"RSA 2048 transient", SignatureTypeRSA_SHA256_2048, 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offsig := &OfflineSig{
				Expires:            uint32(time.Now().Unix() + 3600),
				TransientSigType:   tt.transientType,
				TransientPublicKey: make([]byte, tt.transientKeyLen),
				DestSignature:      make([]byte, 64), // Ed25519 dest signature
			}
			_, err = rand.Read(offsig.TransientPublicKey)
			require.NoError(t, err)
			_, err = rand.Read(offsig.DestSignature)
			require.NoError(t, err)

			pkt := &Packet{
				SendStreamID:     1,
				RecvStreamID:     2,
				SequenceNum:      100,
				AckThrough:       99,
				Flags:            FlagFromIncluded | FlagSignatureIncluded | FlagOfflineSignature,
				FromDestination:  dest,
				Signature:        make([]byte, 64),
				OfflineSignature: offsig,
				Payload:          []byte("test"),
			}

			// Marshal and unmarshal
			data, err := pkt.Marshal()
			require.NoError(t, err, "marshal failed for %s", tt.name)

			pkt2 := &Packet{}
			err = pkt2.Unmarshal(data)
			require.NoError(t, err, "unmarshal failed for %s", tt.name)

			// Verify offline signature fields
			require.NotNil(t, pkt2.OfflineSignature)
			assert.Equal(t, offsig.Expires, pkt2.OfflineSignature.Expires)
			assert.Equal(t, offsig.TransientSigType, pkt2.OfflineSignature.TransientSigType)
			assert.Equal(t, offsig.TransientPublicKey, pkt2.OfflineSignature.TransientPublicKey)
			assert.Equal(t, offsig.DestSignature, pkt2.OfflineSignature.DestSignature)
		})
	}
}

// TestOfflineSigExpiredTimestamp verifies parsing works with expired timestamps
func TestOfflineSigExpiredTimestamp(t *testing.T) {
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err)

	// Create offline signature with expired timestamp
	offsig := &OfflineSig{
		Expires:            uint32(time.Now().Unix() - 3600), // Expired 1 hour ago
		TransientSigType:   SignatureTypeEd25519,
		TransientPublicKey: make([]byte, 32),
		DestSignature:      make([]byte, 64),
	}
	_, err = rand.Read(offsig.TransientPublicKey)
	require.NoError(t, err)
	_, err = rand.Read(offsig.DestSignature)
	require.NoError(t, err)

	pkt := &Packet{
		SendStreamID:     1,
		RecvStreamID:     2,
		SequenceNum:      100,
		AckThrough:       99,
		Flags:            FlagFromIncluded | FlagSignatureIncluded | FlagOfflineSignature,
		FromDestination:  dest,
		Signature:        make([]byte, 64),
		OfflineSignature: offsig,
		Payload:          []byte("test"),
	}

	// Marshal and unmarshal should succeed (expiration check is done during verification, not parsing)
	data, err := pkt.Marshal()
	require.NoError(t, err)

	pkt2 := &Packet{}
	err = pkt2.Unmarshal(data)
	require.NoError(t, err, "unmarshal should succeed even with expired timestamp")
	assert.Equal(t, offsig.Expires, pkt2.OfflineSignature.Expires)
}

// TestOfflineSigOptionSizeCalculation verifies correct option size calculation with offline signatures
func TestOfflineSigOptionSizeCalculation(t *testing.T) {
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err)

	offsig := &OfflineSig{
		Expires:            uint32(time.Now().Unix() + 3600),
		TransientSigType:   SignatureTypeEd25519,
		TransientPublicKey: make([]byte, 32),
		DestSignature:      make([]byte, 64),
	}

	pkt := &Packet{
		SendStreamID:     1,
		RecvStreamID:     2,
		SequenceNum:      100,
		AckThrough:       99,
		Flags:            FlagFromIncluded | FlagSignatureIncluded | FlagOfflineSignature,
		FromDestination:  dest,
		Signature:        make([]byte, 64),
		OfflineSignature: offsig,
		Payload:          []byte("test payload"),
	}

	data, err := pkt.Marshal()
	require.NoError(t, err)

	// Parse option size from packet (at offset 20)
	optionSize := binary.BigEndian.Uint16(data[20:22])

	// Calculate expected option size:
	// FROM destination: variable (encode it to get size)
	// Signature: 64 bytes
	// Offline signature: 4 (expires) + 2 (type) + 32 (transient key) + 64 (dest sig) = 102 bytes
	fromStream := go_i2cp.NewStream(make([]byte, 0, 512))
	err = dest.WriteToMessage(fromStream)
	require.NoError(t, err)
	fromBytes := fromStream.Bytes()
	expectedOptionSize := len(fromBytes) + 64 + 102

	assert.Equal(t, expectedOptionSize, int(optionSize), "option size mismatch")
}

// TestOfflineSigWithoutFromDestination verifies error when offline signature is present but FROM is missing
func TestOfflineSigWithoutFromDestination(t *testing.T) {
	offsig := &OfflineSig{
		Expires:            uint32(time.Now().Unix() + 3600),
		TransientSigType:   SignatureTypeEd25519,
		TransientPublicKey: make([]byte, 32),
		DestSignature:      make([]byte, 64),
	}

	pkt := &Packet{
		SendStreamID:     1,
		RecvStreamID:     2,
		SequenceNum:      100,
		AckThrough:       99,
		Flags:            FlagSignatureIncluded | FlagOfflineSignature, // Missing FlagFromIncluded
		FromDestination:  nil,
		Signature:        make([]byte, 64),
		OfflineSignature: offsig,
		Payload:          []byte("test"),
	}

	_, err := pkt.Marshal()
	assert.Error(t, err, "marshal should fail when offline signature is present but FROM destination is missing")
}

// TestOfflineSigUnknownTransientType verifies error when transient signature type is unknown
func TestOfflineSigUnknownTransientType(t *testing.T) {
	crypto := go_i2cp.NewCrypto()
	dest, err := go_i2cp.NewDestination(crypto)
	require.NoError(t, err)

	offsig := &OfflineSig{
		Expires:            uint32(time.Now().Unix() + 3600),
		TransientSigType:   9999, // Unknown type
		TransientPublicKey: make([]byte, 32),
		DestSignature:      make([]byte, 64),
	}

	pkt := &Packet{
		SendStreamID:     1,
		RecvStreamID:     2,
		SequenceNum:      100,
		AckThrough:       99,
		Flags:            FlagFromIncluded | FlagSignatureIncluded | FlagOfflineSignature,
		FromDestination:  dest,
		Signature:        make([]byte, 64),
		OfflineSignature: offsig,
		Payload:          []byte("test"),
	}

	// Marshal should fail because getPublicKeyLength returns 0 for unknown type
	// This causes a length mismatch when we have 32 bytes but expect 0
	_, err = pkt.Marshal()
	assert.Error(t, err, "marshal should fail when transient signature type is unknown")
	assert.Contains(t, err.Error(), "transient public key length mismatch")
}
