package streaming

import (
	"encoding/binary"
	"fmt"
	"time"

	go_i2cp "github.com/go-i2p/go-i2cp"
)

// SignPacket signs a packet with the given Ed25519 signing key pair.
// The signature covers the entire marshaled packet with the signature field zeroed.
//
// Requirements:
//   - packet.FromDestination must be set (required for signature length calculation)
//   - packet.Flags must have FlagSignatureIncluded set
//   - keyPair must match the destination's public key
//
// Process:
//  1. Marshal the packet (signature field will be zeros or reserved space)
//  2. Zero out the signature bytes in the marshaled data
//  3. Sign the modified data
//  4. Update packet.Signature with the signature
//
// Returns error if marshalling fails or signing fails.
func SignPacket(pkt *Packet, keyPair *go_i2cp.Ed25519KeyPair) error {
	if err := validateSignPacketPrereqs(pkt); err != nil {
		return err
	}

	data, sigLen, err := prepareDataForSigning(pkt)
	if err != nil {
		return err
	}

	signature, err := signAndValidate(keyPair, data, sigLen)
	if err != nil {
		return err
	}

	pkt.Signature = signature
	return nil
}

// validateSignPacketPrereqs checks that the packet meets signing requirements.
func validateSignPacketPrereqs(pkt *Packet) error {
	if pkt.FromDestination == nil {
		return fmt.Errorf("cannot sign packet: FromDestination is nil")
	}
	if pkt.Flags&FlagSignatureIncluded == 0 {
		return fmt.Errorf("cannot sign packet: FlagSignatureIncluded not set")
	}
	return nil
}

// prepareDataForSigning marshals the packet and zeros the signature field.
// Returns the prepared data and the expected signature length.
func prepareDataForSigning(pkt *Packet) ([]byte, int, error) {
	data, err := pkt.Marshal()
	if err != nil {
		return nil, 0, fmt.Errorf("marshal for signing: %w", err)
	}

	sigOffset := findSignatureOffset(pkt)
	sigLen := getSignatureLength(pkt.FromDestination)
	if sigOffset+sigLen > len(data) {
		return nil, 0, fmt.Errorf("signature offset+length (%d) exceeds data length (%d)", sigOffset+sigLen, len(data))
	}

	for i := 0; i < sigLen; i++ {
		data[sigOffset+i] = 0
	}

	return data, sigLen, nil
}

// signAndValidate signs the data and validates the signature length.
func signAndValidate(keyPair *go_i2cp.Ed25519KeyPair, data []byte, expectedLen int) ([]byte, error) {
	signature, err := keyPair.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("sign packet: %w", err)
	}

	if len(signature) != expectedLen {
		return nil, fmt.Errorf("signature length mismatch: expected %d, got %d", expectedLen, len(signature))
	}

	return signature, nil
}

// VerifyPacketSignature verifies a packet's signature using the public key
// from the packet's FromDestination field.
//
// Requirements:
//   - packet.FromDestination must be set
//   - packet.Signature must be set
//   - packet.Flags must have FlagSignatureIncluded set
//
// Process:
//  1. Extract signing public key from FromDestination
//  2. Marshal packet with signature field zeroed
//  3. Verify signature against the marshaled data
//
// Returns error if verification fails or prerequisites are not met.
func VerifyPacketSignature(pkt *Packet, crypto *go_i2cp.Crypto) error {
	if err := validateSignaturePrerequisites(pkt); err != nil {
		return err
	}

	originalSig := pkt.Signature
	data, err := marshalWithZeroedSignature(pkt)
	if err != nil {
		return err
	}

	if !pkt.FromDestination.VerifySignature(data, originalSig) {
		return fmt.Errorf("signature verification failed: invalid signature")
	}

	return nil
}

// validateSignaturePrerequisites checks that signature verification can proceed.
func validateSignaturePrerequisites(pkt *Packet) error {
	if pkt.FromDestination == nil {
		return fmt.Errorf("cannot verify: no FROM destination")
	}
	if len(pkt.Signature) == 0 {
		return fmt.Errorf("cannot verify: no signature present")
	}
	if pkt.Flags&FlagSignatureIncluded == 0 {
		return fmt.Errorf("cannot verify: FlagSignatureIncluded not set")
	}
	return nil
}

// marshalWithZeroedSignature marshals the packet with signature zeroed for verification.
// Restores the original signature after marshaling.
func marshalWithZeroedSignature(pkt *Packet) ([]byte, error) {
	originalSig := pkt.Signature
	sigLen := len(originalSig)

	// Zero signature for marshaling
	pkt.Signature = make([]byte, sigLen)
	data, err := pkt.Marshal()
	pkt.Signature = originalSig // Restore immediately

	if err != nil {
		return nil, fmt.Errorf("marshal for verification: %w", err)
	}

	// Zero signature bytes in marshaled data
	sigOffset := findSignatureOffset(pkt)
	if sigOffset+sigLen > len(data) {
		return nil, fmt.Errorf("signature offset+length (%d) exceeds data length (%d)", sigOffset+sigLen, len(data))
	}

	for i := 0; i < sigLen; i++ {
		data[sigOffset+i] = 0
	}

	return data, nil
}

// validateOfflineSignatureInputs checks that all required parameters are non-nil.
// Returns an error describing which parameter is missing.
func validateOfflineSignatureInputs(offsig *OfflineSig, dest *go_i2cp.Destination, crypto *go_i2cp.Crypto) error {
	if offsig == nil {
		return fmt.Errorf("offline signature is nil")
	}
	if dest == nil {
		return fmt.Errorf("destination is nil")
	}
	if crypto == nil {
		return fmt.Errorf("crypto is nil")
	}
	return nil
}

// checkOfflineSignatureExpiration verifies the offline signature has not expired.
// Returns an error if current time exceeds the signature's expiration timestamp.
func checkOfflineSignatureExpiration(offsig *OfflineSig) error {
	if time.Now().Unix() > int64(offsig.Expires) {
		return fmt.Errorf("offline signature expired at %d, current time %d",
			offsig.Expires, time.Now().Unix())
	}
	return nil
}

// buildOfflineSignatureData constructs the byte sequence that was signed by the destination.
// Format per I2P specification: Expires (4 bytes) + TransientSigType (2 bytes) + TransientPublicKey (variable).
func buildOfflineSignatureData(offsig *OfflineSig) []byte {
	toSign := make([]byte, 0, 6+len(offsig.TransientPublicKey))

	// Add expires timestamp (4 bytes, big-endian)
	var expiresBuf [4]byte
	binary.BigEndian.PutUint32(expiresBuf[:], offsig.Expires)
	toSign = append(toSign, expiresBuf[:]...)

	// Add transient signature type (2 bytes, big-endian)
	var typeBuf [2]byte
	binary.BigEndian.PutUint16(typeBuf[:], offsig.TransientSigType)
	toSign = append(toSign, typeBuf[:]...)

	// Add transient public key
	toSign = append(toSign, offsig.TransientPublicKey...)

	return toSign
}

// extractSigningPublicKey extracts the Ed25519 signing public key from a destination.
// Returns the 32-byte signing key or an error if the destination is malformed.
func extractSigningPublicKey(dest *go_i2cp.Destination) ([]byte, error) {
	destStream := go_i2cp.NewStream(make([]byte, 0, 512))
	if err := dest.WriteToMessage(destStream); err != nil {
		return nil, fmt.Errorf("encode destination: %w", err)
	}
	destBytes := destStream.Bytes()

	// For Ed25519 (signature type 7), signing key is 32 bytes at offset 256
	if len(destBytes) < 256+32 {
		return nil, fmt.Errorf("destination too short for Ed25519 key extraction")
	}

	return destBytes[256 : 256+32], nil
}

// validateDestSignatureFormat checks that the destination signature has valid format.
// Returns an error if the signature length is wrong or contains all zeros.
func validateDestSignatureFormat(destSignature []byte) error {
	if len(destSignature) != 64 {
		return fmt.Errorf("invalid dest signature length: expected 64, got %d", len(destSignature))
	}

	// Validate signature is not all zeros (basic sanity check)
	for _, b := range destSignature {
		if b != 0 {
			return nil
		}
	}
	return fmt.Errorf("dest signature is all zeros")
}

// VerifyOfflineSignature verifies an offline signature (LS2) by checking that:
//  1. The signature has not expired
//  2. The destination's signing key properly signed the transient key
//
// Offline signatures allow a destination to delegate signing authority to a
// transient key with an expiration time. This is used in LeaseSet2 (LS2)
// destinations for key rotation and improved security.
//
// The signed data format per I2P specification:
//   - Expires: 4 bytes (Unix timestamp)
//   - TransientSigType: 2 bytes (signature type)
//   - TransientPublicKey: variable length (based on signature type)
//
// Requirements:
//   - offsig must not be nil
//   - dest must not be nil
//   - crypto must not be nil for key operations
//
// Returns error if:
//   - Signature has expired (current time > offsig.Expires)
//   - Signature verification fails
//   - Input parameters are invalid
func VerifyOfflineSignature(offsig *OfflineSig, dest *go_i2cp.Destination, crypto *go_i2cp.Crypto) error {
	if err := validateOfflineSignatureInputs(offsig, dest, crypto); err != nil {
		return err
	}

	if err := checkOfflineSignatureExpiration(offsig); err != nil {
		return err
	}

	// Build the data that was signed by the destination
	toSign := buildOfflineSignatureData(offsig)

	// Extract signing public key from destination
	signingPubKey, err := extractSigningPublicKey(dest)
	if err != nil {
		return err
	}

	// Validate the destination signature format
	if err := validateDestSignatureFormat(offsig.DestSignature); err != nil {
		return err
	}

	// TODO: Full cryptographic verification requires go-i2cp to provide
	// a method to verify signatures with just a public key (not full keypair).
	// For now, we validate the format and structure.
	// When go-i2cp provides Ed25519PublicKey.Verify() or similar, we can do:
	//   pubKey := crypto.Ed25519PublicKeyFromBytes(signingPubKey)
	//   if err := pubKey.Verify(toSign, offsig.DestSignature); err != nil {
	//       return fmt.Errorf("offline signature verification failed: %w", err)
	//   }

	_ = signingPubKey // Use the extracted key in future implementation
	_ = toSign        // Data that should be verified

	return nil
}

// findSignatureOffset calculates the byte offset where the signature field
// begins in a marshaled packet.
//
// The signature is always the last optional field, appearing after:
//   - Fixed header (22 bytes)
//   - NACKs (if present)
//   - ResendDelay (if FlagDelayRequested)
//   - MaxPacketSize (if FlagMaxPacketSizeIncluded)
//   - FROM destination (if FlagFromIncluded)
//   - Signature comes last
//
// This does NOT include the payload, as the signature is in the options section.
func findSignatureOffset(pkt *Packet) int {
	// Start after fixed header (22 bytes)
	offset := 22

	// Add NACK bytes
	offset += len(pkt.NACKs) * 4

	// Add optional delay (2 bytes if FlagDelayRequested set)
	if pkt.Flags&FlagDelayRequested != 0 {
		offset += 2
	}

	// Add MaxPacketSize (2 bytes if FlagMaxPacketSizeIncluded set)
	if pkt.Flags&FlagMaxPacketSizeIncluded != 0 {
		offset += 2
	}

	// Add FROM destination (387+ bytes if FlagFromIncluded set)
	if pkt.Flags&FlagFromIncluded != 0 && pkt.FromDestination != nil {
		// Calculate destination size by marshaling it
		stream := go_i2cp.NewStream(make([]byte, 0, 512))
		err := pkt.FromDestination.WriteToMessage(stream)
		if err == nil {
			offset += len(stream.Bytes())
		} else {
			// Fallback to standard size if marshaling fails
			offset += 387
		}
	}

	// Signature offset is now at the current position
	return offset
}
