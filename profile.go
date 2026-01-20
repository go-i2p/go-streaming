// Package streaming provides TCP-like reliable streams over I2P.
package streaming

import "fmt"

// StreamProfile represents the streaming profile hint per I2P spec.
// The profile is a hint to the streaming library about expected traffic patterns.
// Per spec: "Optimization strategies, if any, are implementation-dependent."
//
// Note: As of API 0.9.64, Java I2P ignores this value. The PROFILE_INTERACTIVE
// flag is defined in the protocol but "not implemented in any known router."
// This implementation accepts the configuration for completeness but does not
// change behavior based on profile selection.
type StreamProfile int

const (
	// ProfileBulk (1) optimizes for high bandwidth, possibly at the expense of latency.
	// This is the default profile per I2P streaming specification.
	ProfileBulk StreamProfile = 1

	// ProfileInteractive (2) optimizes for low latency, possibly at the expense
	// of bandwidth or efficiency. When set, the PROFILE_INTERACTIVE flag (bit 8)
	// is included in SYN packets to hint to the remote peer.
	ProfileInteractive StreamProfile = 2
)

// String returns a human-readable name for the profile.
func (p StreamProfile) String() string {
	switch p {
	case ProfileBulk:
		return "bulk"
	case ProfileInteractive:
		return "interactive"
	default:
		return fmt.Sprintf("unknown(%d)", p)
	}
}

// IsValid returns true if the profile is a valid value per I2P spec.
func (p StreamProfile) IsValid() bool {
	return p == ProfileBulk || p == ProfileInteractive
}

// ProfileConfig holds profile-related configuration for streaming connections.
// Per I2P spec: i2p.streaming.profile option.
type ProfileConfig struct {
	// Profile specifies the traffic pattern hint.
	// Default: ProfileBulk (1)
	Profile StreamProfile
}

// DefaultProfileConfig returns the default profile configuration.
// Per spec, the default is bulk (optimize for bandwidth).
func DefaultProfileConfig() ProfileConfig {
	return ProfileConfig{
		Profile: ProfileBulk,
	}
}

// profileFromFlag extracts the profile from packet flags.
// If PROFILE_INTERACTIVE flag (bit 8) is set, returns ProfileInteractive.
// Otherwise returns ProfileBulk (the default).
func profileFromFlag(flags uint16) StreamProfile {
	if flags&FlagProfileInteractive != 0 {
		log.Debug("profile extracted from flags: interactive")
		return ProfileInteractive
	}
	log.Debug("profile extracted from flags: bulk (default)")
	return ProfileBulk
}

// profileToFlag returns the flag bits to set for the given profile.
// Only ProfileInteractive sets a flag (bit 8); ProfileBulk uses no flag.
func profileToFlag(profile StreamProfile) uint16 {
	if profile == ProfileInteractive {
		log.Debug("converting interactive profile to flag")
		return FlagProfileInteractive
	}
	log.Debug("converting bulk profile to flag (no flag set)")
	return 0
}
