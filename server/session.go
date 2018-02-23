package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Minimal allowed length of the session key, in bytes
// This is to prevent possible mistakes security reasons.
const MIN_SESSION_KEY_BYTE_LEN = 24

type sessionManager struct {
	sessionKeyByteLen int
}

func newSessionManager(n int) (*sessionManager, error) {
	var err error
	if n < MIN_SESSION_KEY_BYTE_LEN {
		err = fmt.Errorf("desired length of the session key (%d B) is too short, falling back to %d B",
			n, MIN_SESSION_KEY_BYTE_LEN)
		n = MIN_SESSION_KEY_BYTE_LEN
	}
	return &sessionManager{
		sessionKeyByteLen: n,
	}, err
}

// generateSessionKey produces a secure random n-byte session key and returns its
// base64-encoded representation that is URL-safe.
// It reports an error if n is less than MIN_SESSION_KEY_BYTE_LEN.
func (m *sessionManager) generateSessionKey() (*string, error) {
	randBytes := make([]byte, m.sessionKeyByteLen)

	// reads m.sessionKeyByteLen random bytes (e.g. len(randBytes)) to randBytes array
	_, err := rand.Read(randBytes)

	// an error may occur if the system's secure RNG doesn't function properly, in which case
	// we can't generate a secure session key
	if err != nil {
		return nil, err
	}

	sessionKey := base64.URLEncoding.EncodeToString(randBytes)
	return &sessionKey, nil
}
