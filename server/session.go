package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// SessionManager generates a new session key.
// It returns a string containing the generated session key
// or an error in case session key could not be generated.
type SessionManager interface {
	GenerateSessionKey() (*string, error)
}

// MIN_SESSION_KEY_BYTE_LEN represents the minimal allowed length
// of the session key in bytes, for security reasons.
const MIN_SESSION_KEY_BYTE_LEN = 24

// RandSessionKeyGen generates session keys of the desired byte
// length from random bytes.
type RandSessionKeyGen struct {
	byteLen int
}

// NewRandSessionKeyGen creates a new RandSessionKeyGen instance.
// The new instance will be configured to generate session keys
// with exactly byteLen bytes. For security reasons, the function
// checks the byteLen against the value of MIN_SESSION_KEY_BYTE_LEN.
// If the provided byteLen is smaller than MIN_SESSION_KEY_BYTE_LEN,
// an error is set and the returned RandSessionKeyGen is configured
// to use MIN_SESSION_KEY_BYTE_LEN instead of the provided byteLen.
func NewRandSessionKeyGen(byteLen int) (*RandSessionKeyGen, error) {
	var err error
	if byteLen < MIN_SESSION_KEY_BYTE_LEN {
		err = fmt.Errorf("desired length of the session key (%d B) is too short, falling back to %d B",
			byteLen, MIN_SESSION_KEY_BYTE_LEN)
		byteLen = MIN_SESSION_KEY_BYTE_LEN
	}
	return &RandSessionKeyGen{
		byteLen: byteLen,
	}, err
}

// GenerateSessionKey produces a secure random session key and returns
// its base64-encoded representation that is URL-safe.
// It reports an error in case random byte sequence could not be generated.
func (m *RandSessionKeyGen) GenerateSessionKey() (*string, error) {
	randBytes := make([]byte, m.byteLen)

	// reads m.byteLen random bytes (e.g. len(randBytes)) to randBytes array
	_, err := rand.Read(randBytes)

	// an error may occur if the system's secure RNG doesn't function properly, in which case
	// we can't generate a secure session key
	if err != nil {
		return nil, err
	}

	sessionKey := base64.URLEncoding.EncodeToString(randBytes)
	return &sessionKey, nil
}
