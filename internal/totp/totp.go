// Package totp computes RFC 6238 time-based one-time passwords locally (HMAC-SHA1, 30s
// period, 6 digits — the near-universal default used by Google Authenticator, GitHub,
// AWS, etc.). It performs no network I/O; codes are derived purely from the shared seed
// and the current time.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Period is the TOTP time step in seconds.
const Period = 30

// Normalize cleans a user-entered base32 seed: uppercased, spaces removed, padding
// trimmed (services often present the seed in spaced groups).
func Normalize(secret string) string {
	return strings.TrimRight(strings.ToUpper(strings.ReplaceAll(secret, " ", "")), "=")
}

func decode(secret string) ([]byte, error) {
	s := Normalize(secret)
	if s == "" {
		return nil, fmt.Errorf("totp: empty secret")
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("totp: invalid base32 seed: %w", err)
	}
	return key, nil
}

// Validate reports whether secret is a decodable base32 TOTP seed.
func Validate(secret string) error {
	_, err := decode(secret)
	return err
}

// Code returns the 6-digit TOTP for secret at time t and the seconds remaining in the
// current window.
func Code(secret string, t time.Time) (code string, remaining int, err error) {
	key, err := decode(secret)
	if err != nil {
		return "", 0, err
	}
	counter := uint64(t.Unix()) / Period

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.3).
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	remaining = Period - int(uint64(t.Unix())%Period)
	return fmt.Sprintf("%06d", bin%1_000_000), remaining, nil
}
