package crypto

import "golang.org/x/crypto/blake2b"

// blake2bKeyed returns a 32-byte keyed BLAKE2b hash of data. The key is truncated or
// used as-is by blake2b (max 64 bytes); our keys are 32 bytes.
func blake2bKeyed(key, data []byte) []byte {
	h, err := blake2b.New256(key)
	if err != nil {
		// blake2b.New256 only errors on an over-long key (>64 bytes); our keys are 32.
		panic("crypto: blake2b keyed hash init: " + err.Error())
	}
	h.Write(data)
	return h.Sum(nil)
}
