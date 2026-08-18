package crypto

import (
	"bytes"
	"testing"
)

func testKEK(t *testing.T) []byte {
	t.Helper()
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	// Use light params for tests to keep them fast.
	return DeriveKey([]byte("correct horse battery staple"), salt, KDFParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1})
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("sk-super-secret-openai-key")
	ad := []byte("secret:42|openai|prod")

	blob, err := Encrypt(key, pt, ad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(blob, pt) {
		t.Fatal("ciphertext must not contain plaintext")
	}

	got, err := Decrypt(key, blob, ad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round trip mismatch: got %q want %q", got, pt)
	}
}

func TestDecryptWrongADFails(t *testing.T) {
	key, _ := NewKey()
	blob, _ := Encrypt(key, []byte("secret"), []byte("ad-a"))
	if _, err := Decrypt(key, blob, []byte("ad-b")); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt for wrong AD, got %v", err)
	}
}

func TestDecryptTamperFails(t *testing.T) {
	key, _ := NewKey()
	blob, _ := Encrypt(key, []byte("secret"), nil)
	blob[len(blob)-1] ^= 0xFF // flip a tag bit
	if _, err := Decrypt(key, blob, nil); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt for tampered ciphertext, got %v", err)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	k1, _ := NewKey()
	k2, _ := NewKey()
	blob, _ := Encrypt(k1, []byte("secret"), nil)
	if _, err := Decrypt(k2, blob, nil); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt for wrong key, got %v", err)
	}
}

func TestWrapUnwrapDEK(t *testing.T) {
	kek := testKEK(t)
	dek, _ := NewKey()

	wrapped, err := WrapKey(kek, dek)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	got, err := UnwrapKey(kek, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped DEK mismatch")
	}
}

func TestUnwrapWrongKEKFails(t *testing.T) {
	dek, _ := NewKey()
	good := testKEK(t)
	wrapped, _ := WrapKey(good, dek)

	badSalt, _ := NewSalt()
	bad := DeriveKey([]byte("wrong-password"), badSalt, KDFParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1})
	if _, err := UnwrapKey(bad, wrapped); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt unwrapping with wrong KEK, got %v", err)
	}
}

func TestVerifier(t *testing.T) {
	kek := testKEK(t)
	v, err := MakeVerifier(kek)
	if err != nil {
		t.Fatalf("MakeVerifier: %v", err)
	}
	if !CheckVerifier(kek, v) {
		t.Fatal("verifier should validate with correct KEK")
	}
	other := testKEK(t)
	if CheckVerifier(other, v) {
		t.Fatal("verifier must not validate with a different KEK")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	salt := bytes.Repeat([]byte{0x01}, SaltLen)
	p := KDFParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
	a := DeriveKey([]byte("pw"), salt, p)
	b := DeriveKey([]byte("pw"), salt, p)
	if !bytes.Equal(a, b) {
		t.Fatal("same password+salt+params must derive the same key")
	}
	if len(a) != KeyLen {
		t.Fatalf("derived key length = %d, want %d", len(a), KeyLen)
	}
}

func TestKeyedHashDuplicateDetection(t *testing.T) {
	key, _ := NewKey()
	h1 := KeyedHash(key, []byte("same-secret"))
	h2 := KeyedHash(key, []byte("same-secret"))
	h3 := KeyedHash(key, []byte("different"))
	if !bytes.Equal(h1, h2) {
		t.Fatal("identical inputs must hash equal (duplicate detection)")
	}
	if bytes.Equal(h1, h3) {
		t.Fatal("different inputs must hash differently")
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, v)
		}
	}
}
