package vault

import (
	"errors"
	"testing"

	"kosh/internal/crypto"
)

// stronger returns params one step above the floor — enough to be a real change without
// making tests pay for 512 MiB of Argon2id.
func stronger() crypto.KDFParams {
	p := crypto.DefaultKDFParams()
	p.MemoryKiB *= 2
	return p
}

func TestRekeyKDFChangesParamsAndKeepsSecretsReadable(t *testing.T) {
	v := newInitedVault(t)
	if _, err := v.AddSecret(AddSecretInput{
		Alias: "K1", ProviderKey: "github", Environment: Dev, Value: []byte("s3cret"),
	}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	before, err := v.KDFParams()
	if err != nil {
		t.Fatalf("KDFParams: %v", err)
	}

	want := stronger()
	if err := v.RekeyKDF([]byte("pw"), want); err != nil {
		t.Fatalf("RekeyKDF: %v", err)
	}

	after, err := v.KDFParams()
	if err != nil {
		t.Fatalf("KDFParams: %v", err)
	}
	if after.MemoryKiB != want.MemoryKiB || after.Time != want.Time {
		t.Fatalf("params = %+v, want %+v", after, want)
	}
	if after.MemoryKiB <= before.MemoryKiB {
		t.Fatal("re-key did not increase the cost")
	}

	// The DEK is unchanged, so the secret must still decrypt without re-encryption.
	got, err := v.Reveal("K1")
	if err != nil {
		t.Fatalf("Reveal after re-key: %v", err)
	}
	if string(got) != "s3cret" {
		t.Fatalf("value = %q after re-key", got)
	}

	// And the new password derivation must be what unlocks it.
	v.Lock()
	if err := v.Unlock([]byte("pw")); err != nil {
		t.Fatalf("Unlock after re-key: %v", err)
	}
	if err := v.Unlock([]byte("wrong")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password after re-key: got %v", err)
	}
}

func TestRekeyKDFRequiresMasterPassword(t *testing.T) {
	v := newInitedVault(t)
	if err := v.RekeyKDF([]byte("wrong"), stronger()); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("want ErrWrongPassword, got %v", err)
	}
	// The vault must be untouched — a failed re-key that half-wrote key material would
	// be unrecoverable.
	p, err := v.KDFParams()
	if err != nil {
		t.Fatalf("KDFParams: %v", err)
	}
	if p != crypto.DefaultKDFParams() {
		t.Fatalf("params changed after a failed re-key: %+v", p)
	}
	if err := v.Unlock([]byte("pw")); err != nil {
		t.Fatalf("vault no longer unlocks with the original password: %v", err)
	}
}

func TestRekeyKDFRefusesWeakerParams(t *testing.T) {
	v := newInitedVault(t)
	if err := v.RekeyKDF([]byte("pw"), stronger()); err != nil {
		t.Fatalf("RekeyKDF: %v", err)
	}

	// Now try to go back down to the floor.
	weaker := crypto.DefaultKDFParams()
	if err := v.RekeyKDF([]byte("pw"), weaker); !errors.Is(err, ErrWeakerKDF) {
		t.Fatalf("want ErrWeakerKDF, got %v", err)
	}
}

func TestRekeyKDFRejectsOutOfRangeParams(t *testing.T) {
	v := newInitedVault(t)
	for _, p := range []crypto.KDFParams{
		{},
		{Time: 3, MemoryKiB: 1024, Threads: 4}, // below the floor
		{Time: 3, MemoryKiB: 4 * 1024 * 1024, Threads: 4},      // above the ceiling
		{Time: 99, MemoryKiB: crypto.MinMemoryKiB, Threads: 4}, // absurd time
	} {
		if err := v.RekeyKDF([]byte("pw"), p); !errors.Is(err, ErrBadKDFParams) {
			t.Errorf("params %+v: want ErrBadKDFParams, got %v", p, err)
		}
	}
}

func TestRekeyKDFRequiresUnlockedVault(t *testing.T) {
	v := newInitedVault(t)
	v.Lock()
	if err := v.RekeyKDF([]byte("pw"), stronger()); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
}

// The whole reason migration 0009 exists: re-keying the master password must not break an
// existing recovery key.
func TestRecoveryKeyStillWorksAfterRekey(t *testing.T) {
	v := newInitedVault(t)
	if _, err := v.AddSecret(AddSecretInput{
		Alias: "K1", ProviderKey: "github", Environment: Dev, Value: []byte("s3cret"),
	}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}
	code, err := v.GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey: %v", err)
	}

	if err := v.RekeyKDF([]byte("pw"), stronger()); err != nil {
		t.Fatalf("RekeyKDF: %v", err)
	}

	v.Lock()
	if err := v.RecoverWithKey(code, []byte("brand-new-password")); err != nil {
		t.Fatalf("recovery key stopped working after a re-key: %v", err)
	}
	got, err := v.Reveal("K1")
	if err != nil {
		t.Fatalf("Reveal after recovery: %v", err)
	}
	if string(got) != "s3cret" {
		t.Fatalf("value = %q", got)
	}
}

// Recovery must not silently downgrade a strengthened vault back to the floor.
func TestRecoveryPreservesStrengthenedParams(t *testing.T) {
	v := newInitedVault(t)
	want := stronger()
	if err := v.RekeyKDF([]byte("pw"), want); err != nil {
		t.Fatalf("RekeyKDF: %v", err)
	}
	code, err := v.GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey: %v", err)
	}

	v.Lock()
	if err := v.RecoverWithKey(code, []byte("new-password")); err != nil {
		t.Fatalf("RecoverWithKey: %v", err)
	}

	after, err := v.KDFParams()
	if err != nil {
		t.Fatalf("KDFParams: %v", err)
	}
	if after.MemoryKiB != want.MemoryKiB {
		t.Fatalf("recovery downgraded the vault: params = %+v, want %+v", after, want)
	}
}

// The audit MAC subkey comes from the DEK, and a re-key leaves the DEK alone — so every
// pre-re-key audit record must still verify.
func TestAuditChainSurvivesRekey(t *testing.T) {
	v := newInitedVault(t)
	if _, err := v.AddSecret(AddSecretInput{
		Alias: "K1", ProviderKey: "github", Environment: Dev, Value: []byte("v"),
	}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	if err := v.RekeyKDF([]byte("pw"), stronger()); err != nil {
		t.Fatalf("RekeyKDF: %v", err)
	}
	if bad, err := v.VerifyAuditChain(); err != nil || bad != 0 {
		t.Fatalf("VerifyAuditChain after re-key: bad=%d err=%v", bad, err)
	}

	// The re-key itself must be recorded, with the parameter change in the detail.
	var action, detail string
	if err := v.DB().SQL().QueryRow(
		`SELECT action, detail FROM audit_log WHERE action='rekey_kdf' ORDER BY seq DESC LIMIT 1`).
		Scan(&action, &detail); err != nil {
		t.Fatalf("read rekey audit record: %v", err)
	}
	if detail == "" {
		t.Fatal("rekey_kdf audit record has no detail recording the parameter change")
	}
}

func TestInitWithParamsRejectsOutOfRange(t *testing.T) {
	v := newVault(t)
	if err := v.InitWithParams([]byte("pw"), crypto.KDFParams{}); !errors.Is(err, ErrBadKDFParams) {
		t.Fatalf("want ErrBadKDFParams, got %v", err)
	}
	if init, _ := v.IsInitialized(); init {
		t.Fatal("a rejected InitWithParams still created a vault")
	}
}

func TestInitWithParamsStoresGivenParams(t *testing.T) {
	v := newVault(t)
	want := stronger()
	if err := v.InitWithParams([]byte("pw"), want); err != nil {
		t.Fatalf("InitWithParams: %v", err)
	}
	got, err := v.KDFParams()
	if err != nil {
		t.Fatalf("KDFParams: %v", err)
	}
	if got.MemoryKiB != want.MemoryKiB || got.Time != want.Time {
		t.Fatalf("stored params = %+v, want %+v", got, want)
	}
	// And the vault must unlock under them.
	v.Lock()
	if err := v.Unlock([]byte("pw")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}
