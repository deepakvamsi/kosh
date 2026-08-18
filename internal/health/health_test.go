package health

import (
	"testing"
	"time"

	"kosh/internal/storage"
	"kosh/internal/vault"
)

type testBed struct {
	db *storage.DB
	v  *vault.Vault
}

func newBed(t *testing.T) *testBed {
	t.Helper()
	db, err := storage.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.OpenDB(db, "ui")
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := v.Init([]byte("test-pw")); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close(); db.Close() })
	return &testBed{db: db, v: v}
}

func (b *testBed) add(t *testing.T, alias string, value []byte, expiresAt *int64) {
	t.Helper()
	_, err := b.v.AddSecret(vault.AddSecretInput{
		Alias:       alias,
		ProviderKey: "openai",
		Environment: vault.Dev,
		Value:       append([]byte(nil), value...),
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		t.Fatalf("AddSecret %s: %v", alias, err)
	}
}

func TestHealthySecret(t *testing.T) {
	bed := newBed(t)
	future := time.Now().Add(365 * 24 * time.Hour).Unix()
	bed.add(t, "HEALTHY_KEY", []byte("sk-1"), &future)

	results, err := Score(bed.db.SQL(), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	h := findAlias(results, "HEALTHY_KEY")
	if h == nil {
		t.Fatal("secret not found in health results")
	}
	if h.Status != StatusHealthy {
		t.Fatalf("expected healthy, got %s (flags %v)", h.Status, h.Flags)
	}
}

func TestExpiredSecret(t *testing.T) {
	bed := newBed(t)
	past := time.Now().Add(-24 * time.Hour).Unix()
	bed.add(t, "EXPIRED_KEY", []byte("sk-expired"), &past)

	results, _ := Score(bed.db.SQL(), DefaultConfig())
	h := findAlias(results, "EXPIRED_KEY")
	if h == nil {
		t.Fatal("not found")
	}
	if !hasFlag(h.Flags, FlagExpired) {
		t.Fatalf("expected expired flag, got %v", h.Flags)
	}
	if h.Status == StatusHealthy {
		t.Fatalf("expired secret should not be healthy, got %s", h.Status)
	}
}

func TestExpiringSoonSecret(t *testing.T) {
	bed := newBed(t)
	soon := time.Now().Add(3 * 24 * time.Hour).Unix()
	bed.add(t, "SOON_KEY", []byte("sk-soon"), &soon)

	results, _ := Score(bed.db.SQL(), DefaultConfig())
	h := findAlias(results, "SOON_KEY")
	if !hasFlag(h.Flags, FlagUpcoming) {
		t.Fatalf("expected expiring_soon flag, got %v", h.Flags)
	}
}

func TestDuplicateSecret(t *testing.T) {
	bed := newBed(t)
	sameValue := []byte("same-secret-value-duplicate")

	bed.add(t, "DUP_A", sameValue, nil)
	bed.add(t, "DUP_B", sameValue, nil)

	results, _ := Score(bed.db.SQL(), DefaultConfig())
	a := findAlias(results, "DUP_A")
	b := findAlias(results, "DUP_B")
	if a == nil || b == nil {
		t.Fatal("duplicate secrets not found")
	}
	if !hasFlag(a.Flags, FlagDuplicate) {
		t.Fatalf("DUP_A missing duplicate flag: %v", a.Flags)
	}
	if !hasFlag(b.Flags, FlagDuplicate) {
		t.Fatalf("DUP_B missing duplicate flag: %v", b.Flags)
	}
	if len(a.DupAliases) == 0 || a.DupAliases[0] != "DUP_B" {
		t.Fatalf("DUP_A.DupAliases = %v, want [DUP_B]", a.DupAliases)
	}
}

func TestOldSecretFlag(t *testing.T) {
	bed := newBed(t)
	bed.add(t, "OLD_KEY", []byte("sk-old"), nil)

	old := time.Now().Add(-200 * 24 * time.Hour).Unix()
	if _, err := bed.db.SQL().Exec(`UPDATE secrets SET updated_at=? WHERE alias='OLD_KEY'`, old); err != nil {
		t.Fatal(err)
	}

	results, _ := Score(bed.db.SQL(), DefaultConfig())
	h := findAlias(results, "OLD_KEY")
	if !hasFlag(h.Flags, FlagOld) {
		t.Fatalf("expected old flag, got %v", h.Flags)
	}
}

func TestScoreFormula(t *testing.T) {
	if s := computeScore(nil); s != 100 {
		t.Fatalf("no flags should be 100, got %d", s)
	}
	if s := computeScore([]Flag{FlagExpired}); s != 60 {
		t.Fatalf("one critical flag should be 60, got %d", s)
	}
	if s := computeScore([]Flag{FlagExpired, FlagDuplicate}); s != 20 {
		t.Fatalf("two critical flags should be 20, got %d", s)
	}
	if s := computeScore([]Flag{FlagExpired, FlagDuplicate, FlagOld}); s != 0 {
		t.Fatalf("three critical+warning should clamp to 0, got %d", s)
	}
}

func findAlias(results []SecretHealth, alias string) *SecretHealth {
	for i := range results {
		if results[i].Alias == alias {
			return &results[i]
		}
	}
	return nil
}

func hasFlag(flags []Flag, f Flag) bool {
	for _, fl := range flags {
		if fl == f {
			return true
		}
	}
	return false
}
