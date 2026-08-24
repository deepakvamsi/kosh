package main

import (
	"strings"
	"testing"

	lv_vault "kosh/internal/vault"
)

// testProvider is a built-in provider key seeded by storage.seedProviders. AddSecret
// requires a known provider, so tests anchor to one rather than inventing a key.
const (
	testProvider = "github"
	testEnv      = "dev"
)

// newApp returns an App backed by a fresh in-memory vault, initialized and unlocked
// with password "pw". a.ctx stays nil: bound methods must never dereference it, and
// leaving it nil is what proves that.
func newApp(t *testing.T) *App {
	t.Helper()
	v, err := lv_vault.Open(":memory:", "ui")
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	t.Cleanup(func() { v.Close() })
	if err := v.Init([]byte("pw")); err != nil {
		t.Fatalf("vault.Init: %v", err)
	}
	return &App{vault: v, dbPath: ":memory:"}
}

// addKey inserts a plain api_key entry and fails the test if it does not land.
func addKey(t *testing.T, a *App, alias, value string) {
	t.Helper()
	res := a.AddSecret(AddSecretInput{Alias: alias, ItemType: "api_key", ProviderKey: testProvider, Environment: testEnv, Value: value})
	if res.Err != "" {
		t.Fatalf("AddSecret(%q): %s", alias, res.Err)
	}
	if res.ID == 0 {
		t.Fatalf("AddSecret(%q) returned id 0", alias)
	}
}

// --- nil-vault guards -------------------------------------------------------------
//
// startup() leaves a.vault nil when the database cannot be opened, and the webview can
// still call every bound method in that state. Each must surface a clean error instead
// of panicking on a nil dereference. This table is the regression net for that class.

func TestBoundMethodsSurviveNilVault(t *testing.T) {
	a := &App{} // exactly the state startup() leaves behind on an open failure

	// Methods that return an error value.
	errCases := map[string]func() error{
		"GenerateRecoveryKey": func() error { _, err := a.GenerateRecoveryKey("pw"); return err },
		"RevealSecret":        func() error { _, err := a.RevealSecret("x"); return err },
		"GetCustomFields":     func() error { _, err := a.GetCustomFields("x"); return err },
		"GetHealth":           func() error { _, err := a.GetHealth(); return err },
		"GetAuditLog":         func() error { _, err := a.GetAuditLog(10); return err },
		"VerifyAuditChain":    func() error { _, err := a.VerifyAuditChain(); return err },
		"ExportBackup":        func() error { _, err := a.ExportBackup("pw", "pw"); return err },
		"ListProviders":       func() error { _, err := a.ListProviders(); return err },
	}
	for name, fn := range errCases {
		t.Run(name, func(t *testing.T) {
			err := fn()
			if err == nil {
				t.Fatal("want an error with a nil vault, got nil")
			}
			if err != errVaultUnavailable {
				t.Fatalf("want errVaultUnavailable, got %v", err)
			}
		})
	}

	// Methods that report failure through BoolResult.Err rather than an error.
	boolCases := map[string]func() BoolResult{
		"InitVault":         func() BoolResult { return a.InitVault("pw") },
		"Unlock":            func() BoolResult { return a.Unlock("pw") },
		"RecoverWithKey":    func() BoolResult { return a.RecoverWithKey("code", "new") },
		"UpdateSecretValue": func() BoolResult { return a.UpdateSecretValue("x", "v") },
		"DeleteSecret":      func() BoolResult { return a.DeleteSecret("x") },
		"ArchiveSecret":     func() BoolResult { return a.ArchiveSecret("x", true) },
		"TagSecret":         func() BoolResult { return a.TagSecret("x", "t") },
		"SetFavorite":       func() BoolResult { return a.SetFavorite("x", true) },
		"SetTOTP":           func() BoolResult { return a.SetTOTP("x", "seed") },
		"SetCustomFields":   func() BoolResult { return a.SetCustomFields("x", "{}") },
		"ImportBackup":      func() BoolResult { return a.ImportBackup([]byte("d"), "pw") },
		"AddProvider":       func() BoolResult { return a.AddProvider(AddProviderInput{Key: "k", Name: "n"}) },
		"DeleteProvider":    func() BoolResult { return a.DeleteProvider("k") },
		"SetSetting":        func() BoolResult { return a.SetSetting("k", "v") },
		"StrengthenKDF":     func() BoolResult { return a.StrengthenKDF("pw") },
	}
	for name, fn := range boolCases {
		t.Run(name, func(t *testing.T) {
			res := fn()
			if res.OK {
				t.Fatal("want failure with a nil vault, got OK")
			}
			if res.Err == "" {
				t.Fatal("want a non-empty Err with a nil vault")
			}
		})
	}

	// Methods with bespoke return shapes.
	t.Run("AddSecret", func(t *testing.T) {
		if res := a.AddSecret(AddSecretInput{Alias: "x"}); res.Err == "" {
			t.Fatal("want an error with a nil vault")
		}
	})
	t.Run("RevealItem", func(t *testing.T) {
		if res := a.RevealItem("x"); res.Err == "" {
			t.Fatal("want an error with a nil vault")
		}
	})
	t.Run("GetKDFParams", func(t *testing.T) {
		if res := a.GetKDFParams(); res.Err == "" {
			t.Fatal("want an error with a nil vault")
		}
	})
	t.Run("GetTOTPCode", func(t *testing.T) {
		if res := a.GetTOTPCode("x"); res.Err == "" {
			t.Fatal("want an error with a nil vault")
		}
	})
	t.Run("ResetVault", func(t *testing.T) {
		if res := a.ResetVault(); res.OK {
			t.Fatal("ResetVault must not report success with no vault path")
		}
	})

	// Methods with no error channel at all: they must not panic.
	t.Run("no-panic accessors", func(t *testing.T) {
		if res := a.IsInitialized(); res.Value || res.Err == "" {
			t.Errorf("IsInitialized = %+v, want false with an error", res)
		}
		if a.IsUnlocked() {
			t.Error("IsUnlocked: want false with a nil vault")
		}
		if res := a.HasRecoveryKey(); res.Value || res.Err == "" {
			t.Errorf("HasRecoveryKey = %+v, want false with an error", res)
		}
		if got := a.UnlockStatus(); got != 0 {
			t.Errorf("UnlockStatus = %d, want 0", got)
		}
		// A DB failure must be distinguishable from an empty vault, and Items must
		// never be nil — the UI maps over it.
		got := a.ListSecrets("", "", "", false)
		if got.Err == "" {
			t.Error("ListSecrets: want Err set with a nil vault")
		}
		if got.Items == nil {
			t.Error("ListSecrets: Items must be an empty slice, not nil")
		}
		if len(got.Items) != 0 {
			t.Errorf("ListSecrets returned %d items with a nil vault", len(got.Items))
		}
		if got := a.GetSetting("k"); got != "" {
			t.Errorf("GetSetting = %q, want empty", got)
		}
		if got := a.autoLockSeconds(); got != 300 {
			t.Errorf("autoLockSeconds = %d, want the 300s default", got)
		}
		a.Lock()  // must be a no-op, not a panic
		a.Touch() // must be a no-op, not a panic
	})
}

// --- locked-vault enforcement -----------------------------------------------------
//
// An open-but-locked vault has no DEK. Nothing that reads or writes secret material may
// succeed, and no method may silently report success.

func TestLockedVaultRefusesSecretOperations(t *testing.T) {
	a := newApp(t)
	addKey(t, a, "before-lock", "s3cret")
	a.Lock()

	if a.IsUnlocked() {
		t.Fatal("IsUnlocked reports true after Lock")
	}

	t.Run("RevealSecret", func(t *testing.T) {
		got, err := a.RevealSecret("before-lock")
		if err == nil {
			t.Fatal("revealed a secret from a locked vault")
		}
		if got != "" {
			t.Fatalf("returned plaintext %q alongside an error", got)
		}
	})
	t.Run("RevealItem", func(t *testing.T) {
		res := a.RevealItem("before-lock")
		if res.Err == "" {
			t.Fatal("revealed an item from a locked vault")
		}
		if res.Value != "" || res.Password != "" || res.SecretKey != "" {
			t.Fatalf("leaked material from a locked vault: %+v", res)
		}
	})
	t.Run("AddSecret", func(t *testing.T) {
		if res := a.AddSecret(AddSecretInput{Alias: "new", ItemType: "api_key", ProviderKey: testProvider, Environment: testEnv, Value: "v"}); res.Err == "" {
			t.Fatal("added a secret to a locked vault")
		}
	})
	t.Run("UpdateSecretValue", func(t *testing.T) {
		if res := a.UpdateSecretValue("before-lock", "rotated"); res.OK {
			t.Fatal("updated a secret in a locked vault")
		}
	})
	t.Run("SetTOTP", func(t *testing.T) {
		if res := a.SetTOTP("before-lock", "JBSWY3DPEHPK3PXP"); res.OK {
			t.Fatal("set a TOTP seed on a locked vault")
		}
	})
	t.Run("AddProvider", func(t *testing.T) {
		if res := a.AddProvider(AddProviderInput{Key: "k", Name: "n"}); res.OK {
			t.Fatal("added a provider to a locked vault")
		}
	})
}

// --- re-authentication gate at the bound-API layer --------------------------------

func TestGenerateRecoveryKeyRequiresMasterPassword(t *testing.T) {
	a := newApp(t)

	code, err := a.GenerateRecoveryKey("wrong")
	if err == nil {
		t.Fatal("minted a recovery key with the wrong master password")
	}
	if code != "" {
		t.Fatalf("returned a recovery code %q alongside an error", code)
	}
	if res := a.HasRecoveryKey(); res.Err != "" || res.Value {
		t.Fatalf("after a failed re-auth HasRecoveryKey = %+v, want false with no error", res)
	}

	code, err = a.GenerateRecoveryKey("pw")
	if err != nil {
		t.Fatalf("GenerateRecoveryKey with the correct password: %v", err)
	}
	if code == "" {
		t.Fatal("want a recovery code, got empty string")
	}
	if res := a.HasRecoveryKey(); res.Err != "" || !res.Value {
		t.Fatalf("HasRecoveryKey = %+v after generating one, want true", res)
	}
}

func TestGenerateRecoveryKeyRequiresUnlockedVault(t *testing.T) {
	a := newApp(t)
	a.Lock()
	if _, err := a.GenerateRecoveryKey("pw"); err == nil {
		t.Fatal("minted a recovery key on a locked vault")
	}
}

func TestExportBackupRequiresMasterPassword(t *testing.T) {
	a := newApp(t)
	addKey(t, a, "k1", "s3cret")

	data, err := a.ExportBackup("wrong", "backup-pw")
	if err == nil {
		t.Fatal("exported a backup with the wrong master password")
	}
	if len(data) != 0 {
		t.Fatalf("returned %d bytes of backup alongside an error", len(data))
	}

	data, err = a.ExportBackup("pw", "backup-pw")
	if err != nil {
		t.Fatalf("ExportBackup with the correct password: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("want backup bytes, got none")
	}
	// The export must not carry plaintext.
	if strings.Contains(string(data), "s3cret") {
		t.Fatal("backup contains the secret value in plaintext")
	}
}

// A wrong-password re-auth must not be usable as a lockout oracle against the unlock
// screen: the vault is already unlocked, so failed re-auths cannot cost availability.
func TestFailedReauthDoesNotLockOutUnlock(t *testing.T) {
	a := newApp(t)
	for i := 0; i < 10; i++ {
		_, _ = a.GenerateRecoveryKey("wrong")
	}
	if got := a.UnlockStatus(); got != 0 {
		t.Fatalf("UnlockStatus = %d after failed re-auths, want 0", got)
	}
}

// --- round trips ------------------------------------------------------------------

func TestAddRevealRoundTripPerItemType(t *testing.T) {
	a := newApp(t)

	cases := []struct {
		name  string
		in    AddSecretInput
		check func(t *testing.T, got RevealedItemDTO)
	}{
		{
			name: "api_key",
			in:   AddSecretInput{Alias: "ak", ItemType: "api_key", ProviderKey: testProvider, Environment: testEnv, Value: "sk-live-123"},
			check: func(t *testing.T, got RevealedItemDTO) {
				if got.Value != "sk-live-123" {
					t.Errorf("Value = %q", got.Value)
				}
			},
		},
		{
			name: "login",
			in:   AddSecretInput{Alias: "lg", ItemType: "login", ProviderKey: testProvider, Environment: testEnv, Username: "alice", Password: "hunter2"},
			check: func(t *testing.T, got RevealedItemDTO) {
				if got.Username != "alice" || got.Password != "hunter2" {
					t.Errorf("Username/Password = %q/%q", got.Username, got.Password)
				}
			},
		},
		{
			name: "secure_note",
			in:   AddSecretInput{Alias: "nt", ItemType: "secure_note", ProviderKey: testProvider, Environment: testEnv, Note: "line one\nline two"},
			check: func(t *testing.T, got RevealedItemDTO) {
				if got.Note != "line one\nline two" {
					t.Errorf("Note = %q", got.Note)
				}
			},
		},
		{
			name: "keypair",
			in:   AddSecretInput{Alias: "kp", ItemType: "keypair", ProviderKey: testProvider, Environment: testEnv, AccessKey: "AKIA123", SecretKey: "wJalr/EXAMPLE"},
			check: func(t *testing.T, got RevealedItemDTO) {
				if got.AccessKey != "AKIA123" || got.SecretKey != "wJalr/EXAMPLE" {
					t.Errorf("AccessKey/SecretKey = %q/%q", got.AccessKey, got.SecretKey)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if res := a.AddSecret(tc.in); res.Err != "" {
				t.Fatalf("AddSecret: %s", res.Err)
			}
			got := a.RevealItem(tc.in.Alias)
			if got.Err != "" {
				t.Fatalf("RevealItem: %s", got.Err)
			}
			if got.ItemType != tc.in.ItemType {
				t.Errorf("ItemType = %q, want %q", got.ItemType, tc.in.ItemType)
			}
			tc.check(t, got)
		})
	}
}

// ListSecrets feeds a .map() in the UI, so Tags must never marshal to JSON null.
func TestListSecretsNeverEmitsNilTags(t *testing.T) {
	a := newApp(t)
	addKey(t, a, "untagged", "v")

	got := a.ListSecrets("", "", "", false)
	if got.Err != "" {
		t.Fatalf("ListSecrets: %s", got.Err)
	}
	if len(got.Items) == 0 {
		t.Fatal("ListSecrets returned nothing for a vault with one entry")
	}
	for _, s := range got.Items {
		if s.Tags == nil {
			t.Fatalf("entry %q has nil Tags", s.Alias)
		}
	}
}

func TestDeleteSecretRemovesItFromListings(t *testing.T) {
	a := newApp(t)
	addKey(t, a, "doomed", "v")

	if res := a.DeleteSecret("doomed"); !res.OK {
		t.Fatalf("DeleteSecret: %s", res.Err)
	}
	listed := a.ListSecrets("", "", "", true)
	if listed.Err != "" {
		t.Fatalf("ListSecrets: %s", listed.Err)
	}
	for _, s := range listed.Items {
		if s.Alias == "doomed" {
			t.Fatal("deleted entry still listed")
		}
	}
	if _, err := a.RevealSecret("doomed"); err == nil {
		t.Fatal("revealed a deleted entry")
	}
}

// --- settings / auto-lock ---------------------------------------------------------

func TestAutoLockSecondsReadsAndFallsBack(t *testing.T) {
	a := newApp(t)

	if got := a.autoLockSeconds(); got != 300 {
		t.Errorf("unset autolock_seconds: got %d, want the 300s default", got)
	}

	if res := a.SetSetting("autolock_seconds", "60"); !res.OK {
		t.Fatalf("SetSetting: %s", res.Err)
	}
	if got := a.autoLockSeconds(); got != 60 {
		t.Errorf("autoLockSeconds = %d, want 60", got)
	}

	// A non-numeric value must fall back to the default, never to 0 — 0 disables
	// auto-lock, so reading garbage as "disabled" would leave the DEK resident
	// indefinitely.
	if res := a.SetSetting("autolock_seconds", "not-a-number"); !res.OK {
		t.Fatalf("SetSetting: %s", res.Err)
	}
	if got := a.autoLockSeconds(); got != 300 {
		t.Errorf("garbage autolock_seconds: got %d, want the 300s default", got)
	}

	// An explicit 0 is a real choice (auto-lock off) and must be honored.
	if res := a.SetSetting("autolock_seconds", "0"); !res.OK {
		t.Fatalf("SetSetting: %s", res.Err)
	}
	if got := a.autoLockSeconds(); got != 0 {
		t.Errorf("autoLockSeconds = %d, want 0 (explicitly disabled)", got)
	}
}

func TestSetSettingRoundTrips(t *testing.T) {
	a := newApp(t)
	if res := a.SetSetting("theme", "light"); !res.OK {
		t.Fatalf("SetSetting: %s", res.Err)
	}
	if got := a.GetSetting("theme"); got != "light" {
		t.Fatalf("GetSetting = %q, want light", got)
	}
	// Upsert, not insert-only.
	if res := a.SetSetting("theme", "dark"); !res.OK {
		t.Fatalf("SetSetting overwrite: %s", res.Err)
	}
	if got := a.GetSetting("theme"); got != "dark" {
		t.Fatalf("GetSetting after overwrite = %q, want dark", got)
	}
}

// --- audit ------------------------------------------------------------------------

func TestPrivilegedOperationsLandInTheAuditLog(t *testing.T) {
	a := newApp(t)
	addKey(t, a, "audited", "v")
	if _, err := a.RevealSecret("audited"); err != nil {
		t.Fatalf("RevealSecret: %v", err)
	}

	records, err := a.GetAuditLog(100)
	if err != nil {
		t.Fatalf("GetAuditLog: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("audit log is empty after init, add and reveal")
	}
	for _, r := range records {
		if r.Seq == 0 || r.TS == 0 || r.Action == "" {
			t.Fatalf("malformed audit record: %+v", r)
		}
	}

	// The chain must verify through every operation above.
	if _, err := a.VerifyAuditChain(); err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
}

func TestGetAuditLogClampsNonPositiveLimit(t *testing.T) {
	a := newApp(t)
	// A 0 or negative limit from the UI must not become an error or an unbounded scan.
	for _, limit := range []int{0, -1} {
		if _, err := a.GetAuditLog(limit); err != nil {
			t.Fatalf("GetAuditLog(%d): %v", limit, err)
		}
	}
}

// --- providers --------------------------------------------------------------------

func TestBuiltinProvidersCannotBeDeleted(t *testing.T) {
	a := newApp(t)
	providers, err := a.ListProviders()
	if err != nil {
		t.Fatalf("ListProviders: %v", err)
	}

	var builtin string
	for _, p := range providers {
		if p.Builtin {
			builtin = p.Key
			break
		}
	}
	if builtin == "" {
		t.Skip("no built-in providers seeded in this schema")
	}

	if res := a.DeleteProvider(builtin); res.OK {
		t.Fatalf("deleted built-in provider %q", builtin)
	}
	after, err := a.ListProviders()
	if err != nil {
		t.Fatalf("ListProviders: %v", err)
	}
	if len(after) != len(providers) {
		t.Fatalf("provider count changed from %d to %d", len(providers), len(after))
	}
}

func TestAddProviderRejectsIncompleteInput(t *testing.T) {
	a := newApp(t)
	for _, in := range []AddProviderInput{
		{Key: "", Name: "Name"},
		{Key: "key", Name: ""},
	} {
		if res := a.AddProvider(in); res.OK {
			t.Fatalf("accepted incomplete provider %+v", in)
		}
	}
}

// --- KDF calibration and strengthening --------------------------------------------

func TestGetKDFParamsReportsCurrentAndSuggested(t *testing.T) {
	a := newApp(t)
	got := a.GetKDFParams()
	if got.Err != "" {
		t.Fatalf("GetKDFParams: %s", got.Err)
	}
	if got.Time == 0 || got.MemoryKiB == 0 || got.Threads == 0 {
		t.Fatalf("current params look unset: %+v", got)
	}
	// The suggestion must never be weaker than what the vault already uses, or the UI
	// would be offering a downgrade.
	if got.SuggestedMem < got.MemoryKiB {
		t.Errorf("suggested memory %d is below current %d", got.SuggestedMem, got.MemoryKiB)
	}
	if got.SuggestedTime < got.Time {
		t.Errorf("suggested time %d is below current %d", got.SuggestedTime, got.Time)
	}
	// CanStrengthen must agree with the numbers it is derived from.
	wantCan := got.SuggestedMem > got.MemoryKiB || got.SuggestedTime > got.Time
	if got.CanStrengthen != wantCan {
		t.Errorf("CanStrengthen = %v, but suggested=%d/%d vs current=%d/%d",
			got.CanStrengthen, got.SuggestedTime, got.SuggestedMem, got.Time, got.MemoryKiB)
	}
}

func TestStrengthenKDFRequiresMasterPassword(t *testing.T) {
	a := newApp(t)
	before := a.GetKDFParams()

	if res := a.StrengthenKDF("wrong"); res.OK {
		t.Fatal("strengthened the KDF with the wrong master password")
	}

	after := a.GetKDFParams()
	if after.MemoryKiB != before.MemoryKiB || after.Time != before.Time {
		t.Fatalf("params changed after a failed re-auth: %+v -> %+v", before, after)
	}
	// The vault must still be usable with the original password.
	a.Lock()
	if res := a.Unlock("pw"); !res.OK {
		t.Fatalf("Unlock after a failed strengthen: %s", res.Err)
	}
}

func TestStrengthenKDFRaisesCostAndKeepsSecretsReadable(t *testing.T) {
	a := newApp(t)
	addKey(t, a, "k1", "s3cret")

	before := a.GetKDFParams()
	if !before.CanStrengthen {
		t.Skip("this machine cannot sustain parameters above the vault's current cost")
	}

	if res := a.StrengthenKDF("pw"); !res.OK {
		t.Fatalf("StrengthenKDF: %s", res.Err)
	}

	after := a.GetKDFParams()
	if after.MemoryKiB < before.MemoryKiB || after.Time < before.Time {
		t.Fatalf("strengthen reduced the cost: %+v -> %+v", before, after)
	}
	if after.MemoryKiB == before.MemoryKiB && after.Time == before.Time {
		t.Fatal("strengthen reported success but changed nothing")
	}

	// No secret was re-encrypted, so the value must still reveal.
	got := a.RevealItem("k1")
	if got.Err != "" {
		t.Fatalf("RevealItem after strengthen: %s", got.Err)
	}
	if got.Value != "s3cret" {
		t.Fatalf("value = %q after strengthen", got.Value)
	}

	// And the audit chain must still verify under the unchanged DEK.
	if bad, err := a.VerifyAuditChain(); err != nil || bad != 0 {
		t.Fatalf("VerifyAuditChain after strengthen: bad=%d err=%v", bad, err)
	}

	// Re-running when there is nothing left to gain must report that, not silently
	// re-key again.
	if res := a.StrengthenKDF("pw"); res.OK {
		if again := a.GetKDFParams(); again.CanStrengthen {
			t.Skip("machine still has headroom; a second strengthen is legitimate")
		}
		t.Fatal("a second strengthen succeeded with nothing to gain")
	}
}

func TestStrengthenKDFRequiresUnlockedVault(t *testing.T) {
	a := newApp(t)
	a.Lock()
	if res := a.StrengthenKDF("pw"); res.OK {
		t.Fatal("strengthened the KDF on a locked vault")
	}
}
