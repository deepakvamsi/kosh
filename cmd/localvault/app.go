package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	lv_audit "kosh/internal/audit"
	lv_backup "kosh/internal/backup"
	lv_datadir "kosh/internal/datadir"
	lv_health "kosh/internal/health"
	lv_importer "kosh/internal/importer"
	lv_screenguard "kosh/internal/screenguard"
	lv_vault "kosh/internal/vault"
)

// errVaultUnavailable is returned by bound methods when the database could not be opened
// at startup (a.vault is nil). Guarding on it turns what used to be a nil-pointer panic
// into a clean, surfaced error the UI can display.
var errVaultUnavailable = errors.New("vault unavailable: the database failed to open")

// autoLockCheckInterval is how often the backend re-evaluates the idle timeout. The
// actual timeout is read from the autolock_seconds setting each tick.
const autoLockCheckInterval = 10 * time.Second

type App struct {
	ctx    context.Context
	vault  *lv_vault.Vault
	dbPath string
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	dbPath, err := lv_datadir.DBPath()
	if err != nil {
		runtime.LogErrorf(ctx, "datadir: %v", err)
		dbPath = "vault.db"
	}
	a.dbPath = dbPath

	v, err := lv_vault.Open(dbPath, "ui")
	if err != nil {
		runtime.LogErrorf(ctx, "vault open: %v", err)
		return
	}
	a.vault = v

	// Authoritative, backend-enforced auto-lock. The frontend also runs an activity
	// timer for prompt UX, but the DEK lives in Go memory, so the guarantee that it is
	// wiped on idle must be enforced here — independent of whether the webview is alive,
	// focused, or cooperating.
	go a.autoLockLoop(ctx)
}

// autoLockLoop periodically zeroizes the DEK if the vault has been idle longer than the
// configured timeout. It runs for the lifetime of the app context.
func (a *App) autoLockLoop(ctx context.Context) {
	ticker := time.NewTicker(autoLockCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.vault == nil {
				continue
			}
			secs := a.autoLockSeconds()
			if secs <= 0 {
				continue // auto-lock disabled
			}
			if a.vault.AutoLockIfIdle(time.Duration(secs) * time.Second) {
				// Tell the UI to drop to the lock screen; the DEK is already gone.
				runtime.EventsEmit(ctx, "vault:locked")
			}
		}
	}
}

// autoLockSeconds reads the configured idle timeout (seconds) from settings, defaulting
// to 300s. A value of 0 disables auto-lock.
func (a *App) autoLockSeconds() int {
	const def = 300
	if a.vault == nil {
		return def
	}
	var val string
	if err := a.vault.DB().SQL().QueryRow(`SELECT value FROM settings WHERE key='autolock_seconds'`).Scan(&val); err != nil {
		return def
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return def
	}
	return n
}

// Touch records UI activity so the idle auto-lock timer resets. The frontend calls this
// (throttled) on user interaction.
func (a *App) Touch() {
	if a.vault != nil {
		a.vault.Touch()
	}
}

func (a *App) domReady(ctx context.Context) {
	res := lv_screenguard.Apply(0)
	if !res.Applied {
		runtime.LogWarningf(ctx, "screenguard: %s", res.Note)
	}
}

func (a *App) beforeClose(ctx context.Context) bool {
	if a.vault != nil {
		a.vault.Close()
	}
	return false
}

type BoolResult struct {
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
}

type IDResult struct {
	ID  int64  `json:"id"`
	Err string `json:"err,omitempty"`
}

func ok() BoolResult { return BoolResult{OK: true} }
func fail(err error) BoolResult {
	if err == nil {
		return ok()
	}
	return BoolResult{Err: err.Error()}
}

func (a *App) IsInitialized() bool {
	if a.vault == nil {
		return false
	}
	init, _ := a.vault.IsInitialized()
	return init
}

func (a *App) IsUnlocked() bool {
	return a.vault != nil && a.vault.Unlocked()
}

func (a *App) InitVault(password string) BoolResult {
	if a.vault == nil {
		return BoolResult{Err: "vault not opened"}
	}
	return fail(a.vault.Init([]byte(password)))
}

func (a *App) Unlock(password string) BoolResult {
	if a.vault == nil {
		return BoolResult{Err: "vault not opened"}
	}
	return fail(a.vault.Unlock([]byte(password)))
}

// UnlockStatus returns the seconds the vault is currently locked out for after repeated
// failed attempts (0 if an unlock may be tried now). The unlock screen polls this to show
// a countdown and disable the button; it survives app restarts.
func (a *App) UnlockStatus() int {
	if a.vault == nil {
		return 0
	}
	return a.vault.LockoutRemaining()
}

func (a *App) Lock() {
	if a.vault != nil {
		a.vault.Lock()
	}
}

// HasRecoveryKey reports whether a recovery key is configured (used to show/hide the
// "recover with key" option on the unlock screen).
func (a *App) HasRecoveryKey() bool {
	if a.vault == nil {
		return false
	}
	has, _ := a.vault.HasRecoveryKey()
	return has
}

// GenerateRecoveryKey creates (or replaces) the recovery key and returns the code ONCE.
// Requires the vault to be unlocked.
func (a *App) GenerateRecoveryKey() (string, error) {
	if a.vault == nil {
		return "", errVaultUnavailable
	}
	return a.vault.GenerateRecoveryKey()
}

// RecoverWithKey unlocks the vault with a recovery code and resets the master password.
func (a *App) RecoverWithKey(recoveryCode, newPassword string) BoolResult {
	if a.vault == nil {
		return BoolResult{Err: errVaultUnavailable.Error()}
	}
	return fail(a.vault.RecoverWithKey(recoveryCode, []byte(newPassword)))
}

type SecretSummaryDTO struct {
	ID           int64    `json:"id"`
	Alias        string   `json:"alias"`
	ItemType     string   `json:"itemType"`
	ProviderKey  string   `json:"providerKey"`
	ProviderName string   `json:"providerName"`
	Environment  string   `json:"environment"`
	Tags         []string `json:"tags"`
	FolderName   string   `json:"folderName"`
	Description  string   `json:"description"`
	ExpiresAt    *int64   `json:"expiresAt"`
	LastUsedAt   *int64   `json:"lastUsedAt"`
	IsArchived   bool     `json:"isArchived"`
}

func (a *App) ListSecrets(search, provider, env string, includeArchived bool) ([]SecretSummaryDTO, error) {
	if a.vault == nil {
		return nil, errVaultUnavailable
	}
	summaries, err := a.vault.ListNames(lv_vault.ListFilter{
		Search:          search,
		ProviderKey:     provider,
		Environment:     lv_vault.Environment(env),
		IncludeArchived: includeArchived,
	})
	if err != nil {
		return nil, err
	}
	out := make([]SecretSummaryDTO, len(summaries))
	for i, s := range summaries {
		out[i] = SecretSummaryDTO{
			ID: s.ID, Alias: s.Alias, ItemType: string(s.ItemType), ProviderKey: s.ProviderKey,
			ProviderName: s.ProviderName, Environment: string(s.Environment),
			Tags: s.Tags, FolderName: s.FolderName, Description: s.Description,
			ExpiresAt: s.ExpiresAt, LastUsedAt: s.LastUsedAt, IsArchived: s.IsArchived,
		}
	}
	return out, nil
}

func (a *App) RevealSecret(alias string) (string, error) {
	if a.vault == nil {
		return "", errVaultUnavailable
	}
	b, err := a.vault.Reveal(alias)
	if err != nil {
		return "", err
	}
	v := string(b)
	for i := range b {
		b[i] = 0
	}
	return v, nil
}

type AddSecretInput struct {
	Alias        string `json:"alias"`
	ItemType     string `json:"itemType"` // "api_key" (default) | "login" | "secure_note"
	ProviderKey  string `json:"providerKey"`
	Environment  string `json:"environment"`
	Description  string `json:"description"`
	Value        string `json:"value"`    // api_key
	Username     string `json:"username"` // login
	Password     string `json:"password"` // login
	Note         string `json:"note"`     // secure_note
	ExpiresAt    *int64 `json:"expiresAt"`
	RotationDays *int   `json:"rotationDays"`
}

func (a *App) AddSecret(in AddSecretInput) IDResult {
	if a.vault == nil {
		return IDResult{Err: errVaultUnavailable.Error()}
	}
	id, err := a.vault.AddSecret(lv_vault.AddSecretInput{
		Alias:        in.Alias,
		ItemType:     lv_vault.ItemType(in.ItemType),
		ProviderKey:  in.ProviderKey,
		Environment:  lv_vault.Environment(in.Environment),
		Description:  in.Description,
		Value:        []byte(in.Value),
		Username:     in.Username,
		Password:     in.Password,
		Note:         in.Note,
		ExpiresAt:    in.ExpiresAt,
		RotationDays: in.RotationDays,
	})
	if err != nil {
		return IDResult{Err: err.Error()}
	}
	return IDResult{ID: id}
}

// RevealedItemDTO is the decoded, type-aware reveal returned to the UI. Only the fields
// relevant to ItemType are populated.
type RevealedItemDTO struct {
	ItemType string `json:"itemType"`
	Value    string `json:"value"`
	Username string `json:"username"`
	Password string `json:"password"`
	Note     string `json:"note"`
	Err      string `json:"err,omitempty"`
}

// RevealItem decrypts an entry and returns it decoded per its stored type (api_key /
// login / secure_note). This is the reveal path the UI should use so a login surfaces its
// username and password as separate, individually-copyable fields.
func (a *App) RevealItem(alias string) RevealedItemDTO {
	if a.vault == nil {
		return RevealedItemDTO{Err: errVaultUnavailable.Error()}
	}
	r, err := a.vault.RevealItem(alias)
	if err != nil {
		return RevealedItemDTO{Err: err.Error()}
	}
	return RevealedItemDTO{
		ItemType: string(r.ItemType),
		Value:    r.Value,
		Username: r.Username,
		Password: r.Password,
		Note:     r.Note,
	}
}

func (a *App) UpdateSecretValue(alias, newValue string) BoolResult {
	if a.vault == nil {
		return BoolResult{Err: errVaultUnavailable.Error()}
	}
	return fail(a.vault.UpdateValue(alias, []byte(newValue)))
}

func (a *App) DeleteSecret(alias string) BoolResult {
	if a.vault == nil {
		return BoolResult{Err: errVaultUnavailable.Error()}
	}
	return fail(a.vault.DeleteSecret(alias))
}

func (a *App) ArchiveSecret(alias string, archived bool) BoolResult {
	if a.vault == nil {
		return BoolResult{Err: errVaultUnavailable.Error()}
	}
	return fail(a.vault.ArchiveSecret(alias, archived))
}

func (a *App) TagSecret(alias, tag string) BoolResult {
	if a.vault == nil {
		return BoolResult{Err: errVaultUnavailable.Error()}
	}
	return fail(a.vault.TagSecret(alias, tag))
}

func (a *App) GetCustomFields(alias string) (string, error) {
	if a.vault == nil {
		return "", errVaultUnavailable
	}
	return a.vault.GetCustomFields(alias)
}

func (a *App) SetCustomFields(alias, jsonFields string) BoolResult {
	if a.vault == nil {
		return BoolResult{Err: errVaultUnavailable.Error()}
	}
	return fail(a.vault.SetCustomFields(alias, jsonFields))
}

type HealthDTO struct {
	SecretID   int64    `json:"secretId"`
	Alias      string   `json:"alias"`
	Status     string   `json:"status"`
	Flags      []string `json:"flags"`
	Score      int      `json:"score"`
	DupAliases []string `json:"dupAliases"`
}

func (a *App) GetHealth() ([]HealthDTO, error) {
	if a.vault == nil {
		return nil, errVaultUnavailable
	}
	results, err := lv_health.Score(a.vault.DB().SQL(), lv_health.DefaultConfig())
	if err != nil {
		return nil, err
	}
	out := make([]HealthDTO, len(results))
	for i, h := range results {
		flags := make([]string, len(h.Flags))
		for j, f := range h.Flags {
			flags[j] = string(f)
		}
		out[i] = HealthDTO{
			SecretID: h.SecretID, Alias: h.Alias, Status: string(h.Status),
			Flags: flags, Score: h.Score, DupAliases: h.DupAliases,
		}
	}
	return out, nil
}

type AuditDTO struct {
	Seq     int64  `json:"seq"`
	TS      int64  `json:"ts"`
	Actor   string `json:"actor"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
}

func (a *App) GetAuditLog(limit int) ([]AuditDTO, error) {
	if a.vault == nil {
		return nil, errVaultUnavailable
	}
	if limit <= 0 {
		limit = 200
	}
	records, err := lv_audit.List(a.vault.DB().SQL(), limit)
	if err != nil {
		return nil, err
	}
	out := make([]AuditDTO, len(records))
	for i, r := range records {
		out[i] = AuditDTO{
			Seq: r.Seq, TS: r.TS, Actor: r.Actor, Action: r.Action,
			Target: r.Target, Outcome: string(r.Outcome), Detail: r.Detail,
		}
	}
	return out, nil
}

func (a *App) VerifyAuditChain() (int64, error) {
	if a.vault == nil {
		return 0, errVaultUnavailable
	}
	return lv_audit.VerifyChain(a.vault.DB().SQL())
}

func (a *App) ExportBackup(password string) ([]byte, error) {
	if a.vault == nil {
		return nil, errVaultUnavailable
	}
	return lv_backup.Export(a.vault.DB().SQL(), []byte(password))
}

func (a *App) ImportBackup(data []byte, password string) BoolResult {
	if a.vault == nil {
		return BoolResult{Err: errVaultUnavailable.Error()}
	}
	if err := lv_backup.Import(a.vault.DB().SQL(), data, []byte(password)); err != nil {
		return fail(err)
	}
	// A restore replaces the vault's key material, so the in-memory DEK is now stale.
	// Lock so the user re-unlocks with the backup's master password.
	a.vault.Lock()
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "vault:locked")
	}
	return ok()
}

type ProviderDTO struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Builtin  bool   `json:"builtin"`
}

func (a *App) ListProviders() ([]ProviderDTO, error) {
	if a.vault == nil {
		return nil, errVaultUnavailable
	}
	rows, err := a.vault.DB().SQL().Query(`SELECT key,name,category,is_builtin FROM providers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProviderDTO
	for rows.Next() {
		var p ProviderDTO
		var b int
		if err := rows.Scan(&p.Key, &p.Name, &p.Category, &b); err != nil {
			return nil, err
		}
		p.Builtin = b == 1
		out = append(out, p)
	}
	return out, rows.Err()
}

type AddProviderInput struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

func (a *App) AddProvider(in AddProviderInput) BoolResult {
	if a.vault == nil {
		return BoolResult{Err: errVaultUnavailable.Error()}
	}
	if !a.vault.Unlocked() {
		return BoolResult{Err: lv_vault.ErrLocked.Error()}
	}
	if in.Key == "" || in.Name == "" {
		return BoolResult{Err: "key and name are required"}
	}
	_, err := a.vault.DB().SQL().Exec(
		`INSERT INTO providers(key,name,category,is_builtin,created_at) VALUES(?,?,?,0,?)`,
		in.Key, in.Name, in.Category, time.Now().Unix())
	return fail(err)
}

func (a *App) DeleteProvider(key string) BoolResult {
	if a.vault == nil {
		return BoolResult{Err: errVaultUnavailable.Error()}
	}
	if !a.vault.Unlocked() {
		return BoolResult{Err: lv_vault.ErrLocked.Error()}
	}
	var isBuiltin int
	a.vault.DB().SQL().QueryRow(`SELECT is_builtin FROM providers WHERE key=?`, key).Scan(&isBuiltin)
	if isBuiltin == 1 {
		return BoolResult{Err: "cannot delete a built-in provider"}
	}
	_, err := a.vault.DB().SQL().Exec(`DELETE FROM providers WHERE key=? AND is_builtin=0`, key)
	return fail(err)
}

func (a *App) ResetVault() BoolResult {
	if a.vault != nil {
		a.vault.Close()
		a.vault = nil
	}
	if a.dbPath == "" || a.dbPath == ":memory:" {
		return BoolResult{Err: "no vault path set"}
	}
	// Remove the database and its WAL/SHM siblings. Deleting only vault.db while a -wal
	// file survives can resurrect committed-but-uncheckpointed data on the next open.
	for _, p := range []string{a.dbPath, a.dbPath + "-wal", a.dbPath + "-shm"} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return BoolResult{Err: err.Error()}
		}
	}
	return BoolResult{OK: true}
}

func (a *App) GetSetting(key string) string {
	if a.vault == nil {
		return ""
	}
	var val string
	a.vault.DB().SQL().QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&val)
	return val
}

func (a *App) SetSetting(key, value string) BoolResult {
	if a.vault == nil {
		return BoolResult{Err: errVaultUnavailable.Error()}
	}
	_, err := a.vault.DB().SQL().Exec(
		`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value)
	return fail(err)
}

func (a *App) GetVaultPath() string { return a.dbPath }

func (a *App) GetCurrentTime() int64 { return time.Now().Unix() }

type AddKeyPairInput struct {
	AccessKeyAlias string `json:"accessKeyAlias"`
	AccessKeyValue string `json:"accessKeyValue"`
	SecretKeyAlias string `json:"secretKeyAlias"`
	SecretKeyValue string `json:"secretKeyValue"`
	ProviderKey    string `json:"providerKey"`
	Environment    string `json:"environment"`
	Description    string `json:"description"`
	ExpiresAt      *int64 `json:"expiresAt"`
}

type AddKeyPairResult struct {
	AccessKeyID int64  `json:"accessKeyId"`
	SecretKeyID int64  `json:"secretKeyId"`
	Err         string `json:"err,omitempty"`
}

func (a *App) AddKeyPair(in AddKeyPairInput) AddKeyPairResult {
	if a.vault == nil {
		return AddKeyPairResult{Err: errVaultUnavailable.Error()}
	}
	if !a.vault.Unlocked() {
		return AddKeyPairResult{Err: lv_vault.ErrLocked.Error()}
	}

	akID, err := a.vault.AddSecret(lv_vault.AddSecretInput{
		Alias:       in.AccessKeyAlias,
		ProviderKey: in.ProviderKey,
		Environment: lv_vault.Environment(in.Environment),
		Description: in.Description,
		Value:       []byte(in.AccessKeyValue),
		ExpiresAt:   in.ExpiresAt,
	})
	if err != nil {
		return AddKeyPairResult{Err: "access key: " + err.Error()}
	}

	skID, err := a.vault.AddSecret(lv_vault.AddSecretInput{
		Alias:       in.SecretKeyAlias,
		ProviderKey: in.ProviderKey,
		Environment: lv_vault.Environment(in.Environment),
		Description: in.Description,
		Value:       []byte(in.SecretKeyValue),
		ExpiresAt:   in.ExpiresAt,
	})
	if err != nil {
		_ = a.vault.DeleteSecret(in.AccessKeyAlias)
		return AddKeyPairResult{Err: "secret key: " + err.Error()}
	}

	return AddKeyPairResult{AccessKeyID: akID, SecretKeyID: skID}
}

type ImportRowDTO struct {
	SourceRow   int    `json:"sourceRow"`
	Alias       string `json:"alias"`
	Value       string `json:"value"`
	ProviderKey string `json:"providerKey"`
	Environment string `json:"environment"`
	Description string `json:"description"`
	ExpiresAt   *int64 `json:"expiresAt"`
	Status      string `json:"status"`
	StatusNote  string `json:"statusNote"`
}

type ImportPreviewResult struct {
	Headers []string       `json:"headers"`
	Rows    []ImportRowDTO `json:"rows"`
	ColMap  ColMapDTO      `json:"colMap"`
	Errors  []string       `json:"errors"`
}

type ColMapDTO struct {
	Alias       int `json:"alias"`
	Value       int `json:"value"`
	ProviderKey int `json:"providerKey"`
	Environment int `json:"environment"`
	Description int `json:"description"`
	ExpiresAt   int `json:"expiresAt"`
}

type ImportCommitResult struct {
	Imported  int      `json:"imported"`
	Skipped   int      `json:"skipped"`
	Duplicate int      `json:"duplicate"`
	Invalid   int      `json:"invalid"`
	Errors    []string `json:"errors"`
}

func (a *App) ImportPreview(filePath string, cm ColMapDTO) (ImportPreviewResult, error) {
	if a.vault == nil {
		return ImportPreviewResult{}, errVaultUnavailable
	}
	if !a.vault.Unlocked() {
		return ImportPreviewResult{}, lv_vault.ErrLocked
	}

	table, err := lv_importer.ParseFile(filePath)
	if err != nil {
		return ImportPreviewResult{}, err
	}

	icm := lv_importer.ColMap{
		Alias: cm.Alias, Value: cm.Value, ProviderKey: cm.ProviderKey,
		Environment: cm.Environment, Description: cm.Description, ExpiresAt: cm.ExpiresAt,
	}
	if cm.Alias < 0 && len(table.Headers) > 0 {
		auto := lv_importer.DefaultColMap(table.Headers)
		icm = auto
	}

	rows, parseErrs := lv_importer.MapColumns(table, icm)

	var errStrs []string
	for _, e := range parseErrs {
		errStrs = append(errStrs, e.Error())
	}

	dtos := make([]ImportRowDTO, len(rows))
	for i, r := range rows {
		dtos[i] = ImportRowDTO{
			SourceRow: r.SourceRow, Alias: r.Alias, Value: r.Value,
			ProviderKey: r.ProviderKey, Environment: r.Environment,
			Description: r.Description, ExpiresAt: r.ExpiresAt,
			Status: string(r.Status), StatusNote: r.StatusNote,
		}
	}

	return ImportPreviewResult{
		Headers: table.Headers,
		Rows:    dtos,
		ColMap:  ColMapDTO{Alias: icm.Alias, Value: icm.Value, ProviderKey: icm.ProviderKey, Environment: icm.Environment, Description: icm.Description, ExpiresAt: icm.ExpiresAt},
		Errors:  errStrs,
	}, nil
}

func (a *App) ImportCommit(filePath string, cm ColMapDTO) (ImportCommitResult, error) {
	if a.vault == nil {
		return ImportCommitResult{}, errVaultUnavailable
	}
	if !a.vault.Unlocked() {
		return ImportCommitResult{}, lv_vault.ErrLocked
	}

	table, err := lv_importer.ParseFile(filePath)
	if err != nil {
		return ImportCommitResult{}, err
	}

	icm := lv_importer.ColMap{
		Alias: cm.Alias, Value: cm.Value, ProviderKey: cm.ProviderKey,
		Environment: cm.Environment, Description: cm.Description, ExpiresAt: cm.ExpiresAt,
	}
	if cm.Alias < 0 && len(table.Headers) > 0 {
		icm = lv_importer.DefaultColMap(table.Headers)
	}

	rows, _ := lv_importer.MapColumns(table, icm)
	res, err := lv_importer.Commit(rows, a.vault)
	if err != nil {
		return ImportCommitResult{}, err
	}
	return ImportCommitResult{
		Imported: res.Imported, Skipped: res.Skipped,
		Duplicate: res.Duplicate, Invalid: res.Invalid, Errors: res.Errors,
	}, nil
}

func (a *App) GetVersion() string { return "Kosh v0.1.0-alpha (Phase 3)" }
