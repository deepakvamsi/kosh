// Package importer — commit phase: encrypt mapped rows into the vault.
package importer

import (
	"fmt"

	"kosh/internal/crypto"
	"kosh/internal/vault"
)

// CommitResult summarises what happened after a Commit call.
type CommitResult struct {
	Imported  int
	Skipped   int
	Duplicate int
	Invalid   int
	Errors    []string
}

// Commit iterates over rows that are still StatusPending and adds each one to the
// vault as a new secret. Duplicates (same keyed hash) and invalid rows are not added
// but are counted. The caller must lock/hold the vault unlocked for the duration.
//
// Each plaintext value buffer is zeroized immediately after encryption.
func Commit(rows []ImportRow, v *vault.Vault) (CommitResult, error) {
	var res CommitResult

	for i := range rows {
		r := &rows[i]
		switch r.Status {
		case StatusInvalid:
			res.Invalid++
			continue
		case StatusDuplicate:
			res.Duplicate++
			continue
		case StatusSkipped:
			res.Skipped++
			continue
		}

		// AddSecret zeroizes the Value buffer it is handed; zero our copy as well as soon
		// as the call returns so plaintext does not linger for the rest of the loop.
		// (A deferred Zero here would pile up until Commit returns, keeping every row's
		// plaintext resident in memory — the opposite of the intent.)
		val := []byte(r.Value)

		_, err := v.AddSecret(vault.AddSecretInput{
			Alias:       r.Alias,
			ProviderKey: r.ProviderKey,
			Environment: vault.Environment(r.Environment),
			Description: r.Description,
			Value:       val,
			ExpiresAt:   r.ExpiresAt,
		})
		crypto.Zero(val)
		if err != nil {
			r.Status = StatusInvalid
			r.StatusNote = err.Error()
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %s", r.Alias, err))
			res.Invalid++
		} else {
			r.Status = StatusImported
			res.Imported++
		}
	}
	return res, nil
}
