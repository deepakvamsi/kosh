// Package audit implements a tamper-evident, append-only audit log. Each record is
// hash-chained to the previous one: hash = SHA-256(prev_hash || canonical(record)).
// Any deletion or edit breaks the chain, which VerifyChain detects. Secret values are
// never written to the audit log (see docs/THREAT_MODEL.md §6).
//
// The hash chain alone only resists ACCIDENTAL damage: it involves no secret, so an
// adversary with write access to vault.db can edit a record and recompute every hash
// after it. Resistance to that adversary comes from the keyed layer in keyed.go —
// per-record HMACs under a DEK-derived subkey plus an anchored chain head. Records
// written while the vault is locked cannot be keyed (no DEK exists) and are
// chain-only; see VerifyChainKeyed for exactly what each layer guarantees.
package audit

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
)

// Outcome is either allow or deny.
type Outcome string

const (
	Allow Outcome = "allow"
	Deny  Outcome = "deny"
)

// Record is one audit entry as read back from the log.
type Record struct {
	Seq      int64
	TS       int64
	Actor    string
	Action   string
	Target   string
	Outcome  Outcome
	Detail   string
	PrevHash []byte
	Hash     []byte
}

// genesis is the starting prev_hash for the very first record.
var genesis = make([]byte, sha256.Size)

// canonical builds a deterministic byte encoding of the mutable fields of a record so
// the hash is stable and unambiguous (length-prefixed to avoid field-boundary attacks).
func canonical(ts int64, actor, action, target string, outcome Outcome, detail string) []byte {
	var buf []byte
	appendField := func(s []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(s)))
		buf = append(buf, l[:]...)
		buf = append(buf, s...)
	}
	var tsb [8]byte
	binary.BigEndian.PutUint64(tsb[:], uint64(ts))
	buf = append(buf, tsb[:]...)
	appendField([]byte(actor))
	appendField([]byte(action))
	appendField([]byte(target))
	appendField([]byte(outcome))
	appendField([]byte(detail))
	return buf
}

func chainHash(prev []byte, ts int64, actor, action, target string, outcome Outcome, detail string) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(canonical(ts, actor, action, target, outcome, detail))
	return h.Sum(nil)
}

// LogTx appends a new audit record using the caller's transaction. Because the caller
// controls commit/rollback, the audit entry is written atomically with the mutation it
// records: if the mutation rolls back, so does its audit row, and vice versa. This is
// how state-changing vault operations keep the tamper-evident log consistent with the
// data (see docs/THREAT_MODEL.md §6).
//
// It writes an unauthenticated (chain-only) record. Prefer LogTxKeyed with the vault's
// audit subkey whenever the vault is unlocked — an unkeyed record can be rewritten by
// anyone with database write access.
func LogTx(tx *sql.Tx, actor, action, target string, outcome Outcome, detail string) error {
	return LogTxKeyed(tx, nil, actor, action, target, outcome, detail)
}

// Log appends a new audit record in its own transaction. Use it for session-lifecycle
// events (unlock/autolock) that have no surrounding data mutation; state-changing
// operations should use LogTx so the audit row shares the mutation's transaction.
func Log(db *sql.DB, actor, action, target string, outcome Outcome, detail string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := LogTx(tx, actor, action, target, outcome, detail); err != nil {
		return err
	}
	return tx.Commit()
}

// VerifyChain walks the entire log in order and returns the seq of the first record
// whose chain is inconsistent, or 0 if the whole chain is intact.
func VerifyChain(db *sql.DB) (badSeq int64, err error) {
	rows, err := db.Query(`SELECT seq,ts,actor,action,target,outcome,detail,prev_hash,hash FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	expectedPrev := genesis
	for rows.Next() {
		var r Record
		var oc string
		if err := rows.Scan(&r.Seq, &r.TS, &r.Actor, &r.Action, &r.Target, &oc, &r.Detail, &r.PrevHash, &r.Hash); err != nil {
			return 0, err
		}
		r.Outcome = Outcome(oc)
		if !bytes.Equal(r.PrevHash, expectedPrev) {
			return r.Seq, nil
		}
		want := chainHash(r.PrevHash, r.TS, r.Actor, r.Action, r.Target, r.Outcome, r.Detail)
		if !bytes.Equal(want, r.Hash) {
			return r.Seq, nil
		}
		expectedPrev = r.Hash
	}
	return 0, rows.Err()
}

// List returns the most recent n records, newest first.
func List(db *sql.DB, n int) ([]Record, error) {
	rows, err := db.Query(`SELECT seq,ts,actor,action,target,outcome,detail,prev_hash,hash FROM audit_log ORDER BY seq DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		var oc string
		if err := rows.Scan(&r.Seq, &r.TS, &r.Actor, &r.Action, &r.Target, &oc, &r.Detail, &r.PrevHash, &r.Hash); err != nil {
			return nil, err
		}
		r.Outcome = Outcome(oc)
		out = append(out, r)
	}
	return out, rows.Err()
}
