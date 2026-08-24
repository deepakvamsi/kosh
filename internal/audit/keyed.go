package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// ErrNoAnchor reports that the log contains keyed records but vault_meta holds no head
// anchor. That combination should be impossible — every keyed append rewrites the
// anchor in the same transaction — so it is treated as tampering, not as a missing
// feature.
var ErrNoAnchor = errors.New("audit: keyed records present but the head anchor is missing")

// recordMAC authenticates one record. hash already commits to prev_hash and every
// mutable field of the record (see chainHash), so a MAC over it pins the record's
// content AND its position in the chain.
func recordMAC(key, hash []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("kosh/audit-record-v1"))
	m.Write(hash)
	return m.Sum(nil)
}

// anchorMAC authenticates the head of the chain: the sequence number of the newest
// keyed record together with its hash. Without this, an attacker could delete a
// trailing run of records — a per-record MAC cannot detect the absence of a record it
// was never written for.
func anchorMAC(key []byte, seq int64, hash []byte) []byte {
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], uint64(seq))
	m := hmac.New(sha256.New, key)
	m.Write([]byte("kosh/audit-anchor-v1"))
	m.Write(s[:])
	m.Write(hash)
	return m.Sum(nil)
}

// LogTxKeyed appends a record inside the caller's transaction, authenticating it with
// key when one is available. A nil or empty key degrades to the plain hash-chained
// append used for events that occur while the vault is locked (failed unlock, lockout),
// where no DEK-derived subkey exists.
//
// When keyed, the record's MAC and the vault's head anchor are written in the SAME
// transaction as the record, so the anchor can never drift from the log.
func LogTxKeyed(tx *sql.Tx, key []byte, actor, action, target string, outcome Outcome, detail string) error {
	var prev []byte
	err := tx.QueryRow(`SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err == sql.ErrNoRows {
		prev = genesis
	} else if err != nil {
		return fmt.Errorf("audit: read last hash: %w", err)
	}

	ts := time.Now().Unix()
	h := chainHash(prev, ts, actor, action, target, outcome, detail)

	var mac []byte
	if len(key) > 0 {
		mac = recordMAC(key, h)
	}

	res, err := tx.Exec(
		`INSERT INTO audit_log(ts,actor,action,target,outcome,detail,prev_hash,hash,mac) VALUES(?,?,?,?,?,?,?,?,?)`,
		ts, actor, action, target, string(outcome), detail, prev, h, mac,
	)
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	if len(key) == 0 {
		return nil
	}

	seq, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("audit: last insert id: %w", err)
	}
	upd, err := tx.Exec(
		`UPDATE vault_meta SET audit_head_seq=?, audit_head_mac=? WHERE id=1`,
		seq, anchorMAC(key, seq, h),
	)
	if err != nil {
		return fmt.Errorf("audit: update head anchor: %w", err)
	}
	// A keyed append with nowhere to store the anchor would leave the log claiming
	// protection it does not have, so it is an error rather than a silent no-op.
	// Init writes the vault_meta row inside the same transaction as its first record,
	// so this holds from the very first append onward.
	n, err := upd.RowsAffected()
	if err != nil {
		return fmt.Errorf("audit: head anchor rows affected: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("audit: head anchor not stored (vault_meta rows updated: %d)", n)
	}
	return nil
}

// LogKeyed appends an authenticated record in its own transaction.
func LogKeyed(db *sql.DB, key []byte, actor, action, target string, outcome Outcome, detail string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := LogTxKeyed(tx, key, actor, action, target, outcome, detail); err != nil {
		return err
	}
	return tx.Commit()
}

// VerifyChainKeyed performs the full tamper check. It walks the chain exactly as
// VerifyChain does, and additionally:
//
//   - verifies every record that carries a MAC, which an attacker without the DEK
//     cannot forge or recompute;
//   - verifies the head anchor in vault_meta, which catches truncation of the tail.
//
// It returns the seq of the first record that fails, or 0 when the log is intact.
// Records with a NULL mac are checked chain-only: they were written while the vault was
// locked and no key existed. Stripping a MAC to dodge detection does not help an
// attacker — every later keyed record's MAC covers a hash that transitively depends on
// the stripped record, so the forgery cascades into a MAC they cannot recompute.
//
// Callers must pass the same DEK-derived subkey used for appends. Use VerifyChain when
// the vault is locked and no key is available; it still detects corruption and
// non-adversarial damage.
func VerifyChainKeyed(db *sql.DB, key []byte) (badSeq int64, err error) {
	if len(key) == 0 {
		return 0, errors.New("audit: VerifyChainKeyed requires a key")
	}

	rows, err := db.Query(`SELECT seq,ts,actor,action,target,outcome,detail,prev_hash,hash,mac FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var (
		expectedPrev = genesis
		lastKeyedSeq int64
		lastKeyedHsh []byte
		keyedSeen    bool
	)
	for rows.Next() {
		var (
			r  Record
			oc string
			mc []byte
		)
		if err := rows.Scan(&r.Seq, &r.TS, &r.Actor, &r.Action, &r.Target, &oc, &r.Detail, &r.PrevHash, &r.Hash, &mc); err != nil {
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
		if len(mc) > 0 {
			if !hmac.Equal(mc, recordMAC(key, r.Hash)) {
				return r.Seq, nil
			}
			keyedSeen = true
			lastKeyedSeq = r.Seq
			lastKeyedHsh = append([]byte(nil), r.Hash...)
		}
		expectedPrev = r.Hash
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	var (
		headSeq sql.NullInt64
		headMAC []byte
	)
	if err := db.QueryRow(`SELECT audit_head_seq, audit_head_mac FROM vault_meta WHERE id=1`).
		Scan(&headSeq, &headMAC); err != nil {
		return 0, fmt.Errorf("audit: read head anchor: %w", err)
	}
	anchored := headSeq.Valid && len(headMAC) > 0

	if !keyedSeen {
		// No MACs anywhere. Either this is a pre-0008 vault (or one that has only ever
		// logged locked-state events), or an attacker stripped every MAC to make a
		// rewritten log look like a legacy one. The anchor tells the two apart: a
		// genuine legacy vault has never written one. Without this check, stripping
		// MACs would be a complete bypass.
		if anchored {
			return headSeq.Int64, nil
		}
		return 0, nil
	}

	if !anchored {
		return lastKeyedSeq, ErrNoAnchor
	}
	// The anchor must name the newest keyed record still present. A lower anchor means
	// records after it were removed along with their MACs.
	if headSeq.Int64 != lastKeyedSeq {
		return lastKeyedSeq, nil
	}
	if !hmac.Equal(headMAC, anchorMAC(key, lastKeyedSeq, lastKeyedHsh)) {
		return lastKeyedSeq, nil
	}
	return 0, nil
}
