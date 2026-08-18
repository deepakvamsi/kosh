// Package importer provides a local-only, one-time migration path from existing
// Excel (.xlsx) and CSV files into the Kosh encrypted database.
//
// Security properties:
//   - All parsing and encryption happen in process; no file content leaves the machine.
//   - Plaintext values are held only long enough to encrypt them; buffers are zeroized.
//   - Duplicate detection: if the vault already holds the same credential (same keyed
//     hash) an ImportRow is flagged as a duplicate and skipped by default.
//   - The caller is reminded to delete the source spreadsheet after a successful import.
//
// Workflow:
//  1. Call ParseFile(path) to get raw [][]string rows.
//  2. Call MapColumns(rows, ColMap) to produce []ImportRow for preview.
//  3. User reviews the preview, fixes the column mapping if needed.
//  4. Call Commit(rows, vault) to encrypt every approved row into the vault.
package importer

import (
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xuri/excelize/v2"
)

// ParseError records a row that could not be parsed.
type ParseError struct {
	Row     int
	Message string
}

func (e ParseError) Error() string {
	return fmt.Sprintf("row %d: %s", e.Row, e.Message)
}

// RawTable is the parsed content of a file before column mapping.
// Row 0 is the header (if present).
type RawTable struct {
	Headers []string
	Rows    [][]string
}

// ParseFile reads an .xlsx or .csv file and returns a RawTable.
// The file is read entirely in memory; no temp files are created.
func ParseFile(path string) (RawTable, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".xlsx", ".xls":
		return parseXLSX(path)
	case ".csv":
		return parseCSV(path)
	default:
		return RawTable{}, fmt.Errorf("importer: unsupported file type %q (want .xlsx or .csv)", ext)
	}
}

func parseXLSX(path string) (RawTable, error) {
	f, err := excelize.OpenFile(path)
	if err != nil {
		return RawTable{}, fmt.Errorf("importer: open xlsx: %w", err)
	}
	defer f.Close()

	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return RawTable{}, errors.New("importer: xlsx has no sheets")
	}
	rows, err := f.GetRows(sheets[0])
	if err != nil {
		return RawTable{}, fmt.Errorf("importer: read xlsx rows: %w", err)
	}
	return rowsToTable(rows), nil
}

func parseCSV(path string) (RawTable, error) {
	fh, err := os.Open(path)
	if err != nil {
		return RawTable{}, fmt.Errorf("importer: open csv: %w", err)
	}
	defer fh.Close()

	r := csv.NewReader(fh)
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	rows, err := r.ReadAll()
	if err != nil {
		return RawTable{}, fmt.Errorf("importer: read csv: %w", err)
	}
	return rowsToTable(rows), nil
}

func rowsToTable(rows [][]string) RawTable {
	if len(rows) == 0 {
		return RawTable{}
	}
	return RawTable{Headers: rows[0], Rows: rows[1:]}
}
