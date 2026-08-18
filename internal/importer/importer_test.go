package importer

import (
	"bytes"
	"encoding/csv"
	"os"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"

	"kosh/internal/vault"
)

// TestParseExpiry guards the expiry-parsing fix: ISO/locale date strings must parse as
// real dates, not be truncated to their leading integer. The old fmt.Sscanf("%d")
// implementation turned "2025-12-31" into epoch 2025 (Jan 1970), flagging every imported
// secret as already expired.
func TestParseExpiry(t *testing.T) {
	// A real ISO date -> a timestamp far in the future, not ~1970.
	ts, ok := parseExpiry("2025-12-31")
	if !ok {
		t.Fatal(`parseExpiry("2025-12-31") should succeed`)
	}
	if ts < 1_000_000_000 { // ~2001; anything smaller means it was truncated to "2025"
		t.Fatalf("ISO date parsed as %d (looks truncated to a bare integer)", ts)
	}

	// A genuine Unix-seconds string is still accepted verbatim.
	if got, ok := parseExpiry("1767139200"); !ok || got != 1767139200 {
		t.Fatalf("epoch string: got (%d,%v), want (1767139200,true)", got, ok)
	}

	// Non-numeric / unparseable -> not ok.
	if _, ok := parseExpiry("not-a-date"); ok {
		t.Fatal(`parseExpiry("not-a-date") should fail`)
	}
	if _, ok := parseExpiry(""); ok {
		t.Fatal(`parseExpiry("") should fail`)
	}
}

func writeTempCSV(t *testing.T, rows [][]string) string {
	t.Helper()
	f, err := os.CreateTemp("", "test-*.csv")
	if err != nil {
		t.Fatal(err)
	}
	w := csv.NewWriter(f)
	w.WriteAll(rows)
	w.Flush()
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func writeTempXLSX(t *testing.T, rows [][]string) string {
	t.Helper()
	xl := excelize.NewFile()
	sheet := "Sheet1"
	for i, row := range rows {
		for j, cell := range row {
			coord, _ := excelize.CoordinatesToCellName(j+1, i+1)
			xl.SetCellValue(sheet, coord, cell)
		}
	}
	f, err := os.CreateTemp("", "test-*.xlsx")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := xl.SaveAs(f.Name()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

var sampleRows = [][]string{
	{"alias", "value", "provider", "environment", "description"},
	{"OPENAI_DEV", "sk-abc123", "openai", "dev", "Dev OpenAI key"},
	{"AWS_PROD", "AKID...", "aws", "prod", "Prod IAM"},
	{"GITHUB_DEV", "ghp_xyz", "github", "dev", "GitHub PAT"},
}

func TestParseCSV(t *testing.T) {
	path := writeTempCSV(t, sampleRows)
	table, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile csv: %v", err)
	}
	if len(table.Rows) != 3 {
		t.Fatalf("expected 3 data rows, got %d", len(table.Rows))
	}
	if table.Headers[0] != "alias" {
		t.Fatalf("header[0] = %q, want alias", table.Headers[0])
	}
}

func TestParseXLSX(t *testing.T) {
	path := writeTempXLSX(t, sampleRows)
	table, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile xlsx: %v", err)
	}
	if len(table.Rows) != 3 {
		t.Fatalf("expected 3 data rows, got %d", len(table.Rows))
	}
}

func TestUnsupportedExtension(t *testing.T) {
	_, err := ParseFile("secrets.txt")
	if err == nil {
		t.Fatal("expected error for .txt file")
	}
}

func TestDefaultColMapDetectsHeaders(t *testing.T) {
	cm := DefaultColMap(sampleRows[0])
	if cm.Alias != 0 {
		t.Fatalf("Alias col = %d, want 0", cm.Alias)
	}
	if cm.Value != 1 {
		t.Fatalf("Value col = %d, want 1", cm.Value)
	}
	if cm.ProviderKey != 2 {
		t.Fatalf("ProviderKey col = %d, want 2", cm.ProviderKey)
	}
}

func TestMapColumnsProducesRows(t *testing.T) {
	path := writeTempCSV(t, sampleRows)
	table, _ := ParseFile(path)
	cm := DefaultColMap(table.Headers)
	rows, parseErrs := MapColumns(table, cm)
	if len(parseErrs) != 0 {
		t.Fatalf("unexpected parse errors: %v", parseErrs)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	if rows[0].Alias != "OPENAI_DEV" {
		t.Fatalf("alias = %q, want OPENAI_DEV", rows[0].Alias)
	}
	if rows[0].ProviderKey != "openai" {
		t.Fatalf("provider = %q, want openai", rows[0].ProviderKey)
	}
	if rows[1].Environment != "prod" {
		t.Fatalf("env = %q, want prod", rows[1].Environment)
	}
}

func TestMapColumnsMissingAlias(t *testing.T) {
	bad := [][]string{
		{"alias", "value"},
		{"", "sk-empty-alias"},
	}
	table, _ := ParseFile(writeTempCSV(t, bad))
	cm := DefaultColMap(table.Headers)
	rows, errs := MapColumns(table, cm)
	if len(errs) == 0 {
		t.Fatal("expected parse error for empty alias")
	}
	if rows[0].Status != StatusInvalid {
		t.Fatalf("expected StatusInvalid, got %s", rows[0].Status)
	}
}

func TestAliasIsSanitized(t *testing.T) {
	data := [][]string{
		{"alias", "value"},
		{"my-key name.dev", "secret"},
	}
	table, _ := ParseFile(writeTempCSV(t, data))
	cm := DefaultColMap(table.Headers)
	rows, _ := MapColumns(table, cm)
	if rows[0].Alias != "MY_KEY_NAME_DEV" {
		t.Fatalf("alias sanitize = %q, want MY_KEY_NAME_DEV", rows[0].Alias)
	}
}

func TestNormalizeProvider(t *testing.T) {
	cases := [][2]string{
		{"Amazon", "aws"}, {"google cloud", "gcp"}, {"openai", "openai"},
		{"GROQ", "groq"}, {"unknown-service", "custom"},
	}
	for _, c := range cases {
		got := normalizeProvider(c[0])
		if got != c[1] {
			t.Errorf("normalizeProvider(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}

func TestNormalizeEnv(t *testing.T) {
	cases := [][2]string{
		{"production", "prod"}, {"PROD", "prod"}, {"staging", "staging"},
		{"test", "qa"}, {"DEV", "dev"}, {"anything", "dev"},
	}
	for _, c := range cases {
		got := normalizeEnv(c[0])
		if got != c[1] {
			t.Errorf("normalizeEnv(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}

func TestExpiryParsingDate(t *testing.T) {
	ts, ok := parseExpiry("2025-12-31")
	if !ok || ts <= 0 {
		t.Fatal("expected valid expiry from date string")
	}
}

func TestExpiryParsingUnix(t *testing.T) {
	ts, ok := parseExpiry("1893456000")
	if !ok || ts != 1893456000 {
		t.Fatalf("expected unix timestamp 1893456000, got %d ok=%v", ts, ok)
	}
}

func TestCommitInsertsSecrets(t *testing.T) {
	v, err := vault.Open(":memory:", "ui")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Init([]byte("pw")); err != nil {
		t.Fatal(err)
	}

	data := [][]string{
		{"alias", "value", "provider", "environment"},
		{"COMMIT_A", "val-a", "openai", "dev"},
		{"COMMIT_B", "val-b", "aws", "prod"},
	}
	// Build rows directly (no file I/O needed for the commit test).
	tableRows := data[1:]
	var importRows []ImportRow
	for i, r := range tableRows {
		importRows = append(importRows, ImportRow{
			SourceRow:   i + 2,
			Alias:       r[0],
			Value:       r[1],
			ProviderKey: normalizeProvider(r[2]),
			Environment: normalizeEnv(r[3]),
			Status:      StatusPending,
		})
	}

	res, err := Commit(importRows, v)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if res.Imported != 2 {
		t.Fatalf("expected 2 imported, got %d (errors: %v)", res.Imported, res.Errors)
	}

	secrets, err := v.ListNames(vault.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets in vault, got %d", len(secrets))
	}
}

func TestCSVParserCSVContent(t *testing.T) {
	content := "alias,value,provider\nGROQ_DEV,gsk-xyz,groq\n"
	f, _ := os.CreateTemp("", "*.csv")
	f.WriteString(content)
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	table, err := ParseFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if table.Rows[0][0] != "GROQ_DEV" {
		t.Fatalf("first row alias = %q", table.Rows[0][0])
	}
	_ = bytes.NewReader(nil)
	_ = strings.NewReader("")
}
