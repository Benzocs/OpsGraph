package database

import (
	"path/filepath"
	"testing"
)

func TestDatabaseOpsGraphInitCreatesTables(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "adaptix-test.db")

	dbms, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("NewDatabase failed: %v", err)
	}
	defer dbms.database.Close()

	tables := []string{
		"OpsGraphNodes",
		"OpsGraphEdges",
		"OpsGraphEvidence",
		"OpsGraphCursors",
		"OpsGraphSettings",
		"OpsGraphParseErrors",
		"OpsGraphDelta",
	}

	for _, table := range tables {
		var name string
		err := dbms.database.QueryRow(
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?;`,
			table,
		).Scan(&name)

		if err != nil {
			t.Fatalf("expected table %s to exist: %v", table, err)
		}

		if name != table {
			t.Fatalf("expected table %s, got %s", table, name)
		}
	}
}
