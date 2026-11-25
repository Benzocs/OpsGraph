package database

import (
	"context"
	"path/filepath"
	"testing"

	"AdaptixServer/core/opsgraph"
)

func TestOpsGraphStoreIngestAgentSnapshot(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "adaptix-test.db")

	dbms, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("NewDatabase failed: %v", err)
	}
	defer dbms.database.Close()

	store := NewOpsGraphStore(dbms)
	if err := store.Init(ctx); err != nil {
		t.Fatalf("store init failed: %v", err)
	}

	err = opsgraph.IngestAgentSnapshot(ctx, store, opsgraph.AgentSnapshot{
		ID:        "agent-001",
		Domain:    "INLANEFREIGHT",
		Computer:  "WRK01",
		Username:  "j.arbuckle",
		Elevated:  true,
		Active:    true,
		LastTick:  1720000000,
		Timestamp: 1720000000,
	})
	if err != nil {
		t.Fatalf("agent ingestion failed: %v", err)
	}

	state, err := store.State(ctx)
	if err != nil {
		t.Fatalf("state failed: %v", err)
	}

	if len(state.Nodes) < 4 {
		t.Fatalf("expected at least 4 nodes, got %d", len(state.Nodes))
	}
	if len(state.Edges) < 2 {
		t.Fatalf("expected at least 2 edges, got %d", len(state.Edges))
	}

	computerID := opsgraph.ComputerID("INLANEFREIGHT", "WRK01")
	node, evidence, err := store.Node(ctx, computerID)
	if err != nil {
		t.Fatalf("expected computer node %s: %v", computerID, err)
	}

	if node.HostState != opsgraph.HostElevatedFoothold {
		t.Fatalf("expected elevated foothold host state, got %s", node.HostState)
	}

	if len(evidence) == 0 {
		t.Fatalf("expected evidence for computer node")
	}

	delta, err := store.DeltaSince(ctx, 0)
	if err != nil {
		t.Fatalf("delta failed: %v", err)
	}
	if delta.Cursor == 0 {
		t.Fatalf("expected non-zero delta cursor")
	}
}

func TestOpsGraphStoreIdempotentNodeUpsert(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "adaptix-test.db")

	dbms, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("NewDatabase failed: %v", err)
	}
	defer dbms.database.Close()

	store := NewOpsGraphStore(dbms)

	node := opsgraph.Node{
		ID:             opsgraph.UserID("INLANEFREIGHT", "j.arbuckle"),
		Type:           opsgraph.NodeUser,
		Label:          "j.arbuckle",
		NormalizedName: "INLANEFREIGHT\\j.arbuckle",
		Properties:     map[string]any{"domain": "INLANEFREIGHT", "sam": "j.arbuckle"},
		FirstSeen:      100,
		LastSeen:       100,
		Confidence:     1.0,
	}

	if err := store.UpsertNode(ctx, node, nil); err != nil {
		t.Fatalf("first upsert failed: %v", err)
	}

	node.LastSeen = 200
	if err := store.UpsertNode(ctx, node, nil); err != nil {
		t.Fatalf("second upsert failed: %v", err)
	}

	state, err := store.State(ctx)
	if err != nil {
		t.Fatalf("state failed: %v", err)
	}

	userCount := 0
	for _, n := range state.Nodes {
		if n.ID == node.ID {
			userCount++
			if n.FirstSeen != 100 {
				t.Fatalf("expected first_seen to remain 100, got %d", n.FirstSeen)
			}
			if n.LastSeen != 200 {
				t.Fatalf("expected last_seen 200, got %d", n.LastSeen)
			}
		}
	}

	if userCount != 1 {
		t.Fatalf("expected exactly one user node, got %d", userCount)
	}
}

func TestOpsGraphStoreEmptyStateUsesEmptySlices(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "adaptix-test.db")

	dbms, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("NewDatabase failed: %v", err)
	}
	defer dbms.database.Close()

	store := NewOpsGraphStore(dbms)

	state, err := store.State(ctx)
	if err != nil {
		t.Fatalf("state failed: %v", err)
	}

	if state.Nodes == nil {
		t.Fatalf("expected empty nodes slice, got nil")
	}
	if state.Edges == nil {
		t.Fatalf("expected empty edges slice, got nil")
	}

	delta, err := store.DeltaSince(ctx, 0)
	if err != nil {
		t.Fatalf("delta failed: %v", err)
	}

	if delta.Nodes == nil {
		t.Fatalf("expected empty delta nodes slice, got nil")
	}
	if delta.Edges == nil {
		t.Fatalf("expected empty delta edges slice, got nil")
	}
	if delta.Evidence == nil {
		t.Fatalf("expected empty delta evidence slice, got nil")
	}
	if delta.Errors == nil {
		t.Fatalf("expected empty delta errors slice, got nil")
	}
}
