package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"opsgraph/server/core/opsgraph"
)

type OpsGraphStore struct {
	dbms *DBMS
}

func NewOpsGraphStore(dbms *DBMS) *OpsGraphStore {
	return &OpsGraphStore{dbms: dbms}
}

func (s *OpsGraphStore) Init(ctx context.Context) error {
	if s == nil || s.dbms == nil || s.dbms.database == nil {
		return errors.New("opsgraph store has no database handle")
	}
	return s.dbms.DatabaseOpsGraphInit()
}

func (s *OpsGraphStore) UpsertNode(ctx context.Context, node opsgraph.Node, evidence []opsgraph.Evidence) error {
	if node.ID == "" {
		return errors.New("opsgraph node id is empty")
	}

	now := time.Now().Unix()
	if node.FirstSeen == 0 {
		node.FirstSeen = now
	}
	if node.LastSeen == 0 {
		node.LastSeen = node.FirstSeen
	}
	if node.Confidence == 0 {
		node.Confidence = 1.0
	}
	if node.Properties == nil {
		node.Properties = map[string]any{}
	}

	mergedProps, err := s.mergeExistingNodeProperties(ctx, node.ID, node.Properties)
	if err != nil {
		return fmt.Errorf("merge node properties %s: %w", node.ID, err)
	}
	node.Properties = mergedProps

	props, err := json.Marshal(node.Properties)
	if err != nil {
		return fmt.Errorf("marshal node properties: %w", err)
	}

	highValue := 0
	if node.HighValue {
		highValue = 1
	}

	_, err = s.dbms.database.ExecContext(ctx, `
		INSERT INTO "OpsGraphNodes"
			("Id", "Type", "Label", "NormalizedName", "PropertiesJson", "FirstSeen", "LastSeen", "Confidence", "HighValue", "HostState", "Deleted")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
		ON CONFLICT("Id") DO UPDATE SET
			"Type" = excluded."Type",
			"Label" = excluded."Label",
			"NormalizedName" = excluded."NormalizedName",
			"PropertiesJson" = excluded."PropertiesJson",
			"FirstSeen" = MIN("OpsGraphNodes"."FirstSeen", excluded."FirstSeen"),
			"LastSeen" = MAX("OpsGraphNodes"."LastSeen", excluded."LastSeen"),
			"Confidence" = MAX("OpsGraphNodes"."Confidence", excluded."Confidence"),
			"HighValue" = excluded."HighValue",
			"HostState" = CASE
				WHEN excluded."HostState" IS NOT NULL AND excluded."HostState" != '' THEN excluded."HostState"
				ELSE "OpsGraphNodes"."HostState"
			END,
			"Deleted" = 0;
	`, node.ID, string(node.Type), node.Label, node.NormalizedName, string(props), node.FirstSeen, node.LastSeen, node.Confidence, highValue, string(node.HostState))
	if err != nil {
		return fmt.Errorf("upsert opsgraph node %s: %w", node.ID, err)
	}

	for _, ev := range evidence {
		ev = bindEvidenceToObject(ev, "node", node.ID)
		if err := s.AppendEvidence(ctx, ev); err != nil {
			return err
		}
	}

	return s.appendDelta(ctx, "node", node.ID, "upsert", node, node.LastSeen)
}

func (s *OpsGraphStore) UpsertEdge(ctx context.Context, edge opsgraph.Edge, evidence []opsgraph.Evidence) error {
	if edge.ID == "" {
		return errors.New("opsgraph edge id is empty")
	}
	if edge.SourceID == "" || edge.TargetID == "" {
		return fmt.Errorf("opsgraph edge %s has empty source or target", edge.ID)
	}

	now := time.Now().Unix()
	if edge.FirstSeen == 0 {
		edge.FirstSeen = now
	}
	if edge.LastSeen == 0 {
		edge.LastSeen = edge.FirstSeen
	}
	if edge.Confidence == 0 {
		edge.Confidence = 1.0
	}
	if edge.Properties == nil {
		edge.Properties = map[string]any{}
	}

	props, err := json.Marshal(edge.Properties)
	if err != nil {
		return fmt.Errorf("marshal edge properties: %w", err)
	}

	_, err = s.dbms.database.ExecContext(ctx, `
		INSERT INTO "OpsGraphEdges"
			("Id", "SourceId", "TargetId", "Type", "PropertiesJson", "FirstSeen", "LastSeen", "Confidence", "Deleted")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
		ON CONFLICT("Id") DO UPDATE SET
			"SourceId" = excluded."SourceId",
			"TargetId" = excluded."TargetId",
			"Type" = excluded."Type",
			"PropertiesJson" = excluded."PropertiesJson",
			"FirstSeen" = MIN("OpsGraphEdges"."FirstSeen", excluded."FirstSeen"),
			"LastSeen" = MAX("OpsGraphEdges"."LastSeen", excluded."LastSeen"),
			"Confidence" = MAX("OpsGraphEdges"."Confidence", excluded."Confidence"),
			"Deleted" = 0;
	`, edge.ID, edge.SourceID, edge.TargetID, string(edge.Type), string(props), edge.FirstSeen, edge.LastSeen, edge.Confidence)
	if err != nil {
		return fmt.Errorf("upsert opsgraph edge %s: %w", edge.ID, err)
	}

	for _, ev := range evidence {
		ev = bindEvidenceToObject(ev, "edge", edge.ID)
		if err := s.AppendEvidence(ctx, ev); err != nil {
			return err
		}
	}

	return s.appendDelta(ctx, "edge", edge.ID, "upsert", edge, edge.LastSeen)
}

func (s *OpsGraphStore) AppendEvidence(ctx context.Context, ev opsgraph.Evidence) error {
	if ev.ID == "" {
		return errors.New("opsgraph evidence id is empty")
	}
	if ev.Timestamp == 0 {
		ev.Timestamp = time.Now().Unix()
	}
	if ev.Confidence == 0 {
		ev.Confidence = 1.0
	}

	// Evidence is loaded lazily when an operator selects a node/edge.
	// Do not spam OpsGraphDelta with evidence rows, and do not keep updating
	// identical evidence timestamps on every agent tick.
	var existing string
	err := s.dbms.database.QueryRowContext(ctx, `
        SELECT "Id"
        FROM "OpsGraphEvidence"
        WHERE "Id" = ?
        LIMIT 1;
    `, ev.ID).Scan(&existing)

	if err == nil {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check opsgraph evidence %s: %w", ev.ID, err)
	}

	_, err = s.dbms.database.ExecContext(ctx, `
        INSERT INTO "OpsGraphEvidence"
            ("Id", "NodeId", "EdgeId", "SourceKind", "SourceId", "AgentId", "TaskId", "CommandLine", "ParserName", "RawSnippet", "SnippetSha256", "Timestamp", "Confidence")
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    `, ev.ID, ev.NodeID, ev.EdgeID, ev.SourceKind, ev.SourceID, ev.AgentID, ev.TaskID, ev.CommandLine, ev.ParserName, ev.RawSnippet, ev.SnippetHash, ev.Timestamp, ev.Confidence)
	if err != nil {
		return fmt.Errorf("append opsgraph evidence %s: %w", ev.ID, err)
	}

	return nil
}

func (s *OpsGraphStore) AppendParseError(ctx context.Context, pe opsgraph.ParseError) error {
	if pe.ID == "" {
		return errors.New("opsgraph parse error id is empty")
	}
	if pe.Timestamp == 0 {
		pe.Timestamp = time.Now().Unix()
	}

	_, err := s.dbms.database.ExecContext(ctx, `
		INSERT INTO "OpsGraphParseErrors"
			("Id", "TaskId", "ParserName", "ErrorText", "RawSnippet", "Timestamp")
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT("Id") DO UPDATE SET
			"TaskId" = excluded."TaskId",
			"ParserName" = excluded."ParserName",
			"ErrorText" = excluded."ErrorText",
			"RawSnippet" = excluded."RawSnippet",
			"Timestamp" = excluded."Timestamp";
	`, pe.ID, pe.TaskID, pe.ParserName, pe.ErrorText, pe.RawSnippet, pe.Timestamp)
	if err != nil {
		return fmt.Errorf("append opsgraph parse error %s: %w", pe.ID, err)
	}

	return s.appendDelta(ctx, "parse_error", pe.ID, "upsert", pe, pe.Timestamp)
}

func (s *OpsGraphStore) State(ctx context.Context) (opsgraph.State, error) {
	cursor, err := s.maxDeltaCursor(ctx)
	if err != nil {
		return opsgraph.State{}, err
	}

	nodes, err := s.queryNodes(ctx, `SELECT "Id", "Type", "Label", "NormalizedName", "PropertiesJson", "FirstSeen", "LastSeen", "Confidence", "HighValue", "HostState" FROM "OpsGraphNodes" WHERE "Deleted" = 0 ORDER BY "Type", "Label";`)
	if err != nil {
		return opsgraph.State{}, err
	}

	edges, err := s.queryEdges(ctx, `SELECT "Id", "SourceId", "TargetId", "Type", "PropertiesJson", "FirstSeen", "LastSeen", "Confidence" FROM "OpsGraphEdges" WHERE "Deleted" = 0 ORDER BY "Type", "Id";`)
	if err != nil {
		return opsgraph.State{}, err
	}

	return opsgraph.State{Cursor: cursor, Nodes: nodes, Edges: edges}, nil
}

func (s *OpsGraphStore) DeltaSince(ctx context.Context, cursor int64) (opsgraph.Delta, error) {
	rows, err := s.dbms.database.QueryContext(ctx, `
        SELECT "Id", "ObjectKind", "SnapshotJson"
        FROM "OpsGraphDelta"
        WHERE "Id" > ?
          AND "ObjectKind" IN ('node', 'edge')
        ORDER BY "Id" ASC;
    `, cursor)
	if err != nil {
		return opsgraph.Delta{}, err
	}
	defer rows.Close()

	delta := opsgraph.Delta{
		Cursor:   cursor,
		Nodes:    make([]opsgraph.Node, 0),
		Edges:    make([]opsgraph.Edge, 0),
		Evidence: make([]opsgraph.Evidence, 0),
		Errors:   make([]opsgraph.ParseError, 0),
	}

	for rows.Next() {
		var id int64
		var kind string
		var raw string

		if err := rows.Scan(&id, &kind, &raw); err != nil {
			return opsgraph.Delta{}, err
		}

		delta.Cursor = id

		switch kind {
		case "node":
			var n opsgraph.Node
			if json.Unmarshal([]byte(raw), &n) == nil {
				delta.Nodes = append(delta.Nodes, n)
			}
		case "edge":
			var e opsgraph.Edge
			if json.Unmarshal([]byte(raw), &e) == nil {
				delta.Edges = append(delta.Edges, e)
			}
		}
	}

	return delta, rows.Err()
}

func (s *OpsGraphStore) Search(ctx context.Context, query string, limit int) ([]opsgraph.Node, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	like := "%" + query + "%"
	return s.queryNodes(ctx, `
		SELECT "Id", "Type", "Label", "NormalizedName", "PropertiesJson", "FirstSeen", "LastSeen", "Confidence", "HighValue", "HostState"
		FROM "OpsGraphNodes"
		WHERE "Deleted" = 0
		  AND ("Id" LIKE ? OR "Type" LIKE ? OR "Label" LIKE ? OR "NormalizedName" LIKE ?)
		ORDER BY "LastSeen" DESC
		LIMIT ?;
	`, like, like, like, like, limit)
}

func (s *OpsGraphStore) Node(ctx context.Context, id string) (opsgraph.Node, []opsgraph.Evidence, error) {
	rows, err := s.queryNodes(ctx, `
		SELECT "Id", "Type", "Label", "NormalizedName", "PropertiesJson", "FirstSeen", "LastSeen", "Confidence", "HighValue", "HostState"
		FROM "OpsGraphNodes"
		WHERE "Deleted" = 0 AND "Id" = ?
		LIMIT 1;
	`, id)
	if err != nil {
		return opsgraph.Node{}, nil, err
	}
	if len(rows) == 0 {
		return opsgraph.Node{}, nil, sql.ErrNoRows
	}

	ev, err := s.queryEvidence(ctx, `"NodeId" = ?`, id)
	if err != nil {
		return opsgraph.Node{}, nil, err
	}

	return rows[0], ev, nil
}

func (s *OpsGraphStore) EdgeEvidence(ctx context.Context, id string) ([]opsgraph.Evidence, error) {
	return s.queryEvidence(ctx, `"EdgeId" = ?`, id)
}

func (s *OpsGraphStore) GetCursor(ctx context.Context, name string) (string, error) {
	var value string
	err := s.dbms.database.QueryRowContext(ctx, `
		SELECT "CursorJson"
		FROM "OpsGraphCursors"
		WHERE "Name" = ?;
	`, name).Scan(&value)

	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}

	return value, err
}

func (s *OpsGraphStore) SetCursor(ctx context.Context, name string, value string) error {
	_, err := s.dbms.database.ExecContext(ctx, `
		INSERT INTO "OpsGraphCursors" ("Name", "CursorJson", "UpdatedAt")
		VALUES (?, ?, ?)
		ON CONFLICT("Name") DO UPDATE SET
			"CursorJson" = excluded."CursorJson",
			"UpdatedAt" = excluded."UpdatedAt";
	`, name, value, time.Now().Unix())
	return err
}

func (s *OpsGraphStore) Clear(ctx context.Context) error {
	tx, err := s.dbms.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tables := []string{
		"OpsGraphEvidence",
		"OpsGraphParseErrors",
		"OpsGraphEdges",
		"OpsGraphNodes",
		"OpsGraphCursors",
		"OpsGraphDelta",
	}

	for _, table := range tables {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM "%s";`, table)); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *OpsGraphStore) mergeExistingNodeProperties(ctx context.Context, nodeID string, incoming map[string]any) (map[string]any, error) {
	merged := make(map[string]any)

	var raw string
	err := s.dbms.database.QueryRowContext(ctx, `
		SELECT "PropertiesJson"
		FROM "OpsGraphNodes"
		WHERE "Id" = ? AND "Deleted" = 0
		LIMIT 1;
	`, nodeID).Scan(&raw)

	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	if err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &merged)
	}

	for k, v := range incoming {
		merged[k] = v
	}

	return merged, nil
}

func (s *OpsGraphStore) queryNodes(ctx context.Context, query string, args ...any) ([]opsgraph.Node, error) {
	rows, err := s.dbms.database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	nodes := make([]opsgraph.Node, 0)

	for rows.Next() {
		var n opsgraph.Node
		var nodeType string
		var propsRaw string
		var highValue int
		var hostState sql.NullString

		if err := rows.Scan(&n.ID, &nodeType, &n.Label, &n.NormalizedName, &propsRaw, &n.FirstSeen, &n.LastSeen, &n.Confidence, &highValue, &hostState); err != nil {
			return nil, err
		}

		n.Type = opsgraph.NodeType(nodeType)
		n.HighValue = highValue != 0
		if hostState.Valid {
			n.HostState = opsgraph.HostState(hostState.String)
		}
		if propsRaw == "" {
			propsRaw = "{}"
		}
		if err := json.Unmarshal([]byte(propsRaw), &n.Properties); err != nil {
			n.Properties = map[string]any{"_parse_error": err.Error()}
		}

		nodes = append(nodes, n)
	}

	return nodes, rows.Err()
}

func (s *OpsGraphStore) queryEdges(ctx context.Context, query string, args ...any) ([]opsgraph.Edge, error) {
	rows, err := s.dbms.database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	edges := make([]opsgraph.Edge, 0)

	for rows.Next() {
		var e opsgraph.Edge
		var edgeType string
		var propsRaw string

		if err := rows.Scan(&e.ID, &e.SourceID, &e.TargetID, &edgeType, &propsRaw, &e.FirstSeen, &e.LastSeen, &e.Confidence); err != nil {
			return nil, err
		}

		e.Type = opsgraph.EdgeType(edgeType)
		if propsRaw == "" {
			propsRaw = "{}"
		}
		if err := json.Unmarshal([]byte(propsRaw), &e.Properties); err != nil {
			e.Properties = map[string]any{"_parse_error": err.Error()}
		}

		edges = append(edges, e)
	}

	return edges, rows.Err()
}

func (s *OpsGraphStore) queryEvidence(ctx context.Context, where string, args ...any) ([]opsgraph.Evidence, error) {
	query := fmt.Sprintf(`
		SELECT "Id", "NodeId", "EdgeId", "SourceKind", "SourceId", "AgentId", "TaskId", "CommandLine", "ParserName", "RawSnippet", "SnippetSha256", "Timestamp", "Confidence"
		FROM "OpsGraphEvidence"
		WHERE %s
		ORDER BY "Timestamp" DESC;
	`, where)

	rows, err := s.dbms.database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]opsgraph.Evidence, 0)

	for rows.Next() {
		var ev opsgraph.Evidence
		var nodeID, edgeID, agentID, taskID, commandLine, parserName, rawSnippet, snippetHash sql.NullString

		if err := rows.Scan(&ev.ID, &nodeID, &edgeID, &ev.SourceKind, &ev.SourceID, &agentID, &taskID, &commandLine, &parserName, &rawSnippet, &snippetHash, &ev.Timestamp, &ev.Confidence); err != nil {
			return nil, err
		}

		ev.NodeID = nullString(nodeID)
		ev.EdgeID = nullString(edgeID)
		ev.AgentID = nullString(agentID)
		ev.TaskID = nullString(taskID)
		ev.CommandLine = nullString(commandLine)
		ev.ParserName = nullString(parserName)
		ev.RawSnippet = nullString(rawSnippet)
		ev.SnippetHash = nullString(snippetHash)

		out = append(out, ev)
	}

	return out, rows.Err()
}

func (s *OpsGraphStore) appendDelta(ctx context.Context, objectKind string, objectID string, operation string, snapshot any, ts int64) error {
	if ts == 0 {
		ts = time.Now().Unix()
	}

	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}

	_, err = s.dbms.database.ExecContext(ctx, `
		INSERT INTO "OpsGraphDelta" ("ObjectKind", "ObjectId", "Operation", "SnapshotJson", "Timestamp")
		VALUES (?, ?, ?, ?, ?);
	`, objectKind, objectID, operation, string(raw), ts)

	return err
}

func (s *OpsGraphStore) maxDeltaCursor(ctx context.Context) (int64, error) {
	var cursor sql.NullInt64
	err := s.dbms.database.QueryRowContext(ctx, `SELECT MAX("Id") FROM "OpsGraphDelta";`).Scan(&cursor)
	if err != nil {
		return 0, err
	}
	if !cursor.Valid {
		return 0, nil
	}
	return cursor.Int64, nil
}

func bindEvidenceToObject(ev opsgraph.Evidence, objectKind string, objectID string) opsgraph.Evidence {
	baseID := ev.ID
	if baseID == "" {
		baseID = opsgraph.EvidenceID(ev.SourceKind, ev.SourceID, ev.ParserName, ev.RawSnippet)
	}

	switch objectKind {
	case "node":
		ev.NodeID = objectID
		ev.EdgeID = ""
	case "edge":
		ev.EdgeID = objectID
		ev.NodeID = ""
	}

	ev.ID = fmt.Sprintf("%s:bind:%s:%s", baseID, objectKind, opsgraph.ShortHash(objectID))
	return ev
}

func nullString(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}
