package database

func (dbms *DBMS) DatabaseOpsGraphInit() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS "OpsGraphNodes" (
			"Id" TEXT PRIMARY KEY,
			"Type" TEXT NOT NULL,
			"Label" TEXT NOT NULL,
			"NormalizedName" TEXT NOT NULL,
			"PropertiesJson" TEXT NOT NULL DEFAULT '{}',
			"FirstSeen" BIGINT NOT NULL,
			"LastSeen" BIGINT NOT NULL,
			"Confidence" REAL NOT NULL DEFAULT 1.0,
			"HighValue" INTEGER NOT NULL DEFAULT 0,
			"HostState" TEXT,
			"Deleted" INTEGER NOT NULL DEFAULT 0
		);`,

		`CREATE TABLE IF NOT EXISTS "OpsGraphEdges" (
			"Id" TEXT PRIMARY KEY,
			"SourceId" TEXT NOT NULL,
			"TargetId" TEXT NOT NULL,
			"Type" TEXT NOT NULL,
			"PropertiesJson" TEXT NOT NULL DEFAULT '{}',
			"FirstSeen" BIGINT NOT NULL,
			"LastSeen" BIGINT NOT NULL,
			"Confidence" REAL NOT NULL DEFAULT 1.0,
			"Deleted" INTEGER NOT NULL DEFAULT 0
		);`,

		`CREATE TABLE IF NOT EXISTS "OpsGraphEvidence" (
			"Id" TEXT PRIMARY KEY,
			"NodeId" TEXT,
			"EdgeId" TEXT,
			"SourceKind" TEXT NOT NULL,
			"SourceId" TEXT NOT NULL,
			"AgentId" TEXT,
			"TaskId" TEXT,
			"CommandLine" TEXT,
			"ParserName" TEXT,
			"RawSnippet" TEXT,
			"SnippetSha256" TEXT,
			"Timestamp" BIGINT NOT NULL,
			"Confidence" REAL NOT NULL DEFAULT 1.0
		);`,

		`CREATE TABLE IF NOT EXISTS "OpsGraphCursors" (
			"Name" TEXT PRIMARY KEY,
			"CursorJson" TEXT NOT NULL,
			"UpdatedAt" BIGINT NOT NULL
		);`,

		`CREATE TABLE IF NOT EXISTS "OpsGraphSettings" (
			"Key" TEXT PRIMARY KEY,
			"ValueJson" TEXT NOT NULL,
			"UpdatedAt" BIGINT NOT NULL
		);`,

		`CREATE TABLE IF NOT EXISTS "OpsGraphParseErrors" (
			"Id" TEXT PRIMARY KEY,
			"TaskId" TEXT,
			"ParserName" TEXT,
			"ErrorText" TEXT NOT NULL,
			"RawSnippet" TEXT,
			"Timestamp" BIGINT NOT NULL
		);`,

		`CREATE TABLE IF NOT EXISTS "OpsGraphDelta" (
			"Id" INTEGER PRIMARY KEY AUTOINCREMENT,
			"ObjectKind" TEXT NOT NULL,
			"ObjectId" TEXT NOT NULL,
			"Operation" TEXT NOT NULL,
			"SnapshotJson" TEXT NOT NULL,
			"Timestamp" BIGINT NOT NULL
		);`,

		`CREATE INDEX IF NOT EXISTS "idx_opsgraph_nodes_type" ON "OpsGraphNodes"("Type");`,
		`CREATE INDEX IF NOT EXISTS "idx_opsgraph_nodes_label" ON "OpsGraphNodes"("Label");`,
		`CREATE INDEX IF NOT EXISTS "idx_opsgraph_edges_source" ON "OpsGraphEdges"("SourceId");`,
		`CREATE INDEX IF NOT EXISTS "idx_opsgraph_edges_target" ON "OpsGraphEdges"("TargetId");`,
		`CREATE INDEX IF NOT EXISTS "idx_opsgraph_edges_type" ON "OpsGraphEdges"("Type");`,
		`CREATE INDEX IF NOT EXISTS "idx_opsgraph_evidence_node" ON "OpsGraphEvidence"("NodeId");`,
		`CREATE INDEX IF NOT EXISTS "idx_opsgraph_evidence_edge" ON "OpsGraphEvidence"("EdgeId");`,
		`CREATE INDEX IF NOT EXISTS "idx_opsgraph_delta_timestamp" ON "OpsGraphDelta"("Timestamp");`,
	}

	for _, query := range queries {
		if _, err := dbms.database.Exec(query); err != nil {
			return err
		}
	}

	return nil
}
