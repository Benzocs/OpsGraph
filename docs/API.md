# OpsGraph API

## GET /opsgraph/state
Returns full graph snapshot.

## GET /opsgraph/delta?since=<cursor>
Returns changed nodes, edges, evidence, and parse errors since a cursor.

## GET /opsgraph/search?q=<query>
Returns matching nodes.

## GET /opsgraph/node/:id
Returns node details plus evidence.

## GET /opsgraph/edge/:id/evidence
Returns evidence list for an edge.

## POST /opsgraph/path
Evidence-only shortest observed path.

```json
{
  "start_node_ids": ["agent:abc123"],
  "target_node_ids": ["group:inlanefreight.ad:domain admins"],
  "allowed_edges": ["RunningOn", "RunningAs", "MemberOf", "Contains", "BelongsTo", "Trusts"],
  "max_depth": 8
}
```

## POST /opsgraph/settings
Updates graph visualization/ingestion settings.

## POST /opsgraph/rebuild
Clears derived graph objects and rebuilds from historical Adaptix data.

## GET /opsgraph/export
Exports graph JSON with evidence references. Secret-bearing evidence should be redacted by default.
