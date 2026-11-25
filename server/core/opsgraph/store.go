package opsgraph

import "context"

// Store abstracts Adaptix DBMS implementation. The concrete implementation should live
// near core/database so it can reuse existing db handles, locks, and transaction style.
type Store interface {
	Init(ctx context.Context) error

	UpsertNode(ctx context.Context, node Node, evidence []Evidence) error
	UpsertEdge(ctx context.Context, edge Edge, evidence []Evidence) error
	AppendEvidence(ctx context.Context, evidence Evidence) error
	AppendParseError(ctx context.Context, parseError ParseError) error

	State(ctx context.Context) (State, error)
	DeltaSince(ctx context.Context, cursor int64) (Delta, error)
	Search(ctx context.Context, query string, limit int) ([]Node, error)
	Node(ctx context.Context, id string) (Node, []Evidence, error)
	EdgeEvidence(ctx context.Context, id string) ([]Evidence, error)

	GetCursor(ctx context.Context, name string) (string, error)
	SetCursor(ctx context.Context, name string, value string) error

	Clear(ctx context.Context) error
}
