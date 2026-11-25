package opsgraph

type TaskContext struct {
	TaskID      string
	AgentID     string
	CommandLine string
	Output      string
	User        string
	Computer    string
	Domain      string
	Timestamp   int64
	SourceKind  string
}

type Parser interface {
	Name() string
	Match(ctx TaskContext) bool
	Parse(ctx TaskContext) ParseResult
}

type Router struct {
	parsers []Parser
}

func NewRouter() *Router {
	return &Router{parsers: []Parser{
		LdapSearchParser{},
		AclParser{},
		WhoamiAllParser{},
		IdentityParser{},
		HostnameParser{},
	}}
}

func (r *Router) Parse(ctx TaskContext) []ParseResult {
	results := make([]ParseResult, 0)

	// Dedicated parsers must win before generic context parsers.
	// Otherwise whoami /all output like WIN\benzo gets parsed by IdentityParser
	// and creates fake local-domain nodes such as domain:win and user:win:benzo.
	for _, p := range r.parsers {
		if p.Name() == "whoami_all" && p.Match(ctx) {
			return []ParseResult{p.Parse(ctx)}
		}
	}

	for _, p := range r.parsers {
		if p.Name() == "whoami_all" {
			continue
		}
		if p.Match(ctx) {
			results = append(results, p.Parse(ctx))
		}
	}

	return results
}
