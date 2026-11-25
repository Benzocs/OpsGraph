package opsgraph

import (
	"strings"
	"unicode"
)

type HostnameParser struct{}

func (HostnameParser) Name() string { return "hostname_context" }

func (HostnameParser) Match(ctx TaskContext) bool {
	cmd := strings.ToLower(ctx.CommandLine)

	if looksLikeWhoamiAllOutput(ctx.Output) {
		return false
	}

	if strings.Contains(cmd, "whoami") && strings.Contains(cmd, "/all") {
		return false
	}

	return strings.Contains(cmd, "hostname") || ctx.Computer != ""
}

func (p HostnameParser) Parse(ctx TaskContext) ParseResult {
	res := ParseResult{ParserName: p.Name(), Confidence: 0.90}
	computer := ctx.Computer
	if computer == "" {
		computer = cleanHostname(ctx.Output)
	}
	if computer == "" {
		return res
	}

	ev := Evidence{
		ID:         EvidenceID("task", ctx.TaskID, p.Name(), computer),
		SourceKind: "task", SourceID: ctx.TaskID, TaskID: ctx.TaskID, AgentID: ctx.AgentID,
		CommandLine: ctx.CommandLine, ParserName: p.Name(), RawSnippet: computer,
		SnippetHash: ShortHash(computer), Timestamp: ctx.Timestamp, Confidence: 0.90,
	}
	cid := ComputerID(ctx.Domain, computer)
	res.Nodes = append(res.Nodes, Node{
		ID: cid, Type: NodeComputer, Label: computer,
		NormalizedName: NormalizeComputer(computer),
		Properties:     map[string]any{"domain": ctx.Domain, "computer": computer},
		FirstSeen:      ctx.Timestamp, LastSeen: ctx.Timestamp, Confidence: 0.90,
		HostState: HostEnumerated, EvidenceIDs: []string{ev.ID},
	})
	if ctx.Domain != "" {
		did := DomainID(ctx.Domain)
		res.Nodes = append(res.Nodes, Node{
			ID: did, Type: NodeDomain, Label: ctx.Domain,
			NormalizedName: NormalizeDomain(ctx.Domain),
			Properties:     map[string]any{"domain": ctx.Domain},
			FirstSeen:      ctx.Timestamp, LastSeen: ctx.Timestamp, Confidence: 0.85,
			EvidenceIDs: []string{ev.ID},
		})
		edge := Edge{ID: EdgeID(EdgeInDomain, cid, did), SourceID: cid, TargetID: did, Type: EdgeInDomain, Properties: map[string]any{}, FirstSeen: ctx.Timestamp, LastSeen: ctx.Timestamp, Confidence: 0.85, EvidenceIDs: []string{ev.ID}}
		res.Edges = append(res.Edges, edge)
	}
	res.Evidence = append(res.Evidence, ev)
	return res
}

func cleanHostname(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "\n") {
		s = strings.TrimSpace(strings.Split(s, "\n")[0])
	}
	for _, r := range s {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '.' || r == '_') {
			return ""
		}
	}
	return s
}
