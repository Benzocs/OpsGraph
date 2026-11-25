package opsgraph

import (
	"regexp"
	"strings"
)

var domainSlashUser = regexp.MustCompile(`(?i)([a-z0-9._-]+)\\([a-z0-9._$-]+)`)      // DOMAIN\user
var upnUser = regexp.MustCompile(`(?i)([a-z0-9._$-]+)@([a-z0-9._-]+\.[a-z0-9._-]+)`) // user@domain.tld

type IdentityParser struct{}

func (IdentityParser) Name() string { return "identity_context" }

func (IdentityParser) Match(ctx TaskContext) bool {
	cmd := strings.ToLower(ctx.CommandLine)

	if looksLikeWhoamiAllOutput(ctx.Output) {
		return false
	}

	if strings.Contains(cmd, "whoami") && strings.Contains(cmd, "/all") {
		return false
	}

	return strings.Contains(cmd, "whoami") || domainSlashUser.MatchString(ctx.Output) || upnUser.MatchString(ctx.Output)
}

func (p IdentityParser) Parse(ctx TaskContext) ParseResult {
	res := ParseResult{ParserName: p.Name(), Confidence: 0.90}
	output := strings.TrimSpace(ctx.Output)

	var domain, user string
	if m := domainSlashUser.FindStringSubmatch(output); len(m) == 3 {
		domain = m[1]
		user = strings.TrimSuffix(m[2], "$")
	} else if m := upnUser.FindStringSubmatch(output); len(m) == 3 {
		user = m[1]
		domain = m[2]
	} else if ctx.Domain != "" && ctx.User != "" {
		domain = ctx.Domain
		user = ctx.User
	}

	// Local Windows account output often looks like WIN\benzo.
	// WIN is the computer name, not an AD domain. Merge it into the existing
	// foothold user node: user:unknown:benzo.
	if domain != "" && ctx.Computer != "" && strings.EqualFold(domain, ctx.Computer) {
		domain = ""
	}

	if domain != "" && ctx.Domain == "" && !strings.Contains(domain, ".") {
		domain = ""
	}

	if user == "" {
		return res
	}

	ev := Evidence{
		ID:          EvidenceID("task", ctx.TaskID, p.Name(), output),
		SourceKind:  "task",
		SourceID:    ctx.TaskID,
		TaskID:      ctx.TaskID,
		AgentID:     ctx.AgentID,
		CommandLine: ctx.CommandLine,
		ParserName:  p.Name(),
		RawSnippet:  firstN(output, 512),
		SnippetHash: ShortHash(output),
		Timestamp:   ctx.Timestamp,
		Confidence:  0.90,
	}

	uid := UserID(domain, user)
	res.Nodes = append(res.Nodes, Node{
		ID: uid, Type: NodeUser, Label: user,
		NormalizedName: strings.ToLower(domain + `\` + user),
		Properties:     map[string]any{"domain": domain, "sam": user},
		FirstSeen:      ctx.Timestamp, LastSeen: ctx.Timestamp,
		Confidence: 0.90, EvidenceIDs: []string{ev.ID},
	})
	res.Evidence = append(res.Evidence, ev)
	if domain != "" {
		did := DomainID(domain)
		res.Nodes = append(res.Nodes, Node{
			ID: did, Type: NodeDomain, Label: domain,
			NormalizedName: NormalizeDomain(domain),
			Properties:     map[string]any{"domain": NormalizeDomain(domain)},
			FirstSeen:      ctx.Timestamp, LastSeen: ctx.Timestamp,
			Confidence: 0.85, EvidenceIDs: []string{ev.ID},
		})
	}
	return res
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
