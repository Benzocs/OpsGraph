package opsgraph

import (
	"regexp"
	"strings"
)

var whoamiAllSID = regexp.MustCompile(`S-\d(?:-\d+)+`)

type WhoamiAllParser struct{}

type whoamiAllGroup struct {
	Name       string
	Domain     string
	Type       string
	SID        string
	Attributes string
}

type whoamiAllPrivilege struct {
	Name        string
	Description string
	State       string
}

func (WhoamiAllParser) Name() string { return "whoami_all" }

func (WhoamiAllParser) Match(ctx TaskContext) bool {
	cmd := strings.ToLower(ctx.CommandLine)

	if strings.Contains(cmd, "whoami") && looksLikeWhoamiAllOutput(ctx.Output) {
		return true
	}

	if strings.Contains(cmd, "whoami") && strings.Contains(cmd, "/all") {
		return true
	}

	return looksLikeWhoamiAllOutput(ctx.Output)
}

func looksLikeWhoamiAllOutput(output string) bool {
	out := strings.ToLower(output)

	hasUserHeader := strings.Contains(out, "username") ||
		strings.Contains(out, "user name") ||
		strings.Contains(out, "user information")

	hasGroupHeader := strings.Contains(out, "group information") ||
		strings.Contains(out, "group name")

	hasSID := strings.Contains(out, "sid") && whoamiAllSID.MatchString(output)

	return hasUserHeader && hasGroupHeader && hasSID
}

func (p WhoamiAllParser) Parse(ctx TaskContext) ParseResult {
	res := ParseResult{ParserName: p.Name(), Confidence: 0.95}
	output := strings.TrimSpace(ctx.Output)
	if output == "" {
		return res
	}

	observedUserDomain, username, userSID := parseWhoamiAllUser(output)
	userDomain := observedUserDomain
	if username == "" {
		return res
	}

	userDomain = canonicalWhoamiUserDomain(ctx, userDomain)

	groups := dedupeWhoamiAllGroups(parseWhoamiAllGroups(output))
	privs := dedupeWhoamiAllPrivileges(parseWhoamiAllPrivileges(output))

	ev := Evidence{
		ID:          EvidenceID("task", ctx.TaskID, p.Name(), output),
		SourceKind:  "task",
		SourceID:    ctx.TaskID,
		TaskID:      ctx.TaskID,
		AgentID:     ctx.AgentID,
		CommandLine: ctx.CommandLine,
		ParserName:  p.Name(),
		RawSnippet:  firstN(output, 1200),
		SnippetHash: ShortHash(output),
		Timestamp:   ctx.Timestamp,
		Confidence:  0.95,
	}

	groupProps := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		scope := whoamiAllGroupScope(ctx, g)
		groupProps = append(groupProps, map[string]any{
			"name":       g.Name,
			"domain":     g.Domain,
			"type":       g.Type,
			"sid":        g.SID,
			"attributes": g.Attributes,
			"scope":      scope,
		})
	}

	privProps := make([]map[string]any, 0, len(privs))
	for _, pr := range privs {
		privProps = append(privProps, map[string]any{
			"name":        pr.Name,
			"description": pr.Description,
			"state":       pr.State,
		})
	}

	uid := UserID(userDomain, username)
	res.Nodes = append(res.Nodes, Node{
		ID:             uid,
		Type:           NodeUser,
		Label:          username,
		NormalizedName: strings.ToLower(userDomain + `\` + username),
		Properties: map[string]any{
			"domain":          userDomain,
			"observed_domain": observedUserDomain,
			"sam":             username,
			"sid":             userSID,
			"groups":          groupProps,
			"privileges":      privProps,
			"source":          "whoami",
			"task_id":         ctx.TaskID,
			"agent_id":        ctx.AgentID,
			"computer":        ctx.Computer,
			"commandLine":     ctx.CommandLine,
		},
		FirstSeen:   ctx.Timestamp,
		LastSeen:    ctx.Timestamp,
		Confidence:  0.95,
		EvidenceIDs: []string{ev.ID},
	})

	if userDomain != "" {
		domainID := DomainID(userDomain)
		res.Nodes = append(res.Nodes, Node{
			ID:             domainID,
			Type:           NodeDomain,
			Label:          userDomain,
			NormalizedName: NormalizeDomain(userDomain),
			Properties: map[string]any{
				"domain": NormalizeDomain(userDomain),
				"source": "whoami",
			},
			FirstSeen:   ctx.Timestamp,
			LastSeen:    ctx.Timestamp,
			Confidence:  0.95,
			EvidenceIDs: []string{ev.ID},
		})

		res.Edges = append(res.Edges, Edge{
			ID:       EdgeID(EdgeInDomain, uid, domainID),
			SourceID: uid,
			TargetID: domainID,
			Type:     EdgeInDomain,
			Properties: map[string]any{
				"source":          "whoami",
				"observed_domain": observedUserDomain,
			},
			FirstSeen:   ctx.Timestamp,
			LastSeen:    ctx.Timestamp,
			Confidence:  0.95,
			EvidenceIDs: []string{ev.ID},
		})
	}

	for _, g := range groups {
		scope := whoamiAllGroupScope(ctx, g)
		groupID := whoamiAllGroupID(g.Domain, g.Name)
		groupLabel := g.Name
		if g.Domain != "" {
			groupLabel = g.Domain + `\` + g.Name
		}

		res.Nodes = append(res.Nodes, Node{
			ID:             groupID,
			Type:           NodeGroup,
			Label:          groupLabel,
			NormalizedName: strings.ToLower(groupLabel),
			Properties: map[string]any{
				"domain":     g.Domain,
				"name":       g.Name,
				"sid":        g.SID,
				"type":       g.Type,
				"attributes": g.Attributes,
				"scope":      scope,
				"source":     "whoami",
			},
			FirstSeen:   ctx.Timestamp,
			LastSeen:    ctx.Timestamp,
			Confidence:  0.90,
			EvidenceIDs: []string{ev.ID},
		})

		if userDomain != "" && scope == "domain" {
			domainID := DomainID(userDomain)
			res.Edges = append(res.Edges, Edge{
				ID:       EdgeID(EdgeInDomain, groupID, domainID),
				SourceID: groupID,
				TargetID: domainID,
				Type:     EdgeInDomain,
				Properties: map[string]any{
					"source":          "whoami",
					"observed_domain": g.Domain,
					"group_sid":       g.SID,
				},
				FirstSeen:   ctx.Timestamp,
				LastSeen:    ctx.Timestamp,
				Confidence:  0.90,
				EvidenceIDs: []string{ev.ID},
			})
		}

		res.Edges = append(res.Edges, Edge{
			ID:          EdgeID(EdgeMemberOf, uid, groupID),
			SourceID:    uid,
			TargetID:    groupID,
			Type:        EdgeMemberOf,
			Properties:  map[string]any{"source": "whoami", "group_sid": g.SID},
			FirstSeen:   ctx.Timestamp,
			LastSeen:    ctx.Timestamp,
			Confidence:  0.90,
			EvidenceIDs: []string{ev.ID},
		})
	}

	res.Evidence = append(res.Evidence, ev)
	return res
}

func canonicalWhoamiUserDomain(ctx TaskContext, observedDomain string) string {
	observedDomain = strings.TrimSpace(observedDomain)

	// Local machine account: WIN\user where WIN == current computer.
	if observedDomain != "" &&
		ctx.Computer != "" &&
		strings.EqualFold(NormalizeDomain(observedDomain), NormalizeComputer(ctx.Computer)) {
		return ""
	}

	ctxDomain := NormalizeDomain(ctx.Domain)

	// If service layer enriched us with a real DNS domain, use that as the
	// canonical identity domain for NetBIOS-style whoami output like ZA\user.
	// This prevents:
	//   user:za.tryhackme.loc:paula.bailey
	//   user:unknown:paula.bailey
	// from becoming two different graph nodes.
	if ctxDomain != "" && !domainLooksLikeLocalComputer(ctxDomain, ctx.Computer) {
		if observedDomain == "" {
			return ctxDomain
		}

		if strings.Contains(observedDomain, ".") {
			return NormalizeDomain(observedDomain)
		}

		return ctxDomain
	}

	// If no trusted domain context exists, keep local/workgroup output safe.
	// This avoids creating fake domains like domain:win from WIN\localuser.
	if observedDomain != "" && strings.Contains(observedDomain, ".") {
		return NormalizeDomain(observedDomain)
	}

	return ""
}

func parseWhoamiAllUser(output string) (domain string, user string, sid string) {
	lines := whoamiAllSectionLines(output, "USER INFORMATION", "GROUP INFORMATION")

	if len(lines) == 0 {
		head := output
		if idx := strings.Index(strings.ToLower(output), "group information"); idx >= 0 {
			head = output[:idx]
		}
		lines = strings.Split(head, "\n")
	}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		lower := strings.ToLower(line)

		if line == "" ||
			strings.Contains(line, "===") ||
			strings.Contains(lower, "username") ||
			strings.Contains(lower, "user name") ||
			(strings.Contains(lower, "sid") && !whoamiAllSID.MatchString(line)) {
			continue
		}

		sid = whoamiAllSID.FindString(line)
		if sid == "" {
			continue
		}

		left := strings.TrimSpace(strings.Replace(line, sid, "", 1))
		if left == "" {
			continue
		}

		if parts := strings.SplitN(left, `\`, 2); len(parts) == 2 {
			return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), sid
		}

		return "", left, sid
	}

	return "", "", ""
}

func parseWhoamiAllGroups(output string) []whoamiAllGroup {
	lines := whoamiAllSectionLines(output, "GROUP INFORMATION", "PRIVILEGES INFORMATION")
	out := make([]whoamiAllGroup, 0)

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		lower := strings.ToLower(line)

		if line == "" ||
			strings.Contains(line, "===") ||
			strings.Contains(lower, "group information") ||
			strings.Contains(lower, "group name") ||
			(strings.Contains(lower, "attributes") && strings.Contains(lower, "sid")) {
			continue
		}

		sid := whoamiAllSID.FindString(line)
		if sid == "" {
			continue
		}

		parts := strings.SplitN(line, sid, 2)
		if len(parts) != 2 {
			continue
		}

		left := strings.TrimSpace(parts[0])
		attrs := strings.TrimSpace(parts[1])

		name, groupType := splitWhoamiAllGroupNameAndType(left)
		if name == "" {
			continue
		}

		domain, groupName := splitDomainObjectName(name)

		out = append(out, whoamiAllGroup{
			Name:       groupName,
			Domain:     domain,
			Type:       groupType,
			SID:        sid,
			Attributes: attrs,
		})
	}

	return out
}

func parseWhoamiAllPrivileges(output string) []whoamiAllPrivilege {
	lines := whoamiAllSectionLines(output, "PRIVILEGES INFORMATION", "")
	if len(lines) == 0 {
		lines = whoamiAllSectionLines(output, "PRIVILEGE INFORMATION", "")
	}
	if len(lines) == 0 {
		lower := strings.ToLower(output)
		if idx := strings.Index(lower, "privilege name"); idx >= 0 {
			lines = strings.Split(output[idx:], "\n")
		}
	}

	out := make([]whoamiAllPrivilege, 0)

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		lower := strings.ToLower(line)

		if line == "" ||
			strings.Contains(line, "===") ||
			strings.Contains(lower, "privilege name") ||
			strings.Contains(lower, "description") ||
			strings.Contains(lower, "state") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "Se") {
			continue
		}

		name := fields[0]
		state := fields[len(fields)-1]
		description := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, name), state))

		out = append(out, whoamiAllPrivilege{
			Name:        name,
			Description: description,
			State:       state,
		})
	}

	return out
}

func dedupeWhoamiAllGroups(groups []whoamiAllGroup) []whoamiAllGroup {
	out := make([]whoamiAllGroup, 0, len(groups))
	seen := make(map[string]bool)

	for _, g := range groups {
		key := strings.ToLower(strings.TrimSpace(g.Domain)) + "|" +
			strings.ToLower(strings.TrimSpace(g.Name)) + "|" +
			strings.ToLower(strings.TrimSpace(g.SID))

		if seen[key] {
			continue
		}

		seen[key] = true
		out = append(out, g)
	}

	return out
}

func dedupeWhoamiAllPrivileges(privs []whoamiAllPrivilege) []whoamiAllPrivilege {
	out := make([]whoamiAllPrivilege, 0, len(privs))
	seen := make(map[string]bool)

	for _, p := range privs {
		key := strings.ToLower(strings.TrimSpace(p.Name))
		if key == "" || seen[key] {
			continue
		}

		seen[key] = true
		out = append(out, p)
	}

	return out
}

func splitWhoamiAllGroupNameAndType(left string) (string, string) {
	left = strings.TrimSpace(left)

	knownTypes := []string{
		"Well-known group",
		"Mandatory Label",
		"Alias",
		"Group",
		"Label",
	}

	for _, typ := range knownTypes {
		if strings.HasSuffix(strings.ToLower(left), strings.ToLower(typ)) {
			name := strings.TrimSpace(left[:len(left)-len(typ)])
			return name, typ
		}
	}

	fields := strings.Fields(left)
	if len(fields) < 2 {
		return left, ""
	}

	return strings.Join(fields[:len(fields)-1], " "), fields[len(fields)-1]
}

func splitDomainObjectName(value string) (string, string) {
	value = strings.TrimSpace(value)

	if parts := strings.SplitN(value, `\`, 2); len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}

	return "", value
}

func whoamiAllGroupScope(ctx TaskContext, g whoamiAllGroup) string {
	domain := strings.ToLower(strings.TrimSpace(g.Domain))
	name := strings.ToLower(strings.TrimSpace(g.Name))
	groupType := strings.ToLower(strings.TrimSpace(g.Type))
	computer := strings.ToLower(strings.TrimSpace(ctx.Computer))
	ctxDomain := strings.ToLower(strings.TrimSpace(ctx.Domain))

	if strings.Contains(groupType, "label") ||
		domain == "mandatory label" ||
		strings.Contains(name, "mandatory level") {
		return "integrity_label"
	}

	if domain == "builtin" {
		return "local"
	}

	if computer != "" && domain == computer {
		return "local"
	}

	if domain == "nt authority" ||
		domain == "" && (name == "everyone" || name == "local" || name == "console logon") ||
		strings.Contains(groupType, "well-known") {
		return "well_known"
	}

	if ctxDomain != "" && domain == ctxDomain {
		return "domain"
	}

	if domain != "" && domain != "builtin" && domain != "nt authority" && domain != "mandatory label" && domain != computer {
		return "domain"
	}

	return "unknown"
}

func whoamiAllGroupID(domain string, name string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	name = strings.ToLower(strings.TrimSpace(name))

	if domain == "" {
		domain = "unknown"
	}

	return "group:" + domain + ":" + name
}

func whoamiAllSectionLines(output string, startMarker string, endMarker string) []string {
	lines := strings.Split(output, "\n")
	out := make([]string, 0)
	inSection := false

	startMarker = strings.ToLower(startMarker)
	endMarker = strings.ToLower(endMarker)

	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		lower := strings.ToLower(strings.TrimSpace(line))

		if !inSection && strings.Contains(lower, startMarker) {
			inSection = true
			continue
		}

		if inSection && endMarker != "" && strings.Contains(lower, endMarker) {
			break
		}

		if inSection {
			out = append(out, line)
		}
	}

	return out
}
