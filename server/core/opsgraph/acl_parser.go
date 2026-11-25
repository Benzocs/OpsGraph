package opsgraph

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

type AclParser struct{}

func (AclParser) Name() string { return "acl_parser" }

func (AclParser) Match(ctx TaskContext) bool {
	cmd := strings.ToLower(ctx.CommandLine)
	out := strings.ToLower(ctx.Output)

	if strings.Contains(cmd, "acl") ||
		strings.Contains(cmd, "dacl") ||
		strings.Contains(cmd, "securitydescriptor") ||
		strings.Contains(cmd, "ntsecuritydescriptor") {
		return true
	}

	aclHints := []string{
		"activedirectoryrights",
		"identityreference",
		"objectdn:",
		"targetdn:",
		"trustee:",
		"principal:",
		"genericall",
		"genericwrite",
		"writedacl",
		"writeowner",
		"forcechangepassword",
		"allowedtoact",
		"msds-allowedtoactonbehalfofotheridentity",
	}

	hits := 0
	for _, h := range aclHints {
		if strings.Contains(out, h) {
			hits++
		}
	}

	return hits >= 2
}

func (p AclParser) Parse(ctx TaskContext) ParseResult {
	// OPSGRAPH_DISABLE_GETWRITABLE_EXPLOSION_BEGIN
	// get-writable can return hundreds/thousands of compact inventory rows.
	// Do not expand those into User nodes by default. It will be handled later
	// by the Operational Relevance Engine as summarized evidence/top-N targets.
	if strings.Contains(strings.ToLower(ctx.CommandLine), "get-writable") {
		return ParseResult{
			ParserName: p.Name(),
			Confidence: 0.50,
		}
	}
	// OPSGRAPH_DISABLE_GETWRITABLE_EXPLOSION_END

	ts := ctx.Timestamp
	if ts == 0 {
		ts = time.Now().Unix()
	}

	sourceKind := ctx.SourceKind
	if sourceKind == "" {
		sourceKind = "task"
	}

	sourceID := ctx.TaskID
	if sourceID == "" {
		sourceID = ctx.AgentID
	}
	if sourceID == "" {
		sourceID = ShortHash(ctx.CommandLine + "\n" + ctx.Output)
	}

	result := ParseResult{
		ParserName: p.Name(),
		Confidence: 0.82,
	}

	records := aclParseRecords(ctx.Output)
	if len(records) == 0 {
		result.ParseErrors = append(result.ParseErrors, ParseError{
			ID:         fmt.Sprintf("perr:%s:%s", p.Name(), ShortHash(ctx.Output)),
			TaskID:     ctx.TaskID,
			ParserName: p.Name(),
			ErrorText:  "acl_parser matched but no ACL records were extracted",
			RawSnippet: firstNonEmptyLine(ctx.Output),
			Timestamp:  ts,
		})
		return result
	}

	seenNodes := map[string]bool{}
	seenEdges := map[string]bool{}
	edgeIndexByID := map[string]int{}

	for _, rec := range records {
		principal := firstString(rec,
			"principal",
			"identityreference",
			"identity",
			"trustee",
			"securityidentifier",
			"sid",
		)

		target := firstString(rec,
			"targetdn",
			"objectdn",
			"distinguishedname",
			"target",
			"object",
			"objectname",
			"dn",
		)

		rightsRaw := firstString(rec,
			"activedirectoryrights",
			"rights",
			"right",
			"permission",
			"accessmask",
		)

		if rightsRaw == "" {
			rightsRaw = aclRightsFromFreeText(rec.raw)
		}

		rawRights := aclNormalizeRights(rightsRaw + " " + rec.raw)
		rights := aclAppendUnique(rawRights)
		writableAttrs := aclWritableAttributes(rec)
		inferredPrincipalFromAgent := false

		// Adaptix LDAP BOF get-writable --detailed often returns compact records:
		// distinguishedName: CN=target,...
		// userAccountControl: WRITE
		//
		// It does not repeat the principal in every block. The command itself means
		// the current agent context has write access to the listed attribute.
		if len(rights) == 0 && len(writableAttrs) > 0 {
			rights = []string{"WriteProperty"}
		}

		if principal == "" && target != "" && len(writableAttrs) > 0 {
			if current := aclCurrentPrincipal(ctx); current != "" {
				principal = current
				inferredPrincipalFromAgent = true
			}
		}

		if target != "" {
			rights = aclApplySemanticRights(rec, rights, target)
		}

		if principal == "" || target == "" || len(rights) == 0 {
			continue
		}

		targetSid := firstString(rec, "objectSid", "targetSid", "sid")

		principalCtx := ctx

		// ACL outputs often resolve principals as bare names:
		//   SecurityIdentifier : Domain Users
		//   SecurityIdentifier : IT Support
		//
		// If the principal has no explicit DOMAIN\name or user@domain form,
		// infer the AD domain from the target DN. Otherwise these become
		// group:unknown:* and later create duplicate/fragmented paths.
		if !strings.Contains(principal, "\\") && !strings.Contains(principal, "@") {
			if dnDomain := aclDomainFromDN(target); dnDomain != "" {
				principalCtx.Domain = dnDomain
			}
		}

		srcNode := aclPrincipalNode(principalCtx, principal, ts)
		dstNode := aclTargetNodeWithSID(ctx, target, targetSid, ts)

		if !seenNodes[srcNode.ID] {
			result.Nodes = append(result.Nodes, srcNode)
			seenNodes[srcNode.ID] = true
		}
		if !seenNodes[dstNode.ID] {
			result.Nodes = append(result.Nodes, dstNode)
			seenNodes[dstNode.ID] = true
		}

		edgeID := EdgeID(EdgeACLRight, srcNode.ID, dstNode.ID)
		props := map[string]any{
			"rights":                        rights,
			"raw_rights":                    rawRights,
			"display_rights":                aclDisplayRights(rights),
			"right_weight":                  aclRightWeight(rights),
			"attack_path_candidate":         aclIsAttackPathCandidate(rights),
			"control_class":                 aclControlClass(principal, rights),
			"semantic_resolver":             "acl_semantic_resolver_v1",
			"principal_raw":                 principal,
			"target_raw":                    target,
			"ace_type":                      firstString(rec, "acetype", "accesscontroltype", "type"),
			"object_type":                   firstString(rec, "objecttype", "objectace_type", "objectacetype"),
			"inherited":                     aclBoolish(firstString(rec, "isinherited", "inherited")),
			"inheritance_type":              firstString(rec, "inheritancetype"),
			"source":                        "passive_acl_output",
			"writable_attributes":           writableAttrs,
			"inferred_principal_from_agent": inferredPrincipalFromAgent,
		}

		edge := Edge{
			ID:         edgeID,
			SourceID:   srcNode.ID,
			TargetID:   dstNode.ID,
			Type:       EdgeACLRight,
			Properties: props,
			FirstSeen:  ts,
			LastSeen:   ts,
			Confidence: 0.82,
		}

		if existingIndex, ok := edgeIndexByID[edge.ID]; ok {
			existing := result.Edges[existingIndex]
			existing.Properties = aclMergeACLProperties(existing.Properties, props)

			if edge.LastSeen > existing.LastSeen {
				existing.LastSeen = edge.LastSeen
			}

			if edge.Confidence > existing.Confidence {
				existing.Confidence = edge.Confidence
			}

			result.Edges[existingIndex] = existing
		} else if !seenEdges[edge.ID] {
			result.Edges = append(result.Edges, edge)
			seenEdges[edge.ID] = true
			edgeIndexByID[edge.ID] = len(result.Edges) - 1
		}

		snippet := rec.raw
		if strings.TrimSpace(snippet) == "" {
			snippet = fmt.Sprintf("%s -> %v -> %s", principal, rights, target)
		}

		ev := Evidence{
			ID:          EvidenceID(sourceKind, sourceID, p.Name(), snippet),
			EdgeID:      edge.ID,
			SourceKind:  sourceKind,
			SourceID:    sourceID,
			AgentID:     ctx.AgentID,
			TaskID:      ctx.TaskID,
			CommandLine: ctx.CommandLine,
			ParserName:  p.Name(),
			RawSnippet:  trimSnippet(snippet, 1200),
			SnippetHash: ShortHash(snippet),
			Timestamp:   ts,
			Confidence:  0.82,
		}
		result.Evidence = append(result.Evidence, ev)
	}

	if len(result.Edges) == 0 {
		result.ParseErrors = append(result.ParseErrors, ParseError{
			ID:         fmt.Sprintf("perr:%s:%s", p.Name(), ShortHash(ctx.Output)),
			TaskID:     ctx.TaskID,
			ParserName: p.Name(),
			ErrorText:  "acl_parser extracted records but no complete principal/right/target tuple",
			RawSnippet: firstNonEmptyLine(ctx.Output),
			Timestamp:  ts,
		})
	}

	return result
}

type aclRecord struct {
	fields map[string]string
	raw    string
}

func aclParseRecords(output string) []aclRecord {
	normalized := strings.ReplaceAll(output, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")

	records := make([]aclRecord, 0)
	cur := aclRecord{fields: map[string]string{}}
	rawLines := make([]string, 0)

	flush := func() {
		if len(cur.fields) > 0 || strings.TrimSpace(strings.Join(rawLines, "\n")) != "" {
			cur.raw = strings.TrimSpace(strings.Join(rawLines, "\n"))
			records = append(records, cur)
		}
		cur = aclRecord{fields: map[string]string{}}
		rawLines = rawLines[:0]
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			flush()
			continue
		}

		rawLines = append(rawLines, line)

		key, value, ok := splitACLKeyValue(trimmed)
		if !ok {
			continue
		}

		nk := normalizeACLKey(key)
		if nk == "" || value == "" {
			continue
		}

		if old := cur.fields[nk]; old != "" {
			cur.fields[nk] = old + "; " + value
		} else {
			cur.fields[nk] = value
		}
	}

	flush()
	return records
}

func splitACLKeyValue(line string) (string, string, bool) {
	if idx := strings.Index(line, ":"); idx > 0 {
		return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
	}
	if idx := strings.Index(line, "="); idx > 0 {
		return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
	}
	return "", "", false
}

func normalizeACLKey(key string) string {
	k := strings.ToLower(strings.TrimSpace(key))
	k = strings.ReplaceAll(k, " ", "")
	k = strings.ReplaceAll(k, "_", "")
	k = strings.ReplaceAll(k, "-", "")
	return k
}

func firstString(rec aclRecord, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(rec.fields[normalizeACLKey(k)]); v != "" {
			return v
		}
	}
	return ""
}

// OPSGRAPH_GET_WRITABLE_HELPERS_BEGIN
func aclCurrentPrincipal(ctx TaskContext) string {
	user := strings.TrimSpace(ctx.User)
	domain := strings.TrimSpace(ctx.Domain)

	if user == "" {
		return ""
	}

	if strings.Contains(user, "\\") || strings.Contains(user, "@") {
		return user
	}

	if domain != "" {
		return domain + "\\" + user
	}

	return user
}

func aclWritableAttributes(rec aclRecord) []string {
	out := make([]string, 0)
	seen := map[string]bool{}

	skip := map[string]bool{
		normalizeACLKey("distinguishedName"): true,
		normalizeACLKey("objectDN"):          true,
		normalizeACLKey("targetDN"):          true,
		normalizeACLKey("objectSID"):         true,
		normalizeACLKey("sAMAccountName"):    true,
		normalizeACLKey("cn"):                true,
		normalizeACLKey("name"):              true,
	}

	for key, value := range rec.fields {
		if skip[key] {
			continue
		}

		v := strings.ToLower(strings.TrimSpace(value))
		if !strings.Contains(v, "write") {
			continue
		}

		attr := aclDisplayAttributeName(key)
		if attr == "" {
			continue
		}

		if !seen[attr] {
			out = append(out, attr)
			seen[attr] = true
		}
	}

	return out
}

func aclDisplayAttributeName(normalizedKey string) string {
	switch normalizedKey {
	case normalizeACLKey("userAccountControl"):
		return "userAccountControl"
	case normalizeACLKey("servicePrincipalName"):
		return "servicePrincipalName"
	case normalizeACLKey("msDS-AllowedToActOnBehalfOfOtherIdentity"):
		return "msDS-AllowedToActOnBehalfOfOtherIdentity"
	case normalizeACLKey("member"):
		return "member"
	case normalizeACLKey("memberOf"):
		return "memberOf"
	case normalizeACLKey("unicodePwd"):
		return "unicodePwd"
	case normalizeACLKey("pwdLastSet"):
		return "pwdLastSet"
	case normalizeACLKey("lockoutTime"):
		return "lockoutTime"
	case normalizeACLKey("description"):
		return "description"
	default:
		if normalizedKey == "" {
			return ""
		}
		return normalizedKey
	}
}

// OPSGRAPH_GET_WRITABLE_HELPERS_END

func aclPrincipalNode(ctx TaskContext, principal string, ts int64) Node {
	raw := strings.TrimSpace(principal)
	domain := ctx.Domain
	name := raw

	if strings.Contains(raw, "\\") {
		parts := strings.SplitN(raw, "\\", 2)
		domain = parts[0]
		name = parts[1]
	} else if strings.Contains(raw, "@") {
		parts := strings.SplitN(raw, "@", 2)
		name = parts[0]
		domain = parts[1]
	}

	if strings.HasSuffix(name, "$") {
		id := ComputerID(domain, strings.TrimSuffix(name, "$"))
		return Node{
			ID:             id,
			Type:           NodeComputer,
			Label:          raw,
			NormalizedName: NormalizeComputer(strings.TrimSuffix(name, "$")),
			Properties: map[string]any{
				"acl_principal_raw": raw,
				"domain":            NormalizeDomain(domain),
			},
			FirstSeen:  ts,
			LastSeen:   ts,
			Confidence: 0.78,
		}
	}

	if aclLooksLikeGroup(name) {
		id := GroupID(domain, name)
		return Node{
			ID:             id,
			Type:           NodeGroup,
			Label:          raw,
			NormalizedName: NormalizeSAM(name),
			Properties: map[string]any{
				"acl_principal_raw": raw,
				"domain":            NormalizeDomain(domain),
			},
			FirstSeen:  ts,
			LastSeen:   ts,
			Confidence: 0.76,
		}
	}

	id := UserID(domain, name)
	return Node{
		ID:             id,
		Type:           NodeUser,
		Label:          raw,
		NormalizedName: NormalizeSAM(name),
		Properties: map[string]any{
			"acl_principal_raw": raw,
			"domain":            NormalizeDomain(domain),
		},
		FirstSeen:  ts,
		LastSeen:   ts,
		Confidence: 0.72,
	}
}

func aclTargetNodeWithSID(ctx TaskContext, target string, sid string, ts int64) Node {
	node := aclTargetNode(ctx, target, ts)

	sid = strings.TrimSpace(sid)
	if sid != "" {
		if node.Properties == nil {
			node.Properties = map[string]any{}
		}
		node.Properties["sid"] = sid
		node.Properties["objectSid"] = sid
	}

	return node
}

func aclTargetNode(ctx TaskContext, target string, ts int64) Node {
	raw := strings.TrimSpace(target)
	domain := ctx.Domain
	name := raw

	if strings.Contains(strings.ToLower(raw), "dc=") {
		if d := aclDomainFromDN(raw); d != "" {
			domain = d
		}
		if cn := aclCNFromDN(raw); cn != "" {
			name = cn
		}
	} else if strings.Contains(raw, "\\") {
		parts := strings.SplitN(raw, "\\", 2)
		domain = parts[0]
		name = parts[1]
	}

	if strings.HasSuffix(name, "$") || strings.Contains(strings.ToLower(raw), "cn=computers") {
		id := ComputerID(domain, strings.TrimSuffix(name, "$"))
		return Node{
			ID:             id,
			Type:           NodeComputer,
			Label:          name,
			NormalizedName: NormalizeComputer(strings.TrimSuffix(name, "$")),
			Properties: map[string]any{
				"acl_target_raw":     raw,
				"domain":             NormalizeDomain(domain),
				"distinguished_name": raw,
			},
			FirstSeen:  ts,
			LastSeen:   ts,
			Confidence: 0.78,
		}
	}

	if aclLooksLikeGroup(name) || strings.Contains(strings.ToLower(raw), "cn=groups") {
		id := GroupID(domain, name)
		return Node{
			ID:             id,
			Type:           NodeGroup,
			Label:          name,
			NormalizedName: NormalizeSAM(name),
			Properties: map[string]any{
				"acl_target_raw":     raw,
				"domain":             NormalizeDomain(domain),
				"distinguished_name": raw,
			},
			FirstSeen:  ts,
			LastSeen:   ts,
			Confidence: 0.76,
		}
	}

	id := UserID(domain, name)
	return Node{
		ID:             id,
		Type:           NodeUser,
		Label:          name,
		NormalizedName: NormalizeSAM(name),
		Properties: map[string]any{
			"acl_target_raw":     raw,
			"domain":             NormalizeDomain(domain),
			"distinguished_name": raw,
		},
		FirstSeen:  ts,
		LastSeen:   ts,
		Confidence: 0.72,
	}
}

func aclLooksLikeGroup(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))

	if n == "" {
		return false
	}

	// Well-known / special security principals that may appear in ACL SecurityIdentifier
	// fields after --resolve. They are not real user accounts and must not pollute
	// the Users tree.
	exactGroups := map[string]bool{
		"self":                               true,
		"system":                             true,
		"everyone":                           true,
		"creator owner":                      true,
		"owner rights":                       true,
		"authenticated users":                true,
		"interactive":                        true,
		"network":                            true,
		"service":                            true,
		"local service":                      true,
		"network service":                    true,
		"enterprise domain controllers":      true,
		"domain controllers":                 true,
		"ras and ias servers":                true,
		"windows authorization access group": true,
		"pre-windows 2000 compatible access": true,
		"terminal server license servers":    true,
		"cert publishers":                    true,
		"certificate publishers":             true,
	}

	if exactGroups[n] {
		return true
	}

	groupHints := []string{
		"group",
		"admins",
		"administrators",
		"operators",
		"users",
		"support",
		"helpdesk",
		"team",
		"staff",
		"managers",
		"domain admins",
		"enterprise admins",

		// Real-world admin/application/security groups.
		"sql",
		"mssql",
		"database",
		"dba",
		"web",
		"iis",
		"app",
		"backup",
		"veeam",
		"exchange",
		"sharepoint",
		"pki",
		"cert",
		"certificate",
		"key admins",
		"dnsadmins",
		"dns admins",
		"server operators",
		"account operators",
		"backup operators",
		"group policy creator owners",

		// ACL-resolved built-in/special group naming.
		"license servers",
		"authorization access",
		"ras and ias",
		"publishers",
	}

	for _, h := range groupHints {
		if strings.Contains(n, h) {
			return true
		}
	}

	return false
}

func aclNormalizeRights(value string) []string {
	v := strings.ToLower(value)
	rights := make([]string, 0)

	candidates := []struct {
		key  string
		name string
	}{
		{"genericall", "GenericAll"},
		{"genericwrite", "GenericWrite"},
		{"writedacl", "WriteDACL"},
		{"writeowner", "WriteOwner"},
		{"all extended rights", "AllExtendedRights"},
		{"allextendedrights", "AllExtendedRights"},
		{"forcechangepassword", "ForceChangePassword"},
		{"force-change-password", "ForceChangePassword"},
		{"user-force-change-password", "ForceChangePassword"},
		{"user force change password", "ForceChangePassword"},
		{"reset password", "ForceChangePassword"},
		{"addmember", "AddMember"},
		{"allowedtoact", "AllowedToAct"},
		{"msds-allowedtoactonbehalfofotheridentity", "AllowedToAct"},
		{"serviceprincipalname", "WriteSPN"},
		{"writespn", "WriteSPN"},
		{"writeproperty", "WriteProperty"},
		{"self", "Self"},
	}

	seen := map[string]bool{}
	for _, c := range candidates {
		if strings.Contains(v, c.key) && !seen[c.name] {
			rights = append(rights, c.name)
			seen[c.name] = true
		}
	}

	return rights
}


func aclStringSliceContains(values []string, wanted string) bool {
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), wanted) {
			return true
		}
	}
	return false
}

func aclAppendUnique(values []string, extra ...string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values)+len(extra))

	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		key := strings.ToLower(v)
		if !seen[key] {
			out = append(out, v)
			seen[key] = true
		}
	}

	for _, v := range extra {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		key := strings.ToLower(v)
		if !seen[key] {
			out = append(out, v)
			seen[key] = true
		}
	}

	return out
}

func aclToStringSlice(value any) []string {
	out := make([]string, 0)

	switch v := value.(type) {
	case nil:
		return out
	case string:
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	case []string:
		out = append(out, v...)
	case []any:
		for _, item := range v {
			s := strings.TrimSpace(fmt.Sprint(item))
			if s != "" {
				out = append(out, s)
			}
		}
	default:
		s := strings.TrimSpace(fmt.Sprint(v))
		if s != "" {
			out = append(out, s)
		}
	}

	return aclAppendUnique(out)
}

func aclLooksLikeGroupTarget(target string) bool {
	t := strings.ToLower(strings.TrimSpace(target))

	if strings.Contains(t, ",ou=groups,") {
		return true
	}

	if strings.Contains(t, "objectclass=group") {
		return true
	}

	return false
}

func aclApplySemanticRights(rec aclRecord, rights []string, target string) []string {
	raw := strings.ToLower(rec.raw)
	objectType := strings.ToLower(firstString(rec, "objecttype", "objectace_type", "objectacetype"))

	semantic := aclAppendUnique(rights)

	// Extended right resolver:
	// The Adaptix LDAP BOF may resolve the ObjectAceType text as
	// User-Force-Change-Password. Preserve the operator semantic instead of
	// showing only ExtendedRight/WriteProperty.
	if strings.Contains(raw, "user-force-change-password") ||
		strings.Contains(objectType, "user-force-change-password") ||
		strings.Contains(raw, "force-change-password") ||
		strings.Contains(objectType, "force-change-password") {
		semantic = aclAppendUnique(semantic, "ForceChangePassword")
	}

	// Group membership resolver:
	// If an ACE grants WriteProperty against a group object and the ACE is not
	// constrained to a specific non-member ObjectAceType, the operator-relevant
	// semantic is AddMember. This keeps the graph aligned with BloodHound-style
	// path reasoning while retaining raw_rights in edge properties.
	hasWriteProperty := aclStringSliceContains(semantic, "WriteProperty")
	hasStrongControl := aclStringSliceContains(semantic, "GenericAll") ||
		aclStringSliceContains(semantic, "GenericWrite") ||
		aclStringSliceContains(semantic, "WriteDACL") ||
		aclStringSliceContains(semantic, "WriteOwner")

	memberGuid := "bf9679c0-0de6-11d0-a285-00aa003049e2"
	objectTypeIsMember := objectType == "" ||
		strings.Contains(objectType, "member") ||
		strings.Contains(objectType, memberGuid)

	if hasWriteProperty && aclLooksLikeGroupTarget(target) && objectTypeIsMember && !hasStrongControl {
		filtered := make([]string, 0, len(semantic))
		for _, r := range semantic {
			if strings.EqualFold(r, "WriteProperty") {
				continue
			}
			filtered = append(filtered, r)
		}
		semantic = aclAppendUnique(filtered, "AddMember")
	}

	return semantic
}


func aclRightWeight(rights []string) int {
	best := 0

	for _, r := range rights {
		v := strings.ToLower(strings.TrimSpace(r))
		weight := 0

		switch v {
		case "genericall":
			weight = 100
		case "writedacl":
			weight = 95
		case "writeowner":
			weight = 95
		case "genericwrite":
			weight = 90
		case "forcechangepassword":
			weight = 88
		case "addmember":
			weight = 86
		case "allowedtoact":
			weight = 86
		case "writespn":
			weight = 82
		case "allextendedrights":
			weight = 76
		case "writeproperty":
			weight = 45
		case "extendedright":
			weight = 40
		case "self":
			weight = 5
		}

		if weight > best {
			best = weight
		}
	}

	return best
}

func aclDisplayRights(rights []string) []string {
	priority := []string{
		"GenericAll",
		"WriteDACL",
		"WriteOwner",
		"GenericWrite",
		"ForceChangePassword",
		"AddMember",
		"AllowedToAct",
		"WriteSPN",
		"AllExtendedRights",
	}

	out := make([]string, 0)
	seen := map[string]bool{}

	for _, wanted := range priority {
		for _, r := range rights {
			if strings.EqualFold(r, wanted) && !seen[strings.ToLower(wanted)] {
				out = append(out, wanted)
				seen[strings.ToLower(wanted)] = true
			}
		}
	}

	if len(out) > 0 {
		return out
	}

	for _, r := range rights {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}

		key := strings.ToLower(r)
		if !seen[key] {
			out = append(out, r)
			seen[key] = true
		}
	}

	return out
}

func aclIsAttackPathCandidate(rights []string) bool {
	for _, r := range rights {
		switch strings.ToLower(strings.TrimSpace(r)) {
		case "genericall",
			"genericwrite",
			"writedacl",
			"writeowner",
			"forcechangepassword",
			"addmember",
			"allowedtoact",
			"writespn",
			"allextendedrights":
			return true
		}
	}

	return false
}

func aclControlClass(principal string, rights []string) string {
	p := strings.ToLower(strings.TrimSpace(principal))

	if p == "self" || strings.HasSuffix(p, "\\self") {
		return "self_noise"
	}

	if aclIsAttackPathCandidate(rights) {
		return "actionable_control"
	}

	if aclStringSliceContains(rights, "WriteProperty") {
		return "low_signal_property"
	}

	if aclStringSliceContains(rights, "ReadProperty") || aclStringSliceContains(rights, "ReadControl") {
		return "read_only"
	}

	return "context"
}

func aclRefreshControlProperties(props map[string]any) map[string]any {
	if props == nil {
		props = map[string]any{}
	}

	rights := aclToStringSlice(props["rights"])
	displayRights := aclDisplayRights(rights)

	props["display_rights"] = displayRights
	props["right_weight"] = aclRightWeight(rights)
	props["attack_path_candidate"] = aclIsAttackPathCandidate(rights)
	props["control_class"] = aclControlClass(fmt.Sprint(props["principal_raw"]), rights)

	return props
}


func aclMergeACLProperties(dst map[string]any, src map[string]any) map[string]any {
	if dst == nil {
		dst = map[string]any{}
	}

	for key, value := range src {
		if key == "rights" || key == "raw_rights" || key == "display_rights" || key == "writable_attributes" {
			dst[key] = aclAppendUnique(aclToStringSlice(dst[key]), aclToStringSlice(value)...)
			continue
		}

		current, ok := dst[key]
		if !ok || strings.TrimSpace(fmt.Sprint(current)) == "" {
			dst[key] = value
			continue
		}

		if strings.TrimSpace(fmt.Sprint(value)) == "" || fmt.Sprint(current) == fmt.Sprint(value) {
			continue
		}

		// Preserve conflicting metadata without overwriting the first observed
		// value. This is useful when several ACEs between the same source/target
		// have different ObjectAceType values.
		listKey := key + "_values"
		dst[listKey] = aclAppendUnique(aclToStringSlice(dst[listKey]), fmt.Sprint(current), fmt.Sprint(value))
	}

	return aclRefreshControlProperties(dst)
}



func aclRightsFromFreeText(value string) string {
	re := regexp.MustCompile(`(?i)(GenericAll|GenericWrite|WriteDacl|WriteOwner|AllExtendedRights|ForceChangePassword|AddMember|AllowedToAct|msDS-AllowedToActOnBehalfOfOtherIdentity|servicePrincipalName|WriteSPN|WriteProperty)`)
	return strings.Join(re.FindAllString(value, -1), " ")
}

func aclBoolish(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	return v == "true" || v == "yes" || v == "1"
}

func aclCNFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	if len(parts) == 0 {
		return ""
	}
	first := strings.TrimSpace(parts[0])
	if strings.HasPrefix(strings.ToLower(first), "cn=") {
		return strings.TrimSpace(first[3:])
	}
	return ""
}

func aclDomainFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	out := make([]string, 0)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToLower(p), "dc=") {
			out = append(out, strings.TrimSpace(p[3:]))
		}
	}
	return strings.Join(out, ".")
}

func firstNonEmptyLine(value string) string {
	for _, line := range strings.Split(value, "\n") {
		if strings.TrimSpace(line) != "" {
			return trimSnippet(line, 300)
		}
	}
	return ""
}

func trimSnippet(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max] + "...[truncated]"
}
