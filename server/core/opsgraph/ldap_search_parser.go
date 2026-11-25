package opsgraph

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type LdapSearchParser struct{}

type ldapEntry struct {
	Attrs map[string][]string
	Raw   string
}

var ldapDCPart = regexp.MustCompile(`(?i)(?:^|,)DC=([^,]+)`)

func (LdapSearchParser) Name() string { return "ldap_search" }

func (LdapSearchParser) Match(ctx TaskContext) bool {
	cmd := strings.ToLower(ctx.CommandLine)
	out := strings.ToLower(ctx.Output)

	if strings.Contains(cmd, "ldapsearch") {
		return true
	}

	return strings.Contains(out, "successfully bound to ldap server") &&
		strings.Contains(out, "distinguishedname:")
}

func (p LdapSearchParser) Parse(ctx TaskContext) ParseResult {
	res := ParseResult{ParserName: p.Name(), Confidence: 0.90}

	output := strings.TrimSpace(ctx.Output)
	if output == "" {
		return res
	}

	baseDomain := ldapDomainFromOutput(output)
	if baseDomain == "" {
		baseDomain = NormalizeDomain(ctx.Domain)
	}

	ev := Evidence{
		ID:          EvidenceID("task", ctx.TaskID, p.Name(), output),
		SourceKind:  "task",
		SourceID:    ctx.TaskID,
		TaskID:      ctx.TaskID,
		AgentID:     ctx.AgentID,
		CommandLine: ctx.CommandLine,
		ParserName:  p.Name(),
		RawSnippet:  ldapFirstN(output, 1600),
		SnippetHash: ShortHash(output),
		Timestamp:   ctx.Timestamp,
		Confidence:  0.90,
	}

	entries := parseLDAPEntries(output)
	if len(entries) == 0 {
		return res
	}

	if baseDomain != "" {
		res.Nodes = append(res.Nodes, ldapDomainNode(baseDomain, ctx.Timestamp, ev.ID))
	}

	for _, entry := range entries {
		dn := ldapFirstAttr(entry.Attrs, "distinguishedname")
		if dn == "" {
			continue
		}

		domain := ldapDomainFromDN(dn)
		if domain == "" {
			domain = baseDomain
		}
		if domain == "" {
			continue
		}

		domainID := DomainID(domain)
		res.Nodes = append(res.Nodes, ldapDomainNode(domain, ctx.Timestamp, ev.ID))

		objectClass := strings.ToLower(strings.Join(ldapAttrValues(entry.Attrs, "objectclass"), ","))
		sam := ldapFirstAttr(entry.Attrs, "samaccountname")
		cn := ldapCNFromDN(dn)
		sid := ldapFirstAttr(entry.Attrs, "objectsid")
		dnsHost := ldapFirstAttr(entry.Attrs, "dnshostname")
		uac := ldapFirstAttr(entry.Attrs, "useraccountcontrol")
		exposureProps := ldapExposureProperties(entry.Attrs, uac)

		if ldapShouldSkipEntry(entry.Attrs, objectClass, dn, sam, sid, dnsHost) {
			continue
		}

		var objectID string
		var objectType NodeType
		var label string
		var confidence float64 = 0.90

		switch {
		case strings.Contains(objectClass, "domaindns") || ldapIsDomainDN(dn):
			continue

		case ldapLooksLikeComputer(entry.Attrs, objectClass, sam, dnsHost):
			computer := strings.TrimSuffix(sam, "$")
			if computer == "" && dnsHost != "" {
				computer = strings.Split(dnsHost, ".")[0]
			}
			if computer == "" {
				computer = cn
			}

			objectID = ComputerID(domain, computer)
			objectType = NodeComputer
			label = computer

			res.Nodes = append(res.Nodes, Node{
				ID:             objectID,
				Type:           objectType,
				Label:          label,
				NormalizedName: NormalizeComputer(computer),
				Properties: ldapAttachAttackVectors(map[string]any{
					"domain":               domain,
					"sam":                  sam,
					"dn":                   dn,
					"cn":                   cn,
					"sid":                  sid,
					"dns_host_name":        dnsHost,
					"user_account_control": uac,
					"source":               "ldap",
					"exposure":             exposureProps,
				}, exposureProps, objectType),
				FirstSeen:   ctx.Timestamp,
				LastSeen:    ctx.Timestamp,
				Confidence:  confidence,
				HostState:   HostDiscovered,
				EvidenceIDs: []string{ev.ID},
			})

		case ldapLooksLikeGroup(entry.Attrs, objectClass):
			groupName := sam
			if groupName == "" {
				groupName = cn
			}
			netbios := ldapNetBIOSFromDomain(domain)

			objectID = GroupID(netbios, groupName)
			objectType = NodeGroup
			label = netbios + `\` + groupName

			res.Nodes = append(res.Nodes, Node{
				ID:             objectID,
				Type:           objectType,
				Label:          label,
				NormalizedName: strings.ToLower(label),
				Properties: ldapAttachAttackVectors(map[string]any{
					"domain":     netbios,
					"dns_domain": domain,
					"name":       groupName,
					"sam":        sam,
					"dn":         dn,
					"cn":         cn,
					"sid":        sid,
					"scope":      "domain",
					"source":     "ldap",
					"exposure":   exposureProps,
				}, exposureProps, objectType),
				FirstSeen:   ctx.Timestamp,
				LastSeen:    ctx.Timestamp,
				Confidence:  confidence,
				EvidenceIDs: []string{ev.ID},
			})

		default:
			user := sam
			if user == "" {
				user = cn
				confidence = 0.70
			}
			if user == "" {
				continue
			}

			objectID = UserID(domain, user)
			objectType = NodeUser
			label = user

			res.Nodes = append(res.Nodes, Node{
				ID:             objectID,
				Type:           objectType,
				Label:          label,
				NormalizedName: strings.ToLower(domain + `\` + user),
				Properties: ldapAttachAttackVectors(map[string]any{
					"domain":               domain,
					"sam":                  user,
					"dn":                   dn,
					"cn":                   cn,
					"sid":                  sid,
					"user_principal_name":  ldapFirstAttr(entry.Attrs, "userprincipalname"),
					"user_account_control": uac,
					"source":               "ldap",
				}, exposureProps, objectType),
				FirstSeen:   ctx.Timestamp,
				LastSeen:    ctx.Timestamp,
				Confidence:  confidence,
				EvidenceIDs: []string{ev.ID},
			})
		}

		if objectID == "" {
			continue
		}

		res.Edges = append(res.Edges, Edge{
			ID:       EdgeID(EdgeInDomain, objectID, domainID),
			SourceID: objectID,
			TargetID: domainID,
			Type:     EdgeInDomain,
			Properties: map[string]any{
				"source": "ldap",
				"dn":     dn,
			},
			FirstSeen:   ctx.Timestamp,
			LastSeen:    ctx.Timestamp,
			Confidence:  0.90,
			EvidenceIDs: []string{ev.ID},
		})

		for _, memberOfDN := range ldapAttributeDNs(entry.Attrs, "memberof") {
			groupID, groupNode := ldapGroupNodeFromDN(memberOfDN, domain, ctx.Timestamp, ev.ID)
			if groupID == "" {
				continue
			}

			res.Nodes = append(res.Nodes, groupNode)

			res.Edges = append(res.Edges, Edge{
				ID:       EdgeID(EdgeInDomain, groupID, domainID),
				SourceID: groupID,
				TargetID: domainID,
				Type:     EdgeInDomain,
				Properties: map[string]any{
					"source": "ldap",
					"dn":     memberOfDN,
				},
				FirstSeen:   ctx.Timestamp,
				LastSeen:    ctx.Timestamp,
				Confidence:  0.85,
				EvidenceIDs: []string{ev.ID},
			})

			res.Edges = append(res.Edges, Edge{
				ID:       EdgeID(EdgeMemberOf, objectID, groupID),
				SourceID: objectID,
				TargetID: groupID,
				Type:     EdgeMemberOf,
				Properties: map[string]any{
					"source":   "ldap",
					"group_dn": memberOfDN,
				},
				FirstSeen:   ctx.Timestamp,
				LastSeen:    ctx.Timestamp,
				Confidence:  0.90,
				EvidenceIDs: []string{ev.ID},
			})
		}

		if objectType == NodeGroup {
			for _, memberDN := range ldapAttributeDNs(entry.Attrs, "member") {
				memberID, memberNode := ldapNodeFromMemberDN(memberDN, domain, ctx.Timestamp, ev.ID)
				if memberID == "" {
					continue
				}

				res.Nodes = append(res.Nodes, memberNode)

				res.Edges = append(res.Edges, Edge{
					ID:       EdgeID(EdgeMemberOf, memberID, objectID),
					SourceID: memberID,
					TargetID: objectID,
					Type:     EdgeMemberOf,
					Properties: map[string]any{
						"source":               "ldap_member_dn",
						"member_dn":            memberDN,
						"dn_based_identity":    true,
						"requires_correlation": true,
					},
					FirstSeen:   ctx.Timestamp,
					LastSeen:    ctx.Timestamp,
					Confidence:  0.65,
					EvidenceIDs: []string{ev.ID},
				})
			}
		}

		for _, spn := range ldapAttrValues(entry.Attrs, "serviceprincipalname") {
			for _, value := range ldapSplitSimpleList(spn) {
				value = strings.TrimSpace(value)
				if value == "" {
					continue
				}

				spnID := "spn:" + ShortHash(strings.ToLower(value))
				res.Nodes = append(res.Nodes, Node{
					ID:             spnID,
					Type:           NodeSPN,
					Label:          value,
					NormalizedName: strings.ToLower(value),
					Properties: map[string]any{
						"spn":    value,
						"source": "ldap",
					},
					FirstSeen:   ctx.Timestamp,
					LastSeen:    ctx.Timestamp,
					Confidence:  0.90,
					EvidenceIDs: []string{ev.ID},
				})

				res.Edges = append(res.Edges, Edge{
					ID:       EdgeID(EdgeHasSPN, objectID, spnID),
					SourceID: objectID,
					TargetID: spnID,
					Type:     EdgeHasSPN,
					Properties: map[string]any{
						"source": "ldap",
						"spn":    value,
					},
					FirstSeen:   ctx.Timestamp,
					LastSeen:    ctx.Timestamp,
					Confidence:  0.90,
					EvidenceIDs: []string{ev.ID},
				})
			}
		}
		// OPSGRAPH_ATTACK_VECTOR_GRAPH_ARTIFACTS_V1_BEGIN
		// Convert LDAP exposure semantics into graph artifacts.
		//
		// This is evidence-only visualization:
		// object -> HasAttackVector -> AttackVector
		// object -> DelegatesTo      -> SPN target
		// AttackVector -> RelatedToTarget -> SPN target
		//
		// It does not execute or automate any technique.
		attackVectors, _ := ldapAttackVectorsFromExposure(exposureProps, objectType)
		for _, vector := range attackVectors {
			vectorID := ldapAttackVectorField(vector, "id")
			if vectorID == "" {
				continue
			}

			vectorLabel := ldapAttackVectorField(vector, "label")
			if vectorLabel == "" {
				vectorLabel = vectorID
			}

			vectorCategory := ldapAttackVectorField(vector, "category")
			vectorSeverity := ldapAttackVectorField(vector, "severity")

			attackNodeID := ldapAttackVectorNodeID(objectID, vectorID)

			vectorProps := map[string]any{
				"source":       "ldap_attack_surface",
				"owner_id":     objectID,
				"owner_label":  label,
				"vector_id":    vectorID,
				"category":     vectorCategory,
				"severity":     vectorSeverity,
				"display_name": vectorLabel,
			}

			for key, value := range vector {
				vectorProps[key] = value
			}

			res.Nodes = append(res.Nodes, Node{
				ID:             attackNodeID,
				Type:           NodeAttackVector,
				Label:          vectorLabel,
				NormalizedName: strings.ToLower(vectorCategory + ":" + vectorID),
				Properties:     vectorProps,
				FirstSeen:      ctx.Timestamp,
				LastSeen:       ctx.Timestamp,
				Confidence:     ldapAttackVectorConfidence(vector),
				EvidenceIDs:    []string{ev.ID},
			})

			res.Edges = append(res.Edges, Edge{
				ID:       EdgeID(EdgeHasAttackVector, objectID, attackNodeID),
				SourceID: objectID,
				TargetID: attackNodeID,
				Type:     EdgeHasAttackVector,
				Properties: map[string]any{
					"source":    "ldap_attack_surface",
					"vector_id": vectorID,
					"category":  vectorCategory,
					"severity":  vectorSeverity,
					"label":     vectorLabel,
				},
				FirstSeen:   ctx.Timestamp,
				LastSeen:    ctx.Timestamp,
				Confidence:  ldapAttackVectorConfidence(vector),
				EvidenceIDs: []string{ev.ID},
			})

			relatedTargets := make([]string, 0)

			if vectorID == "constrained_delegation" {
				relatedTargets = append(relatedTargets, ldapExposureStringList(exposureProps, "constrained_delegation_targets")...)
			}

			if vectorID == "kerberoast" || vectorID == "kerberoast_password_never_expires" {
				relatedTargets = append(relatedTargets, ldapExposureStringList(exposureProps, "service_principal_names")...)
			}

			relatedTargets = ldapDedupStrings(relatedTargets)

			if vectorID == "constrained_delegation" {
				for _, family := range ldapDelegationTargetFamiliesV1(relatedTargets, domain) {
					targetID := ldapDelegationTargetNodeIDV1(domain, family)

					res.Nodes = append(res.Nodes, Node{
						ID:             targetID,
						Type:           NodeDelegationTarget,
						Label:          family.Label,
						NormalizedName: strings.ToLower(family.Key),
						Properties: map[string]any{
							"source":                  "ldap_attack_surface",
							"target_role":             "delegation_target_family",
							"host":                    family.Host,
							"host_short":              family.HostShort,
							"allowed_services":        family.Services,
							"raw_delegation_targets":  family.RawTargets,
							"attack_vector_target":    true,
							"deduplicated_spn_family": true,
						},
						FirstSeen:   ctx.Timestamp,
						LastSeen:    ctx.Timestamp,
						Confidence:  0.88,
						EvidenceIDs: []string{ev.ID},
					})

					res.Edges = append(res.Edges, Edge{
						ID:       EdgeID(EdgeDelegatesTo, objectID, targetID),
						SourceID: objectID,
						TargetID: targetID,
						Type:     EdgeDelegatesTo,
						Properties: map[string]any{
							"source":                 "ldap_attack_surface",
							"vector_id":              vectorID,
							"target_role":            "delegation_target_family",
							"allowed_services":       family.Services,
							"raw_delegation_targets": family.RawTargets,
						},
						FirstSeen:   ctx.Timestamp,
						LastSeen:    ctx.Timestamp,
						Confidence:  0.88,
						EvidenceIDs: []string{ev.ID},
					})

					res.Edges = append(res.Edges, Edge{
						ID:       EdgeID(EdgeRelatedToTarget, attackNodeID, targetID),
						SourceID: attackNodeID,
						TargetID: targetID,
						Type:     EdgeRelatedToTarget,
						Properties: map[string]any{
							"source":                 "ldap_attack_surface",
							"vector_id":              vectorID,
							"target_role":            "delegation_target_family",
							"allowed_services":       family.Services,
							"raw_delegation_targets": family.RawTargets,
						},
						FirstSeen:   ctx.Timestamp,
						LastSeen:    ctx.Timestamp,
						Confidence:  ldapAttackVectorConfidence(vector),
						EvidenceIDs: []string{ev.ID},
					})
				}
			} else {
				for _, target := range relatedTargets {
					target = strings.TrimSpace(target)
					if target == "" {
						continue
					}

					targetSPNID := "spn:" + ShortHash(strings.ToLower(target))

					res.Nodes = append(res.Nodes, Node{
						ID:             targetSPNID,
						Type:           NodeSPN,
						Label:          target,
						NormalizedName: strings.ToLower(target),
						Properties: map[string]any{
							"spn":                  target,
							"source":               "ldap_attack_surface",
							"attack_vector_target": true,
						},
						FirstSeen:   ctx.Timestamp,
						LastSeen:    ctx.Timestamp,
						Confidence:  0.86,
						EvidenceIDs: []string{ev.ID},
					})

					res.Edges = append(res.Edges, Edge{
						ID:       EdgeID(EdgeRelatedToTarget, attackNodeID, targetSPNID),
						SourceID: attackNodeID,
						TargetID: targetSPNID,
						Type:     EdgeRelatedToTarget,
						Properties: map[string]any{
							"source":    "ldap_attack_surface",
							"vector_id": vectorID,
							"target":    target,
						},
						FirstSeen:   ctx.Timestamp,
						LastSeen:    ctx.Timestamp,
						Confidence:  ldapAttackVectorConfidence(vector),
						EvidenceIDs: []string{ev.ID},
					})
				}
			}
		}
		// OPSGRAPH_ATTACK_VECTOR_GRAPH_ARTIFACTS_V1_END

	}

	res.Evidence = append(res.Evidence, ev)
	return res
}

func ldapShouldSkipEntry(attrs map[string][]string, objectClass string, dn string, sam string, sid string, dnsHost string) bool {
	objectClass = strings.ToLower(strings.TrimSpace(objectClass))
	dn = strings.ToLower(strings.TrimSpace(dn))

	// Keep real principals and relationship-bearing objects even when the LDAP
	// query did not request objectClass. Adaptix ldapsearch often runs with a
	// narrow -a list, so objectClass may be absent while sAMAccountName/objectSid
	// are present.
	if strings.TrimSpace(sam) != "" ||
		strings.TrimSpace(sid) != "" ||
		strings.TrimSpace(dnsHost) != "" ||
		len(ldapAttrValues(attrs, "member")) > 0 ||
		len(ldapAttrValues(attrs, "memberof")) > 0 ||
		len(ldapAttrValues(attrs, "serviceprincipalname")) > 0 {
		return false
	}

	// The base domain object is represented by the Domain node, not as a User.
	if strings.Contains(objectClass, "domaindns") || ldapIsDomainDN(dn) {
		return true
	}

	// LDAP containers and OUs are structure, not security principals.
	// Examples:
	//   CN=Users,DC=...
	//   CN=Computers,DC=...
	//   CN=System,DC=...
	//   OU=Domain Controllers,DC=...
	if strings.Contains(objectClass, "container") ||
		strings.Contains(objectClass, "organizationalunit") {
		return true
	}

	// If objectClass is missing and no principal attributes exist, skip safely.
	if objectClass == "" {
		return true
	}

	return true
}

func parseLDAPEntries(output string) []ldapEntry {
	lines := strings.Split(output, "\n")
	entries := make([]ldapEntry, 0)
	current := make([]string, 0)
	inEntry := false

	flush := func() {
		if len(current) == 0 {
			return
		}

		attrs := make(map[string][]string)
		raw := strings.Join(current, "\n")

		for _, line := range current {
			line = strings.TrimSpace(line)
			idx := strings.Index(line, ":")
			if idx <= 0 {
				continue
			}

			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			if key == "" || val == "" {
				continue
			}

			attrs[key] = append(attrs[key], val)
		}

		if len(attrs) > 0 {
			entries = append(entries, ldapEntry{Attrs: attrs, Raw: raw})
		}

		current = make([]string, 0)
	}

	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "--------------------" {
			if inEntry {
				flush()
			}
			inEntry = true
			continue
		}

		if !inEntry {
			continue
		}

		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "retrieved ") ||
			strings.HasPrefix(lower, "[") ||
			strings.HasPrefix(lower, "+---") {
			continue
		}

		if strings.Contains(line, ":") {
			current = append(current, line)
		}
	}

	flush()
	return entries
}

func ldapDomainFromOutput(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "[*] distinguished name:") {
			idx := strings.Index(line, ":")
			if idx >= 0 {
				return ldapDomainFromDN(strings.TrimSpace(line[idx+1:]))
			}
		}
	}

	return ""
}

func ldapDomainFromDN(dn string) string {
	matches := ldapDCPart.FindAllStringSubmatch(dn, -1)
	if len(matches) == 0 {
		return ""
	}

	parts := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) == 2 {
			parts = append(parts, strings.ToLower(strings.TrimSpace(match[1])))
		}
	}

	return NormalizeDomain(strings.Join(parts, "."))
}

func ldapCNFromDN(dn string) string {
	dn = strings.TrimSpace(dn)
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "cn=") {
			return strings.TrimSpace(part[3:])
		}
	}

	return ""
}

func ldapIsDomainDN(dn string) bool {
	dn = strings.TrimSpace(strings.ToLower(dn))
	return strings.HasPrefix(dn, "dc=")
}

func ldapNetBIOSFromDomain(domain string) string {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return "UNKNOWN"
	}

	first := strings.Split(domain, ".")[0]
	if first == "" {
		return "UNKNOWN"
	}

	return strings.ToUpper(first)
}

func ldapFirstAttr(attrs map[string][]string, names ...string) string {
	for _, name := range names {
		values := attrs[strings.ToLower(name)]
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value != "" {
				return value
			}
		}
	}

	return ""
}

func ldapAttrValues(attrs map[string][]string, name string) []string {
	return attrs[strings.ToLower(name)]
}

func ldapAttributeDNs(attrs map[string][]string, name string) []string {
	out := make([]string, 0)
	for _, value := range ldapAttrValues(attrs, name) {
		for _, dn := range ldapSplitDNList(value) {
			dn = strings.TrimSpace(dn)
			if dn != "" {
				out = append(out, dn)
			}
		}
	}

	return out
}

func ldapSplitDNList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	parts := make([]string, 0)
	start := 0

	for i := 0; i < len(value)-4; i++ {
		if value[i] == ',' && i+1 < len(value) && value[i+1] == ' ' {
			rest := strings.ToLower(value[i+2:])
			if strings.HasPrefix(rest, "cn=") || strings.HasPrefix(rest, "ou=") {
				parts = append(parts, strings.TrimSpace(value[start:i]))
				start = i + 2
			}
		}
	}

	parts = append(parts, strings.TrimSpace(value[start:]))
	return parts
}

func ldapSplitSimpleList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	if strings.Contains(value, ", ") {
		return strings.Split(value, ", ")
	}

	return []string{value}
}

func ldapLooksLikeComputer(attrs map[string][]string, objectClass string, sam string, dnsHost string) bool {
	return strings.Contains(objectClass, "computer") ||
		strings.TrimSpace(dnsHost) != "" ||
		strings.HasSuffix(strings.TrimSpace(sam), "$")
}

func ldapLooksLikeGroup(attrs map[string][]string, objectClass string) bool {
	if strings.Contains(objectClass, "group") {
		return true
	}

	if len(ldapAttrValues(attrs, "member")) > 0 {
		return true
	}

	sam := strings.ToLower(ldapFirstAttr(attrs, "samaccountname"))
	return strings.HasSuffix(sam, "admins") ||
		strings.HasSuffix(sam, "users") ||
		strings.Contains(sam, "group")
}

func ldapDomainNode(domain string, ts int64, evidenceID string) Node {
	return Node{
		ID:             DomainID(domain),
		Type:           NodeDomain,
		Label:          NormalizeDomain(domain),
		NormalizedName: NormalizeDomain(domain),
		Properties: map[string]any{
			"domain": NormalizeDomain(domain),
			"source": "ldap",
		},
		FirstSeen:   ts,
		LastSeen:    ts,
		Confidence:  0.90,
		EvidenceIDs: []string{evidenceID},
	}
}

func ldapGroupNodeFromDN(dn string, fallbackDomain string, ts int64, evidenceID string) (string, Node) {
	domain := ldapDomainFromDN(dn)
	if domain == "" {
		domain = fallbackDomain
	}

	name := ldapCNFromDN(dn)
	if domain == "" || name == "" {
		return "", Node{}
	}

	netbios := ldapNetBIOSFromDomain(domain)
	id := GroupID(netbios, name)
	label := netbios + `\` + name

	return id, Node{
		ID:             id,
		Type:           NodeGroup,
		Label:          label,
		NormalizedName: strings.ToLower(label),
		Properties: map[string]any{
			"domain":     netbios,
			"dns_domain": domain,
			"name":       name,
			"dn":         dn,
			"scope":      "domain",
			"source":     "ldap",
		},
		FirstSeen:   ts,
		LastSeen:    ts,
		Confidence:  0.85,
		EvidenceIDs: []string{evidenceID},
	}
}

func ldapNodeFromMemberDN(dn string, fallbackDomain string, ts int64, evidenceID string) (string, Node) {
	domain := ldapDomainFromDN(dn)
	if domain == "" {
		domain = fallbackDomain
	}

	cn := ldapCNFromDN(dn)
	if domain == "" || cn == "" {
		return "", Node{}
	}

	if strings.HasSuffix(cn, "$") {
		computer := strings.TrimSuffix(cn, "$")
		id := ComputerID(domain, computer)
		return id, Node{
			ID:             id,
			Type:           NodeComputer,
			Label:          computer,
			NormalizedName: NormalizeComputer(computer),
			Properties: map[string]any{
				"domain":               domain,
				"cn":                   cn,
				"dn":                   dn,
				"source":               "ldap_member_dn",
				"dn_based_identity":    true,
				"requires_correlation": true,
			},
			FirstSeen:   ts,
			LastSeen:    ts,
			Confidence:  0.65,
			HostState:   HostDiscovered,
			EvidenceIDs: []string{evidenceID},
		}
	}

	id := UserID(domain, cn)
	return id, Node{
		ID:             id,
		Type:           NodeUser,
		Label:          cn,
		NormalizedName: strings.ToLower(domain + `\` + cn),
		Properties: map[string]any{
			"domain":               domain,
			"sam":                  cn,
			"cn":                   cn,
			"dn":                   dn,
			"source":               "ldap_member_dn",
			"dn_based_identity":    true,
			"requires_correlation": true,
		},
		FirstSeen:   ts,
		LastSeen:    ts,
		Confidence:  0.65,
		EvidenceIDs: []string{evidenceID},
	}
}

func ldapFirstN(text string, n int) string {
	text = strings.TrimSpace(text)
	if len(text) <= n {
		return text
	}

	return text[:n] + "\n... <truncated>"
}

func _ldapFmt(_ string, _ ...any) string {
	// Keeps fmt imported for future richer parser diagnostics without changing API.
	return fmt.Sprintf("", nil)
}

func ldapExposureProperties(attrs map[string][]string, uac string) map[string]any {
	out := make(map[string]any)

	uac = strings.TrimSpace(uac)
	if uac != "" {
		out["user_account_control_raw"] = uac

		flags := ldapUACFlags(uac)
		if len(flags) > 0 {
			out["uac_flags"] = flags
		}

		if ldapUACHas(uac, 0x00000002) {
			out["account_disabled"] = true
		}
		if ldapUACHas(uac, 0x00010000) {
			out["password_never_expires"] = true
		}
		if ldapUACHas(uac, 0x00040000) {
			out["smartcard_required"] = true
		}
		if ldapUACHas(uac, 0x00080000) {
			out["unconstrained_delegation"] = true
		}
		if ldapUACHas(uac, 0x00100000) {
			out["not_delegated"] = true
		}
		if ldapUACHas(uac, 0x00200000) {
			out["use_des_key_only"] = true
		}
		if ldapUACHas(uac, 0x00400000) {
			out["preauth_not_required"] = true
		}
		if ldapUACHas(uac, 0x01000000) {
			out["constrained_delegation_enabled"] = true
		}
		if ldapUACHas(uac, 0x00002000) {
			out["server_trust_account"] = true
		}
	}

	spns := ldapCollectedSimpleAttrValues(attrs, "serviceprincipalname")
	if len(spns) > 0 {
		out["has_spn"] = true
		out["service_principal_names"] = spns
	}

	delegationTargets := ldapCollectedSimpleAttrValues(attrs, "msds-allowedtodelegateto")
	if len(delegationTargets) > 0 {
		out["constrained_delegation_targets"] = delegationTargets
	}

	rbcdValues := ldapAttrValues(attrs, "msds-allowedtoactonbehalfofotheridentity")
	if len(rbcdValues) > 0 {
		out["rbcd_descriptor_present"] = true
		out["rbcd_descriptor_value_count"] = len(rbcdValues)
	}

	adminCount := ldapFirstAttr(attrs, "admincount")
	if strings.TrimSpace(adminCount) != "" {
		out["admin_count"] = strings.TrimSpace(adminCount)
		if strings.TrimSpace(adminCount) == "1" {
			out["admin_count_1"] = true
		}
	}

	return out
}

// OPSGRAPH_LDAP_ATTACK_SURFACE_SEMANTICS_V1_BEGIN
func ldapAttachAttackVectors(props map[string]any, exposure map[string]any, nodeType NodeType) map[string]any {
	if props == nil {
		props = make(map[string]any)
	}

	if exposure == nil {
		exposure = make(map[string]any)
	}

	if len(exposure) > 0 {
		props["exposure"] = exposure

		// Promote exposure fields to top-level properties as well. Existing UI
		// relevance code already checks direct node properties in several places,
		// while newer panels can still use the structured exposure object.
		for key, value := range exposure {
			if _, exists := props[key]; !exists {
				props[key] = value
			}
		}
	}

	vectors, ids := ldapAttackVectorsFromExposure(exposure, nodeType)
	if len(vectors) > 0 {
		props["attack_vectors"] = vectors
		props["attack_vector_ids"] = ids
		props["attack_surface_version"] = "ldap_attack_surface_semantics_v1"
	}

	return props
}

func ldapAttackVectorsFromExposure(exposure map[string]any, nodeType NodeType) ([]map[string]any, []string) {
	vectors := make([]map[string]any, 0)
	ids := make([]string, 0)
	seen := make(map[string]bool)

	add := func(id string, label string, category string, severity string, confidence float64, evidence string, extra map[string]any) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}

		seen[id] = true
		ids = append(ids, id)

		vec := map[string]any{
			"id":         id,
			"label":      label,
			"category":   category,
			"severity":   severity,
			"confidence": confidence,
			"evidence":   evidence,
			"source":     "ldap_exposure",
		}

		if extra != nil {
			for key, value := range extra {
				vec[key] = value
			}
		}

		vectors = append(vectors, vec)
	}

	hasSPN := ldapExposureBool(exposure, "has_spn") || len(ldapExposureStringList(exposure, "service_principal_names")) > 0
	preauthNotRequired := ldapExposureBool(exposure, "preauth_not_required")
	passwordNeverExpires := ldapExposureBool(exposure, "password_never_expires")
	unconstrainedDelegation := ldapExposureBool(exposure, "unconstrained_delegation")
	constrainedDelegationTargets := ldapExposureStringList(exposure, "constrained_delegation_targets")
	constrainedDelegation := ldapExposureBool(exposure, "constrained_delegation_enabled") || len(constrainedDelegationTargets) > 0
	rbcdPresent := ldapExposureBool(exposure, "rbcd_descriptor_present")
	adminCountOne := ldapExposureBool(exposure, "admin_count_1") || ldapExposureString(exposure, "admin_count") == "1"
	useDesOnly := ldapExposureBool(exposure, "use_des_key_only")

	switch nodeType {
	case NodeUser:
		if hasSPN {
			add(
				"kerberoast",
				"Kerberoast candidate",
				"kerberos",
				"medium",
				0.88,
				"servicePrincipalName present on user account",
				nil,
			)
		}

		if hasSPN && passwordNeverExpires {
			add(
				"kerberoast_password_never_expires",
				"Kerberoast candidate with password-never-expires signal",
				"kerberos",
				"high",
				0.90,
				"servicePrincipalName present and password_never_expires observed",
				nil,
			)
		}

		if preauthNotRequired {
			add(
				"asrep_roast",
				"ASREP roastable candidate",
				"kerberos",
				"high",
				0.90,
				"userAccountControl indicates pre-authentication is not required",
				nil,
			)
		}

	case NodeComputer:
		if hasSPN {
			add(
				"spn_service_endpoint",
				"SPN service endpoint",
				"kerberos",
				"info",
				0.78,
				"servicePrincipalName present on computer account",
				nil,
			)
		}
	}

	if unconstrainedDelegation {
		add(
			"unconstrained_delegation",
			"Unconstrained delegation",
			"delegation",
			"critical",
			0.92,
			"userAccountControl indicates trusted for delegation",
			nil,
		)
	}

	if constrainedDelegation {
		extra := map[string]any{}
		if len(constrainedDelegationTargets) > 0 {
			extra["targets"] = constrainedDelegationTargets
		}

		add(
			"constrained_delegation",
			"Constrained delegation",
			"delegation",
			"high",
			0.88,
			"constrained delegation flag or msDS-AllowedToDelegateTo target observed",
			extra,
		)
	}

	if rbcdPresent {
		add(
			"rbcd",
			"RBCD descriptor present",
			"rbcd",
			"high",
			0.86,
			"msDS-AllowedToActOnBehalfOfOtherIdentity present",
			nil,
		)
	}

	if adminCountOne {
		add(
			"protected_admin_count",
			"Protected/adminCount=1 object",
			"privilege",
			"high",
			0.86,
			"adminCount=1 observed",
			nil,
		)
	}

	if useDesOnly {
		add(
			"weak_kerberos_crypto",
			"DES-only Kerberos key flag",
			"kerberos",
			"medium",
			0.84,
			"userAccountControl indicates DES key only",
			nil,
		)
	}

	vectors = ldapMergeKerberoastVectorsV1(vectors, exposure)
	ids = ldapAttackVectorIDsV1(vectors)
	return vectors, ids
}

func ldapExposureBool(exposure map[string]any, key string) bool {
	if exposure == nil {
		return false
	}

	value, ok := exposure[key]
	if !ok || value == nil {
		return false
	}

	switch v := value.(type) {
	case bool:
		return v
	case string:
		s := strings.TrimSpace(strings.ToLower(v))
		return s == "true" || s == "1" || s == "yes" || s == "enabled"
	case int:
		return v != 0
	case int64:
		return v != 0
	case float64:
		return v != 0
	case []string:
		return len(v) > 0
	case []any:
		return len(v) > 0
	default:
		s := strings.TrimSpace(strings.ToLower(fmt.Sprint(v)))
		return s == "true" || s == "1" || s == "yes" || s == "enabled"
	}
}

func ldapExposureString(exposure map[string]any, key string) string {
	if exposure == nil {
		return ""
	}

	value, ok := exposure[key]
	if !ok || value == nil {
		return ""
	}

	return strings.TrimSpace(fmt.Sprint(value))
}

func ldapExposureStringList(exposure map[string]any, key string) []string {
	out := make([]string, 0)
	seen := make(map[string]bool)

	if exposure == nil {
		return out
	}

	value, ok := exposure[key]
	if !ok || value == nil {
		return out
	}

	add := func(raw string) {
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == '\r' || r == '\n' || r == ',' || r == ';'
		}) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}

			lower := strings.ToLower(part)
			if seen[lower] {
				continue
			}

			seen[lower] = true
			out = append(out, part)
		}
	}

	switch v := value.(type) {
	case []string:
		for _, item := range v {
			add(item)
		}
	case []any:
		for _, item := range v {
			add(fmt.Sprint(item))
		}
	case string:
		add(v)
	default:
		add(fmt.Sprint(v))
	}

	return out
}

// OPSGRAPH_LDAP_ATTACK_SURFACE_SEMANTICS_V1_END

// OPSGRAPH_KERBEROAST_VECTOR_MERGE_V1_BEGIN
func ldapMergeKerberoastVectorsV1(vectors []map[string]any, exposure map[string]any) []map[string]any {
	if len(vectors) == 0 {
		return vectors
	}

	passwordNeverExpires := false
	if exposure != nil {
		if v, ok := exposure["password_never_expires"].(bool); ok && v {
			passwordNeverExpires = true
		}
	}

	out := make([]map[string]any, 0, len(vectors))
	var kerberoast map[string]any

	for _, vector := range vectors {
		id := strings.ToLower(strings.TrimSpace(fmt.Sprint(vector["id"])))

		if id == "kerberoast_password_never_expires" {
			passwordNeverExpires = true
			continue
		}

		if id == "kerberoast" {
			kerberoast = vector
			continue
		}

		out = append(out, vector)
	}

	if kerberoast != nil {
		signals := []string{"servicePrincipalName present"}

		kerberoast["id"] = "kerberoast"
		kerberoast["category"] = "kerberos"
		kerberoast["source"] = "ldap_exposure"

		if passwordNeverExpires {
			kerberoast["label"] = "Kerberoast exposure"
			kerberoast["severity"] = "high"
			kerberoast["confidence"] = 0.90
			kerberoast["evidence"] = "servicePrincipalName present; password-never-expires observed"
			signals = append(signals, "password never expires")
			kerberoast["merged_from"] = []string{"kerberoast", "kerberoast_password_never_expires"}
		} else {
			kerberoast["label"] = "Kerberoast exposure"
			kerberoast["severity"] = "medium"
			kerberoast["confidence"] = 0.88
			kerberoast["evidence"] = "servicePrincipalName present on user account"
			kerberoast["merged_from"] = []string{"kerberoast"}
		}

		kerberoast["signals"] = signals
		out = append(out, kerberoast)
	}

	return out
}

func ldapAttackVectorIDsV1(vectors []map[string]any) []string {
	ids := make([]string, 0, len(vectors))
	seen := make(map[string]bool)

	for _, vector := range vectors {
		id := strings.ToLower(strings.TrimSpace(fmt.Sprint(vector["id"])))
		if id == "" || seen[id] {
			continue
		}

		seen[id] = true
		ids = append(ids, id)
	}

	return ids
}

// OPSGRAPH_KERBEROAST_VECTOR_MERGE_V1_END

// OPSGRAPH_DELEGATION_TARGET_FAMILY_V1_BEGIN
type ldapDelegationTargetFamilyV1 struct {
	Key        string
	Label      string
	Host       string
	HostShort  string
	Services   []string
	RawTargets []string
}

func ldapParseSPNV1(spn string) (string, string) {
	spn = strings.TrimSpace(spn)
	if spn == "" {
		return "", ""
	}

	parts := strings.SplitN(spn, "/", 2)
	if len(parts) != 2 {
		return "", strings.ToLower(spn)
	}

	service := strings.ToUpper(strings.TrimSpace(parts[0]))
	host := strings.TrimSpace(parts[1])

	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}

	return service, strings.ToLower(host)
}

func ldapShortHostFromSPNV1(host string, domain string) string {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".")
	domain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")

	if host == "" {
		return ""
	}

	if domain != "" && strings.HasSuffix(host, "."+domain) {
		host = strings.TrimSuffix(host, "."+domain)
	}

	if idx := strings.Index(host, "."); idx > 0 {
		return host[:idx]
	}

	return host
}

func ldapTitleHostV1(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	return strings.ToUpper(host)
}

func ldapDelegationTargetFamiliesV1(targets []string, domain string) []ldapDelegationTargetFamilyV1 {
	families := make(map[string]*ldapDelegationTargetFamilyV1)
	order := make([]string, 0)

	for _, raw := range targets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		service, host := ldapParseSPNV1(raw)
		hostShort := ldapShortHostFromSPNV1(host, domain)
		if hostShort == "" {
			hostShort = host
		}

		key := strings.ToLower(hostShort)
		if key == "" {
			key = strings.ToLower(raw)
		}

		family, ok := families[key]
		if !ok {
			family = &ldapDelegationTargetFamilyV1{
				Key:       key,
				Label:     ldapTitleHostV1(hostShort),
				Host:      host,
				HostShort: hostShort,
			}
			families[key] = family
			order = append(order, key)
		}

		if service != "" {
			exists := false
			for _, s := range family.Services {
				if strings.EqualFold(s, service) {
					exists = true
					break
				}
			}
			if !exists {
				family.Services = append(family.Services, service)
			}
		}

		existsRaw := false
		for _, s := range family.RawTargets {
			if strings.EqualFold(s, raw) {
				existsRaw = true
				break
			}
		}
		if !existsRaw {
			family.RawTargets = append(family.RawTargets, raw)
		}
	}

	out := make([]ldapDelegationTargetFamilyV1, 0, len(order))
	for _, key := range order {
		family := families[key]
		sort.Strings(family.Services)
		sort.Strings(family.RawTargets)
		out = append(out, *family)
	}

	return out
}

func ldapDelegationTargetNodeIDV1(domain string, family ldapDelegationTargetFamilyV1) string {
	key := strings.ToLower(strings.TrimSpace(domain + "|" + family.Key))
	return "service:delegation-target:" + ShortHash(key)
}

// OPSGRAPH_DELEGATION_TARGET_FAMILY_V1_END

func ldapAttackVectorField(vector map[string]any, key string) string {
	if vector == nil {
		return ""
	}

	value, ok := vector[key]
	if !ok || value == nil {
		return ""
	}

	return strings.TrimSpace(fmt.Sprint(value))
}

func ldapAttackVectorConfidence(vector map[string]any) float64 {
	if vector == nil {
		return 0.80
	}

	value, ok := vector["confidence"]
	if !ok || value == nil {
		return 0.80
	}

	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err == nil {
			return parsed
		}
	}

	return 0.80
}

func ldapAttackVectorNodeID(ownerID string, vectorID string) string {
	return "attackvector:" + ShortHash(strings.ToLower(ownerID+"|"+vectorID))
}

func ldapDedupStrings(values []string) []string {
	out := make([]string, 0)
	seen := make(map[string]bool)

	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		key := strings.ToLower(value)
		if seen[key] {
			continue
		}

		seen[key] = true
		out = append(out, value)
	}

	return out
}

func ldapCollectedSimpleAttrValues(attrs map[string][]string, name string) []string {
	out := make([]string, 0)
	seen := make(map[string]bool)

	for _, raw := range ldapAttrValues(attrs, name) {
		for _, value := range ldapSplitSimpleList(raw) {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}

			key := strings.ToLower(value)
			if seen[key] {
				continue
			}

			seen[key] = true
			out = append(out, value)
		}
	}

	return out
}

func ldapUACValue(raw string) (int64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}

	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}

	return value, true
}

func ldapUACHas(raw string, flag int64) bool {
	value, ok := ldapUACValue(raw)
	if !ok {
		return false
	}

	return value&flag != 0
}

func ldapUACFlags(raw string) []string {
	value, ok := ldapUACValue(raw)
	if !ok {
		return nil
	}

	flags := []struct {
		Bit  int64
		Name string
	}{
		{0x00000002, "ACCOUNTDISABLE"},
		{0x00000010, "LOCKOUT"},
		{0x00000020, "PASSWD_NOTREQD"},
		{0x00000200, "NORMAL_ACCOUNT"},
		{0x00001000, "WORKSTATION_TRUST_ACCOUNT"},
		{0x00002000, "SERVER_TRUST_ACCOUNT"},
		{0x00010000, "DONT_EXPIRE_PASSWORD"},
		{0x00040000, "SMARTCARD_REQUIRED"},
		{0x00080000, "TRUSTED_FOR_DELEGATION"},
		{0x00100000, "NOT_DELEGATED"},
		{0x00200000, "USE_DES_KEY_ONLY"},
		{0x00400000, "DONT_REQ_PREAUTH"},
		{0x01000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"},
	}

	out := make([]string, 0)
	for _, flag := range flags {
		if value&flag.Bit != 0 {
			out = append(out, flag.Name)
		}
	}

	return out
}
