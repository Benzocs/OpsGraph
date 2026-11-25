package opsgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var dnsSafe = regexp.MustCompile(`[^a-z0-9._-]+`)

func NormalizeDomain(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimSuffix(v, ".")
	return dnsSafe.ReplaceAllString(v, "")
}

func NormalizeSAM(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, `\\`)
	return strings.Trim(v, " \t\r\n")
}

func NormalizeComputer(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimSuffix(v, "$")
	v = strings.TrimSuffix(v, ".")
	return dnsSafe.ReplaceAllString(v, "")
}

func ShortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:16]
}

func EvidenceID(sourceKind, sourceID, parserName, snippet string) string {
	return fmt.Sprintf("ev:%s:%s:%s:%s", sourceKind, sourceID, parserName, ShortHash(snippet))
}

func DomainID(domain string) string {
	return "domain:" + NormalizeDomain(domain)
}

func UserID(domain, user string) string {
	d := NormalizeDomain(domain)
	u := NormalizeSAM(user)
	if d == "" {
		return "user:unknown:" + u
	}
	return "user:" + d + ":" + u
}

func ComputerID(domain, computer string) string {
	d := NormalizeDomain(domain)
	c := NormalizeComputer(computer)
	if d == "" {
		return "computer:unknown:" + c
	}
	return "computer:" + d + ":" + c
}

func AgentID(agentID string) string {
	return "agent:" + strings.TrimSpace(agentID)
}

func GroupID(domain, group string) string {
	d := NormalizeDomain(domain)
	g := NormalizeSAM(group)
	if d == "" {
		return "group:unknown:" + g
	}
	return "group:" + d + ":" + g
}

func SIDNodeID(kind, sid string) string {
	kind = strings.TrimSpace(strings.ToLower(kind))
	sid = strings.TrimSpace(strings.ToLower(sid))
	if kind == "" {
		kind = "sid"
	}
	return kind + ":sid:" + sid
}

func PrivilegeID(name string) string {
	return "privilege:" + NormalizeSAM(name)
}

func IntegrityID(label string) string {
	return "integrity:" + NormalizeSAM(label)
}

func CredentialID(kind, principal, materialHint string) string {
	raw := kind + ":" + strings.ToLower(principal) + ":" + materialHint
	return "credential:" + ShortHash(raw)
}

func EdgeID(edgeType EdgeType, sourceID, targetID string) string {
	return fmt.Sprintf("edge:%s:%s:%s", strings.ToLower(string(edgeType)), sourceID, targetID)
}
