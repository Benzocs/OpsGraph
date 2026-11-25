package opsgraph

import "testing"

func TestAclParserParsesPrincipalRightTarget(t *testing.T) {
	parser := AclParser{}
	ctx := TaskContext{
		TaskID:      "task-acl-1",
		AgentID:     "agent-1",
		CommandLine: "acl dump",
		Domain:      "za.tryhackme.loc",
		SourceKind:  "task",
		Timestamp:   1700000000,
		Output: `
IdentityReference: ZA\IT Support
ActiveDirectoryRights: GenericWrite, WriteDacl
ObjectDN: CN=svcIIS,CN=Users,DC=za,DC=tryhackme,DC=loc
AccessControlType: Allow
IsInherited: False
`,
	}

	if !parser.Match(ctx) {
		t.Fatalf("expected parser to match ACL-like output")
	}

	result := parser.Parse(ctx)

	if len(result.Edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(result.Edges))
	}

	edge := result.Edges[0]
	if edge.Type != EdgeACLRight {
		t.Fatalf("expected EdgeACLRight, got %s", edge.Type)
	}

	rights, ok := edge.Properties["rights"].([]string)
	if !ok {
		t.Fatalf("expected rights []string property, got %#v", edge.Properties["rights"])
	}

	foundGenericWrite := false
	foundWriteDACL := false
	for _, r := range rights {
		if r == "GenericWrite" {
			foundGenericWrite = true
		}
		if r == "WriteDACL" {
			foundWriteDACL = true
		}
	}

	if !foundGenericWrite || !foundWriteDACL {
		t.Fatalf("expected GenericWrite and WriteDACL rights, got %#v", rights)
	}

	if len(result.Evidence) == 0 {
		t.Fatalf("expected evidence")
	}
}

func TestDefaultAllowedPathEdgesIncludesACLRight(t *testing.T) {
	allowed := DefaultAllowedPathEdges()
	if !allowed[EdgeACLRight] {
		t.Fatalf("expected EdgeACLRight to be allowed in default path edges")
	}
}
