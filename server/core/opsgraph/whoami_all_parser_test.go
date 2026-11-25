package opsgraph

import "testing"

func TestWhoamiAllParserParsesUserGroupsAndPrivileges(t *testing.T) {
	output := `
USER INFORMATION
----------------

User Name SID
========= =============================================
WIN\benzo S-1-5-21-1313843319-228051742-2022106187-1000


GROUP INFORMATION
-----------------

Group Name                                           Type             SID                                            Attributes
==================================================== ================ ============================================== ==================================================
Everyone                                             Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                               Alias            S-1-5-32-544                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                             Well-known group S-1-5-4                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                     Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeShutdownPrivilege           Shut down the system                      Disabled
`

	parser := WhoamiAllParser{}
	ctx := TaskContext{
		TaskID:      "task-001",
		AgentID:     "agent-001",
		CommandLine: "whoami /all",
		Output:      output,
		User:        "benzo",
		Computer:    "WIN",
		Timestamp:   1720000000,
		SourceKind:  "task",
	}

	if !parser.Match(ctx) {
		t.Fatalf("expected parser to match whoami /all")
	}

	res := parser.Parse(ctx)

	if len(res.Nodes) < 5 {
		t.Fatalf("expected user + group nodes, got %d", len(res.Nodes))
	}

	if len(res.Edges) < 4 {
		t.Fatalf("expected memberof edges, got %d", len(res.Edges))
	}

	userID := UserID("", "benzo")
	foundUser := false
	foundAdminGroup := false
	foundAdminEdge := false

	for _, node := range res.Nodes {
		if node.ID == userID {
			foundUser = true

			if node.Properties["sid"] == "" {
				t.Fatalf("expected user sid property")
			}

			groups, ok := node.Properties["groups"].([]map[string]any)
			if !ok || len(groups) < 4 {
				t.Fatalf("expected groups property with at least 4 groups, got %#v", node.Properties["groups"])
			}

			privs, ok := node.Properties["privileges"].([]map[string]any)
			if !ok || len(privs) < 2 {
				t.Fatalf("expected privileges property with at least 2 privileges, got %#v", node.Properties["privileges"])
			}
		}

		if node.Type == NodeGroup && node.Label == `BUILTIN\Administrators` {
			foundAdminGroup = true
		}
	}

	for _, edge := range res.Edges {
		if edge.Type == EdgeMemberOf && edge.SourceID == userID && edge.TargetID == whoamiAllGroupID("BUILTIN", "Administrators") {
			foundAdminEdge = true
		}
	}

	if !foundUser {
		t.Fatalf("expected user node %s", userID)
	}
	if !foundAdminGroup {
		t.Fatalf("expected BUILTIN Administrators group node")
	}
	if !foundAdminEdge {
		t.Fatalf("expected MemberOf edge to BUILTIN Administrators")
	}
}
