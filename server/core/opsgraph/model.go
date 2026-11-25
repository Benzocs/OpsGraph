package opsgraph

// NodeType defines high-level graph entities.
type NodeType string

const (
	NodeForest       NodeType = "Forest"
	NodeDomain       NodeType = "Domain"
	NodeTrust        NodeType = "Trust"
	NodeOU           NodeType = "OU"
	NodeUser         NodeType = "User"
	NodeGroup        NodeType = "Group"
	NodeComputer     NodeType = "Computer"
	NodeAgent        NodeType = "Agent"
	NodeSession      NodeType = "Session"
	NodeCredential   NodeType = "Credential"
	NodeSPN          NodeType = "SPN"
	NodeAttackVector NodeType = "AttackVector"
	NodeService      NodeType = "Service"

	NodeDelegationTarget NodeType = "DelegationTarget"
	NodeShare            NodeType = "Share"
	NodeProcess          NodeType = "Process"
	NodeIP               NodeType = "IP"
	NodeSubnet           NodeType = "Subnet"
	NodeListener         NodeType = "Listener"
	NodePrivilege        NodeType = "Privilege"
	NodeIntegrity        NodeType = "IntegrityLevel"
)

// EdgeType defines observed relationships. Every edge must have evidence.
type EdgeType string

const (
	EdgeMemberOf        EdgeType = "MemberOf"
	EdgeContains        EdgeType = "Contains"
	EdgeInDomain        EdgeType = "InDomain"
	EdgeInForest        EdgeType = "InForest"
	EdgeTrusts          EdgeType = "Trusts"
	EdgeLoggedOnTo      EdgeType = "LoggedOnTo"
	EdgeHasSession      EdgeType = "HasSession"
	EdgeRunningOn       EdgeType = "RunningOn"
	EdgeRunningAs       EdgeType = "RunningAs"
	EdgeImpersonating   EdgeType = "Impersonating"
	EdgeBelongsTo       EdgeType = "BelongsTo"
	EdgeHasSPN          EdgeType = "HasSPN"
	EdgeHasAttackVector EdgeType = "HasAttackVector"
	EdgeDelegatesTo     EdgeType = "DelegatesTo"
	EdgeHasShare        EdgeType = "HasShare"
	EdgeRunsService     EdgeType = "RunsService"
	EdgeHasProcess      EdgeType = "HasProcess"
	EdgeObservedFrom    EdgeType = "ObservedFrom"
	EdgeRelatedToTarget EdgeType = "RelatedToTarget"
	EdgeHasPrivilege    EdgeType = "HasPrivilege"
	EdgeHasIntegrity    EdgeType = "HasIntegrity"
	EdgeACLRight        EdgeType = "ACLRight"
)

type HostState string

const (
	HostUnknown             HostState = "Unknown"
	HostDiscovered          HostState = "Discovered"
	HostEnumerated          HostState = "Enumerated"
	HostAccessObserved      HostState = "AccessObserved"
	HostFootholdActive      HostState = "FootholdActive"
	HostFootholdStale       HostState = "FootholdStale"
	HostElevatedFoothold    HostState = "ElevatedFoothold"
	HostImpersonatedContext HostState = "ImpersonatedContext"
	HostLostAccess          HostState = "LostAccess"
)

type Node struct {
	ID             string         `json:"id"`
	Type           NodeType       `json:"type"`
	Label          string         `json:"label"`
	NormalizedName string         `json:"normalized_name"`
	Properties     map[string]any `json:"properties"`
	FirstSeen      int64          `json:"first_seen"`
	LastSeen       int64          `json:"last_seen"`
	Confidence     float64        `json:"confidence"`
	HostState      HostState      `json:"host_state,omitempty"`
	HighValue      bool           `json:"high_value"`
	EvidenceIDs    []string       `json:"evidence_ids,omitempty"`
}

type Edge struct {
	ID          string         `json:"id"`
	SourceID    string         `json:"source"`
	TargetID    string         `json:"target"`
	Type        EdgeType       `json:"type"`
	Properties  map[string]any `json:"properties"`
	FirstSeen   int64          `json:"first_seen"`
	LastSeen    int64          `json:"last_seen"`
	Confidence  float64        `json:"confidence"`
	EvidenceIDs []string       `json:"evidence_ids,omitempty"`
}

type Evidence struct {
	ID          string  `json:"id"`
	NodeID      string  `json:"node_id,omitempty"`
	EdgeID      string  `json:"edge_id,omitempty"`
	SourceKind  string  `json:"source_kind"` // agent, task, credential, target, event, console
	SourceID    string  `json:"source_id"`
	AgentID     string  `json:"agent_id,omitempty"`
	TaskID      string  `json:"task_id,omitempty"`
	CommandLine string  `json:"command_line,omitempty"`
	ParserName  string  `json:"parser_name"`
	RawSnippet  string  `json:"raw_snippet,omitempty"`
	SnippetHash string  `json:"snippet_sha256,omitempty"`
	Timestamp   int64   `json:"timestamp"`
	Confidence  float64 `json:"confidence"`
}

type ParseError struct {
	ID         string `json:"id"`
	TaskID     string `json:"task_id,omitempty"`
	ParserName string `json:"parser_name"`
	ErrorText  string `json:"error_text"`
	RawSnippet string `json:"raw_snippet,omitempty"`
	Timestamp  int64  `json:"timestamp"`
}

type Delta struct {
	Cursor   int64        `json:"cursor"`
	Nodes    []Node       `json:"nodes"`
	Edges    []Edge       `json:"edges"`
	Evidence []Evidence   `json:"evidence"`
	Errors   []ParseError `json:"errors,omitempty"`
}

type State struct {
	Cursor int64  `json:"cursor"`
	Nodes  []Node `json:"nodes"`
	Edges  []Edge `json:"edges"`
}
