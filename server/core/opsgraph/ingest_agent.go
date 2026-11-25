package opsgraph

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// AgentSnapshot is intentionally framework-neutral. In the real PR, map this from Adaptix AgentData.
type AgentSnapshot struct {
	ID           string
	Domain       string
	Computer     string
	Username     string
	Elevated     bool
	Impersonated string
	Active       bool
	LastTick     int64
	Timestamp    int64
}

const agentMetadataMinIntervalSeconds int64 = 60

type agentMetadataCursorState struct {
	Signature     string `json:"signature"`
	LastTimestamp int64  `json:"last_timestamp"`
}

func IngestAgentSnapshot(ctx context.Context, store Store, a AgentSnapshot) error {
	ts := a.Timestamp
	if ts == 0 {
		ts = a.LastTick
	}
	if ts == 0 {
		ts = time.Now().Unix()
	}

	metadataSignature := agentMetadataSignature(a)
	if shouldSkipAgentMetadataSnapshot(ctx, store, a.ID, metadataSignature, ts) {
		return nil
	}

	ev := Evidence{
		ID:         EvidenceID("agent", a.ID, "agent_metadata", a.ID+a.Domain+a.Computer+a.Username),
		SourceKind: "agent", SourceID: a.ID, AgentID: a.ID, ParserName: "agent_metadata",
		RawSnippet: "agent metadata snapshot", SnippetHash: ShortHash(a.ID + a.Domain + a.Computer + a.Username),
		Timestamp: ts, Confidence: 1.0,
	}

	agentNode := Node{
		ID:             AgentID(a.ID),
		Type:           NodeAgent,
		Label:          a.ID,
		NormalizedName: a.ID,
		Properties: map[string]any{
			"active":       a.Active,
			"last_tick":    a.LastTick,
			"elevated":     a.Elevated,
			"impersonated": a.Impersonated,
			"domain":       a.Domain,
			"computer":     a.Computer,
			"username":     a.Username,
		},
		FirstSeen:   ts,
		LastSeen:    ts,
		Confidence:  1.0,
		EvidenceIDs: []string{ev.ID},
	}
	if err := store.UpsertNode(ctx, agentNode, []Evidence{ev}); err != nil {
		return err
	}

	if a.Computer != "" {
		hostState := HostFootholdActive
		if a.Elevated {
			hostState = HostElevatedFoothold
		}
		if a.Impersonated != "" {
			hostState = HostImpersonatedContext
		}

		computerID := ComputerID(a.Domain, a.Computer)
		cNode := Node{
			ID:             computerID,
			Type:           NodeComputer,
			Label:          a.Computer,
			NormalizedName: NormalizeComputer(a.Computer),
			Properties: map[string]any{
				"domain":   a.Domain,
				"computer": a.Computer,
			},
			FirstSeen:   ts,
			LastSeen:    ts,
			Confidence:  1.0,
			HostState:   hostState,
			EvidenceIDs: []string{ev.ID},
		}
		if err := store.UpsertNode(ctx, cNode, []Evidence{ev}); err != nil {
			return err
		}

		e := Edge{
			ID:          EdgeID(EdgeRunningOn, agentNode.ID, computerID),
			SourceID:    agentNode.ID,
			TargetID:    computerID,
			Type:        EdgeRunningOn,
			Properties:  map[string]any{},
			FirstSeen:   ts,
			LastSeen:    ts,
			Confidence:  1.0,
			EvidenceIDs: []string{ev.ID},
		}
		if err := store.UpsertEdge(ctx, e, []Evidence{ev}); err != nil {
			return err
		}

		if a.Domain != "" {
			domainID := DomainID(a.Domain)
			domainEdge := Edge{
				ID:       EdgeID(EdgeInDomain, computerID, domainID),
				SourceID: computerID,
				TargetID: domainID,
				Type:     EdgeInDomain,
				Properties: map[string]any{
					"source": "agent_metadata",
				},
				FirstSeen:   ts,
				LastSeen:    ts,
				Confidence:  1.0,
				EvidenceIDs: []string{ev.ID},
			}
			if err := store.UpsertEdge(ctx, domainEdge, []Evidence{ev}); err != nil {
				return err
			}
		}
	}

	if a.Username != "" {
		userID := UserID(a.Domain, a.Username)
		uNode := Node{
			ID:             userID,
			Type:           NodeUser,
			Label:          a.Username,
			NormalizedName: a.Domain + `\` + a.Username,
			Properties: map[string]any{
				"domain": a.Domain,
				"sam":    a.Username,
			},
			FirstSeen:   ts,
			LastSeen:    ts,
			Confidence:  1.0,
			EvidenceIDs: []string{ev.ID},
		}
		if err := store.UpsertNode(ctx, uNode, []Evidence{ev}); err != nil {
			return err
		}

		e := Edge{
			ID:          EdgeID(EdgeRunningAs, agentNode.ID, userID),
			SourceID:    agentNode.ID,
			TargetID:    userID,
			Type:        EdgeRunningAs,
			Properties:  map[string]any{},
			FirstSeen:   ts,
			LastSeen:    ts,
			Confidence:  1.0,
			EvidenceIDs: []string{ev.ID},
		}
		if err := store.UpsertEdge(ctx, e, []Evidence{ev}); err != nil {
			return err
		}

		if a.Domain != "" {
			domainID := DomainID(a.Domain)
			domainEdge := Edge{
				ID:       EdgeID(EdgeInDomain, userID, domainID),
				SourceID: userID,
				TargetID: domainID,
				Type:     EdgeInDomain,
				Properties: map[string]any{
					"source": "agent_metadata",
				},
				FirstSeen:   ts,
				LastSeen:    ts,
				Confidence:  1.0,
				EvidenceIDs: []string{ev.ID},
			}
			if err := store.UpsertEdge(ctx, domainEdge, []Evidence{ev}); err != nil {
				return err
			}
		}
	}

	if a.Domain != "" {
		dNode := Node{
			ID:             DomainID(a.Domain),
			Type:           NodeDomain,
			Label:          a.Domain,
			NormalizedName: NormalizeDomain(a.Domain),
			Properties: map[string]any{
				"domain": NormalizeDomain(a.Domain),
			},
			FirstSeen:   ts,
			LastSeen:    ts,
			Confidence:  1.0,
			EvidenceIDs: []string{ev.ID},
		}
		if err := store.UpsertNode(ctx, dNode, []Evidence{ev}); err != nil {
			return err
		}
	}

	rememberAgentTaskContext(ctx, store, a)
	rememberAgentMetadataSnapshot(ctx, store, a.ID, metadataSignature, ts)
	return nil
}

func agentMetadataSignature(a AgentSnapshot) string {
	parts := []string{
		strings.TrimSpace(a.ID),
		NormalizeDomain(a.Domain),
		NormalizeComputer(a.Computer),
		strings.ToLower(strings.TrimSpace(a.Username)),
		strings.ToLower(strings.TrimSpace(a.Impersonated)),
		strconv.FormatBool(a.Elevated),
		strconv.FormatBool(a.Active),
	}

	return ShortHash(strings.Join(parts, "|"))
}

func shouldSkipAgentMetadataSnapshot(ctx context.Context, store Store, agentID string, signature string, ts int64) bool {
	if store == nil || agentID == "" || signature == "" || ts == 0 {
		return false
	}

	raw, err := store.GetCursor(ctx, "agent_metadata:"+agentID)
	if err != nil || raw == "" {
		return false
	}

	var state agentMetadataCursorState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return false
	}

	if state.Signature != signature {
		return false
	}

	if state.LastTimestamp <= 0 || ts < state.LastTimestamp {
		return false
	}

	return ts-state.LastTimestamp < agentMetadataMinIntervalSeconds
}

func rememberAgentMetadataSnapshot(ctx context.Context, store Store, agentID string, signature string, ts int64) {
	if store == nil || agentID == "" || signature == "" || ts == 0 {
		return
	}

	state := agentMetadataCursorState{
		Signature:     signature,
		LastTimestamp: ts,
	}

	raw, err := json.Marshal(state)
	if err != nil {
		return
	}

	_ = store.SetCursor(ctx, "agent_metadata:"+agentID, string(raw))
}
