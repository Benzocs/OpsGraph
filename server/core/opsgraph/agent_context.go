package opsgraph

import (
	"context"
	"encoding/json"
	"strings"
)

const agentTaskContextCursorPrefix = "agent_context:"

type agentTaskContextState struct {
	Domain   string `json:"domain"`
	Computer string `json:"computer"`
	Username string `json:"username"`
	UserID   string `json:"user_id"`
}

func agentTaskContextCursorName(agentID string) string {
	return agentTaskContextCursorPrefix + strings.TrimSpace(agentID)
}

func rememberAgentTaskContext(ctx context.Context, store Store, a AgentSnapshot) {
	if store == nil || strings.TrimSpace(a.ID) == "" {
		return
	}

	state := agentTaskContextState{
		Domain:   NormalizeDomain(a.Domain),
		Computer: NormalizeComputer(a.Computer),
		Username: NormalizeSAM(a.Username),
		UserID:   UserID(a.Domain, a.Username),
	}

	raw, err := json.Marshal(state)
	if err != nil {
		return
	}

	_ = store.SetCursor(ctx, agentTaskContextCursorName(a.ID), string(raw))
}

func loadAgentTaskContext(ctx context.Context, store Store, agentID string) (agentTaskContextState, bool) {
	if store == nil || strings.TrimSpace(agentID) == "" {
		return agentTaskContextState{}, false
	}

	raw, err := store.GetCursor(ctx, agentTaskContextCursorName(agentID))
	if err != nil || strings.TrimSpace(raw) == "" {
		return agentTaskContextState{}, false
	}

	var state agentTaskContextState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return agentTaskContextState{}, false
	}

	state.Domain = NormalizeDomain(state.Domain)
	state.Computer = NormalizeComputer(state.Computer)
	state.Username = NormalizeSAM(state.Username)

	return state, true
}

func domainLooksLikeLocalComputer(domain string, computer string) bool {
	d := NormalizeDomain(domain)
	c := NormalizeComputer(computer)

	return d != "" && c != "" && d == c
}
