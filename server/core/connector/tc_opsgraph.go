package connector

// This is a placement skeleton. Wire these handlers using the same router/auth style
// used by existing tc_agents.go, tc_tasks.go, tc_creds.go, and tc_targets.go.

/*
func (tc *TeamserverConnector) TcOpsGraphState(w http.ResponseWriter, r *http.Request) {
    state, err := tc.Teamserver.OpsGraph.State(r.Context())
    if err != nil { writeError(w, err); return }
    writeJSON(w, state)
}

func (tc *TeamserverConnector) TcOpsGraphDelta(w http.ResponseWriter, r *http.Request) {
    cursor := parseInt64(r.URL.Query().Get("since"))
    delta, err := tc.Teamserver.OpsGraph.DeltaSince(r.Context(), cursor)
    if err != nil { writeError(w, err); return }
    writeJSON(w, delta)
}

func (tc *TeamserverConnector) TcOpsGraphSearch(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("q")
    nodes, err := tc.Teamserver.OpsGraph.Search(r.Context(), q, 50)
    if err != nil { writeError(w, err); return }
    writeJSON(w, nodes)
}

func (tc *TeamserverConnector) TcOpsGraphPath(w http.ResponseWriter, r *http.Request) {
    var req opsgraph.PathRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeError(w, err); return }
    result, err := tc.Teamserver.OpsGraph.Path(r.Context(), req)
    if err != nil { writeError(w, err); return }
    writeJSON(w, result)
}
*/
