package opsgraph

import (
	"container/list"
	"context"
	"errors"
)

type PathRequest struct {
	StartNodeIDs  []string   `json:"start_node_ids"`
	TargetNodeIDs []string   `json:"target_node_ids"`
	AllowedEdges  []EdgeType `json:"allowed_edges"`
	MaxDepth      int        `json:"max_depth"`
}

type PathResult struct {
	Nodes []Node  `json:"nodes"`
	Edges []Edge  `json:"edges"`
	Score float64 `json:"score"`
}

func DefaultAllowedPathEdges() map[EdgeType]bool {
	return map[EdgeType]bool{
		EdgeMemberOf: true, EdgeACLRight: true, EdgeContains: true, EdgeRunningAs: true, EdgeRunningOn: true,
		EdgeLoggedOnTo: true, EdgeHasSession: true, EdgeBelongsTo: true, EdgeTrusts: true,
	}
}

// ShortestObservedPath performs unweighted BFS over stored observed edges only.
// It does not infer missing relationships and does not generate actions.
func ShortestObservedPath(ctx context.Context, state State, req PathRequest) (PathResult, error) {
	if len(req.StartNodeIDs) == 0 || len(req.TargetNodeIDs) == 0 {
		return PathResult{}, errors.New("missing start or target nodes")
	}
	maxDepth := req.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 8
	}
	allowed := DefaultAllowedPathEdges()
	if len(req.AllowedEdges) > 0 {
		allowed = map[EdgeType]bool{}
		for _, e := range req.AllowedEdges {
			allowed[e] = true
		}
	}

	nodeByID := map[string]Node{}
	for _, n := range state.Nodes {
		nodeByID[n.ID] = n
	}
	adj := map[string][]Edge{}
	for _, e := range state.Edges {
		if allowed[e.Type] {
			adj[e.SourceID] = append(adj[e.SourceID], e)
		}
	}
	targets := map[string]bool{}
	for _, t := range req.TargetNodeIDs {
		targets[t] = true
	}

	type item struct {
		node      string
		pathEdges []Edge
	}
	q := list.New()
	seen := map[string]bool{}
	for _, s := range req.StartNodeIDs {
		q.PushBack(item{node: s})
		seen[s] = true
	}

	for q.Len() > 0 {
		front := q.Remove(q.Front()).(item)
		if targets[front.node] {
			nodes := make([]Node, 0, len(front.pathEdges)+1)
			if len(front.pathEdges) == 0 {
				nodes = append(nodes, nodeByID[front.node])
			} else {
				nodes = append(nodes, nodeByID[front.pathEdges[0].SourceID])
				for _, e := range front.pathEdges {
					nodes = append(nodes, nodeByID[e.TargetID])
				}
			}
			return PathResult{Nodes: nodes, Edges: front.pathEdges, Score: scorePath(front.pathEdges)}, nil
		}
		if len(front.pathEdges) >= maxDepth {
			continue
		}
		for _, edge := range adj[front.node] {
			if seen[edge.TargetID] {
				continue
			}
			seen[edge.TargetID] = true
			next := append([]Edge{}, front.pathEdges...)
			next = append(next, edge)
			q.PushBack(item{node: edge.TargetID, pathEdges: next})
		}
	}
	return PathResult{}, errors.New("no observed path found")
}

func scorePath(edges []Edge) float64 {
	if len(edges) == 0 {
		return 1.0
	}
	sum := 0.0
	for _, e := range edges {
		sum += e.Confidence
	}
	return sum / float64(len(edges))
}
