package opsgraph

import (
	"context"
	"strings"
	"sync"
	"time"
)

type TaskSnapshot struct {
	ID          string
	AgentID     string
	CommandLine string
	Output      string
	User        string
	Computer    string
	Domain      string
	Timestamp   int64
}

type CompletedTaskSource interface {
	CompletedTasksSince(ctx context.Context, cursor string) ([]TaskSnapshot, string, error)
}

type DeltaPublisher interface {
	PublishOpsGraphDelta(delta Delta)
}

type Service struct {
	store     Store
	tasks     CompletedTaskSource
	publisher DeltaPublisher
	router    *Router
	interval  time.Duration
	stop      chan struct{}
	wg        sync.WaitGroup
}

func NewService(store Store, tasks CompletedTaskSource, publisher DeltaPublisher) *Service {
	return &Service{store: store, tasks: tasks, publisher: publisher, router: NewRouter(), interval: 10 * time.Second, stop: make(chan struct{})}
}

func (s *Service) Start(ctx context.Context) error {
	if err := s.store.Init(ctx); err != nil {
		return err
	}
	s.wg.Add(1)
	go s.pollLoop(ctx)
	return nil
}

func (s *Service) Stop() {
	close(s.stop)
	s.wg.Wait()
}

func (s *Service) pollLoop(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case <-ticker.C:
			_ = s.ProcessTaskDelta(ctx)
		}
	}
}

func (s *Service) ProcessTaskDelta(ctx context.Context) error {
	if s.tasks == nil {
		return nil
	}
	cursor, _ := s.store.GetCursor(ctx, "tasks")
	tasks, nextCursor, err := s.tasks.CompletedTasksSince(ctx, cursor)
	if err != nil {
		return err
	}
	for _, task := range tasks {
		if err := s.ProcessTask(ctx, task); err != nil {
			return err
		}
	}
	if nextCursor != "" {
		return s.store.SetCursor(ctx, "tasks", nextCursor)
	}
	return nil
}

func (s *Service) ProcessTask(ctx context.Context, task TaskSnapshot) error {
	tctx := TaskContext{TaskID: task.ID, AgentID: task.AgentID, CommandLine: task.CommandLine, Output: task.Output, User: task.User, Computer: task.Computer, Domain: task.Domain, Timestamp: task.Timestamp, SourceKind: "task"}
	tctx = s.enrichTaskContextFromAgent(ctx, tctx)
	for _, result := range s.router.Parse(tctx) {
		for _, ev := range result.Evidence {
			_ = s.store.AppendEvidence(ctx, ev)
		}
		for _, n := range result.Nodes {
			if err := s.store.UpsertNode(ctx, n, result.Evidence); err != nil {
				return err
			}
		}
		for _, e := range result.Edges {
			if err := s.store.UpsertEdge(ctx, e, result.Evidence); err != nil {
				return err
			}
		}
		for _, pe := range result.ParseErrors {
			_ = s.store.AppendParseError(ctx, pe)
		}
	}
	return nil
}

func (s *Service) enrichTaskContextFromAgent(ctx context.Context, tctx TaskContext) TaskContext {
	if s == nil || s.store == nil || strings.TrimSpace(tctx.AgentID) == "" {
		return tctx
	}

	state, ok := loadAgentTaskContext(ctx, s.store, tctx.AgentID)
	if !ok {
		return tctx
	}

	if strings.TrimSpace(tctx.Computer) == "" && state.Computer != "" {
		tctx.Computer = state.Computer
	}

	if strings.TrimSpace(tctx.User) == "" && state.Username != "" {
		tctx.User = state.Username
	}

	if strings.TrimSpace(tctx.Domain) == "" &&
		state.Domain != "" &&
		!domainLooksLikeLocalComputer(state.Domain, state.Computer) {
		tctx.Domain = state.Domain
	}

	return tctx
}

func (s *Service) State(ctx context.Context) (State, error) {
	return s.store.State(ctx)
}

func (s *Service) DeltaSince(ctx context.Context, cursor int64) (Delta, error) {
	return s.store.DeltaSince(ctx, cursor)
}

func (s *Service) Search(ctx context.Context, query string, limit int) ([]Node, error) {
	return s.store.Search(ctx, query, limit)
}

func (s *Service) Node(ctx context.Context, id string) (Node, []Evidence, error) {
	return s.store.Node(ctx, id)
}

func (s *Service) EdgeEvidence(ctx context.Context, id string) ([]Evidence, error) {
	return s.store.EdgeEvidence(ctx, id)
}

func (s *Service) IngestAgentSnapshot(ctx context.Context, snapshot AgentSnapshot) error {
	return IngestAgentSnapshot(ctx, s.store, snapshot)
}

func (s *Service) Clear(ctx context.Context) error {
	return s.store.Clear(ctx)
}
