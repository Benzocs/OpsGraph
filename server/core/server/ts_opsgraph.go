package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"AdaptixServer/core/opsgraph"
	"AdaptixServer/core/utils/logs"
	adaptix "github.com/Adaptix-Framework/axc2"
)

var errOpsGraphNotInitialized = errors.New("opsgraph service is not initialized")

func (ts *Teamserver) TsOpsGraphState(ctx context.Context) (opsgraph.State, error) {
	if ts == nil || ts.OpsGraph == nil {
		return opsgraph.State{}, errOpsGraphNotInitialized
	}
	return ts.OpsGraph.State(ctx)
}

func (ts *Teamserver) TsOpsGraphDeltaSince(ctx context.Context, cursor int64) (opsgraph.Delta, error) {
	if ts == nil || ts.OpsGraph == nil {
		return opsgraph.Delta{}, errOpsGraphNotInitialized
	}
	return ts.OpsGraph.DeltaSince(ctx, cursor)
}

func (ts *Teamserver) TsOpsGraphSearch(ctx context.Context, query string, limit int) ([]opsgraph.Node, error) {
	if ts == nil || ts.OpsGraph == nil {
		return nil, errOpsGraphNotInitialized
	}
	return ts.OpsGraph.Search(ctx, query, limit)
}

func (ts *Teamserver) TsOpsGraphNode(ctx context.Context, id string) (opsgraph.Node, []opsgraph.Evidence, error) {
	if ts == nil || ts.OpsGraph == nil {
		return opsgraph.Node{}, nil, errOpsGraphNotInitialized
	}
	return ts.OpsGraph.Node(ctx, id)
}

func (ts *Teamserver) TsOpsGraphEdgeEvidence(ctx context.Context, id string) ([]opsgraph.Evidence, error) {
	if ts == nil || ts.OpsGraph == nil {
		return nil, errOpsGraphNotInitialized
	}
	return ts.OpsGraph.EdgeEvidence(ctx, id)
}

func (ts *Teamserver) TsOpsGraphIngestAgentData(agentData adaptix.AgentData, active bool) {
	if ts == nil || ts.OpsGraph == nil {
		return
	}

	lastTick := opsGraphInt64(agentData.LastTick)
	createTime := opsGraphInt64(agentData.CreateTime)

	timestamp := lastTick
	if timestamp == 0 {
		timestamp = createTime
	}
	if timestamp == 0 {
		timestamp = time.Now().Unix()
	}

	snapshot := opsgraph.AgentSnapshot{
		ID:           agentData.Id,
		Domain:       agentData.Domain,
		Computer:     agentData.Computer,
		Username:     agentData.Username,
		Impersonated: agentData.Impersonated,
		Elevated:     opsGraphBool(agentData.Elevated),
		Active:       active,
		LastTick:     lastTick,
		Timestamp:    timestamp,
	}

	if err := ts.OpsGraph.IngestAgentSnapshot(context.Background(), snapshot); err != nil {
		logs.Warn("", "OpsGraph agent ingest failed for %s: %s", agentData.Id, err.Error())
	}
}

func opsGraphBool(value interface{}) bool {
	switch v := value.(type) {
	case bool:
		return v
	case int:
		return v != 0
	case int8:
		return v != 0
	case int16:
		return v != 0
	case int32:
		return v != 0
	case int64:
		return v != 0
	case uint:
		return v != 0
	case uint8:
		return v != 0
	case uint16:
		return v != 0
	case uint32:
		return v != 0
	case uint64:
		return v != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "yes", "y", "1", "elevated", "admin":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func opsGraphInt64(value interface{}) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int8:
		return int64(v)
	case int16:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	case uint:
		return int64(v)
	case uint8:
		return int64(v)
	case uint16:
		return int64(v)
	case uint32:
		return int64(v)
	case uint64:
		if v > uint64(^uint(0)>>1) {
			return 0
		}
		return int64(v)
	case float32:
		return int64(v)
	case float64:
		return int64(v)
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0
		}
		return parsed
	default:
		_ = fmt.Sprintf("%v", value)
		return 0
	}
}

func (ts *Teamserver) TsOpsGraphIngestTaskData(taskData adaptix.TaskData) {
	if ts == nil || ts.OpsGraph == nil {
		return
	}

	if !taskData.Completed {
		return
	}

	if taskData.TaskId == "" {
		return
	}

	output := taskData.ClearText
	if output == "" {
		output = taskData.Message
	}

	if output == "" {
		return
	}

	timestamp := taskData.FinishDate
	if timestamp == 0 {
		timestamp = taskData.StartDate
	}

	snapshot := opsgraph.TaskSnapshot{
		ID:          taskData.TaskId,
		AgentID:     taskData.AgentId,
		CommandLine: taskData.CommandLine,
		Output:      output,
		User:        taskData.User,
		Computer:    taskData.Computer,
		Timestamp:   timestamp,
	}

	if err := ts.OpsGraph.ProcessTask(context.Background(), snapshot); err != nil {
		logs.Warn("", "OpsGraph task ingest failed for task %s: %s", taskData.TaskId, err.Error())
	}
}

func (ts *Teamserver) TsOpsGraphClear(ctx context.Context) error {
	if ts == nil || ts.OpsGraph == nil {
		return errOpsGraphNotInitialized
	}
	return ts.OpsGraph.Clear(ctx)
}

func (ts *Teamserver) TsOpsGraphRebuildFromTasks(ctx context.Context, maxTasks int) (int, error) {
	if ts == nil || ts.OpsGraph == nil {
		return 0, errOpsGraphNotInitialized
	}

	if maxTasks <= 0 {
		maxTasks = 5000
	}

	processed := 0
	offset := 0
	pageSize := 250

	for processed < maxTasks {
		remaining := maxTasks - processed
		limit := pageSize
		if remaining < limit {
			limit = remaining
		}

		tasks, err := ts.DBMS.DbTasksCompletedAll(limit, offset)
		if err != nil {
			return processed, err
		}

		if len(tasks) == 0 {
			break
		}

		for _, task := range tasks {
			select {
			case <-ctx.Done():
				return processed, ctx.Err()
			default:
			}

			ts.TsOpsGraphIngestTaskData(task)
			processed++
		}

		offset += len(tasks)
	}

	return processed, nil
}
