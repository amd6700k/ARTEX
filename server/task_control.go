package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

const maxBatchControlIDs = 100

type taskControlResult struct {
	ID     string `json:"id"`
	Paused bool   `json:"paused"`
	Queued bool   `json:"queued"`
	Status string `json:"status"`
}

type intentControlResult struct {
	ID      int64             `json:"id"`
	State   string            `json:"state"`
	Deleted *db.IntentCleanup `json:"deleted,omitempty"`
}

// parsedTaskID carries one requested batch id together with whether it parsed.
// Invalid ids are kept rather than dropped so the response can name them.
type parsedTaskID struct {
	id    string
	valid bool
}

// normalizeBatchTaskIDs trims, canonicalizes and de-duplicates the ids of one
// batch request while preserving the caller's order. Shared by every batch
// endpoint so they agree on what counts as a duplicate.
func normalizeBatchTaskIDs(raw []string) []parsedTaskID {
	seen := map[string]bool{}
	seenInvalid := map[string]bool{}
	taskIDs := make([]parsedTaskID, 0, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		id, valid := canonicalTaskID(trimmed)
		if !valid {
			if seenInvalid[trimmed] {
				continue
			}
			seenInvalid[trimmed] = true
			taskIDs = append(taskIDs, parsedTaskID{id: trimmed})
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		taskIDs = append(taskIDs, parsedTaskID{id: id, valid: true})
	}
	return taskIDs
}

type batchControlItem struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Status string `json:"status,omitempty"`
	Queued bool   `json:"queued,omitempty"`
	Error  string `json:"error,omitempty"`
}

func (s *Server) resumeAdmissionMode(t *Task) string {
	if t == nil {
		return "resume"
	}
	lifecycle := t.lifecycleSnapshot()
	if lifecycle.QueueMode == "bootstrap" {
		return "bootstrap"
	}
	if lifecycle.FirstRunAt == 0 {
		goals, err := t.Store.ListByKind(db.KindGoal, 1)
		if err == nil && len(goals) == 0 {
			return "bootstrap"
		}
	}
	return "resume"
}

// applyTaskControl is shared by the single and batch endpoints. Task resume is
// deliberately limited to paused tasks; reruns and finding follow-ups use
// admitTask directly when they need to revive a terminal task.
func (s *Server) applyTaskControl(t *Task, action string) (taskControlResult, error) {
	return s.applyTaskControlWithCause(t, action, agent.AbortPausedByUser)
}

func (s *Server) applyTaskControlWithCause(t *Task, action string, pauseCause error) (taskControlResult, error) {
	if t == nil {
		return taskControlResult{}, fmt.Errorf("task not found")
	}
	out := taskControlResult{ID: t.ID}
	switch action {
	case "pause":
		s.concMu.Lock()
		defer s.concMu.Unlock()
		current, exists := s.m.Task(t.ID)
		if !exists || current != t || s.engine.IsDeleting(t.ID) {
			return out, fmt.Errorf("任务正在删除，无法控制")
		}
		if !s.engine.beginTaskOperation(t.ID) {
			return out, fmt.Errorf("任务正在删除，无法控制")
		}
		defer s.engine.decInflight(t.ID)
		lifecycle := t.lifecycleSnapshot()
		if isTerminalStatus(lifecycle.Status) {
			return out, fmt.Errorf("终态任务不能执行暂停")
		}
		if lifecycle.Paused {
			return out, fmt.Errorf("任务已经暂停")
		}
		wasQueued := lifecycle.Queued
		wasEnginePaused := s.engine.IsPaused(t.ID)
		if pauseCause == nil {
			pauseCause = agent.AbortPausedByUser
		}
		s.engine.Pause(t.ID, pauseCause)
		if err := s.m.ApplyTaskPause(t.ID); err != nil {
			if !wasEnginePaused && !wasQueued {
				s.engine.Resume(t)
			}
			return out, err
		}
		// Main Agent is independently cancellable. Only cancel its current turn
		// after the persistent pause commits, so a failed control request is fully
		// compensated and does not lose an otherwise valid conversation turn.
		s.cancelTaskChat(t.ID, agent.AbortChatPausedWithTask)
		out.Paused, out.Status = true, "paused"
		go s.reconcileConcurrency()
	case "resume":
		queued, err := s.admitPausedTask(t)
		if err != nil {
			return out, err
		}
		out.Queued = queued
		out.Status = map[bool]string{true: "queued", false: "running"}[queued]
	default:
		return out, fmt.Errorf("action must be pause|resume")
	}
	log.Printf("[task] #%s %s", t.ID, map[string]string{"pause": "已暂停", "resume": "已继续"}[action])
	return out, nil
}

// applyTaskStop is shared by the single and batch stop endpoints. Unlike pause,
// stop is final: the terminal state commits first (the CAS is the authoritative
// idempotence guard), then the engine pause gate blocks new claims while the
// named stop cause cancels in-flight runs (runIntent classifies them as stopped),
// and the main-agent turn is aborted last. A committed stop never rolls back —
// failures surface as 409 before the commit.
func (s *Server) applyTaskStop(t *Task) (taskControlResult, error) {
	out := taskControlResult{ID: t.ID}
	if t == nil {
		return out, fmt.Errorf("task not found")
	}
	s.concMu.Lock()
	defer s.concMu.Unlock()
	// Re-resolve the handle under the lock so a request that captured the pointer
	// before deletion cannot stop a stale task past StopTask's teardown.
	current, exists := s.m.Task(t.ID)
	if !exists || current != t || s.engine.IsDeleting(t.ID) {
		return out, fmt.Errorf("任务正在删除，无法停止")
	}
	if !s.engine.beginTaskOperation(t.ID) {
		return out, fmt.Errorf("任务正在删除，无法停止")
	}
	defer s.engine.decInflight(t.ID)
	if isTerminalStatus(t.lifecycleSnapshot().Status) {
		return out, fmt.Errorf("任务已是终态，无需停止")
	}
	won, err := s.m.ApplyTaskStop(t.ID)
	if err != nil {
		return out, err
	}
	if !won {
		return out, fmt.Errorf("任务已是终态，无需停止")
	}
	// 暂停门:阻断 execContextFor 发新 ctx / worker 领取;在跑 run 的取消由 Pause 内的
	// cancelExec 携带 AbortStoppedByUser 完成,runIntent 按该 cause 归类为 stopped。
	s.engine.Pause(t.ID, agent.AbortStoppedByUser)
	s.cancelTaskChat(t.ID, agent.AbortChatStoppedWithTask)
	go s.stopTaskFrontier(t)
	out.Status = "stopped"
	log.Printf("[task] #%s 已停止", t.ID)
	go s.reconcileConcurrency()
	return out, nil
}

// stopTaskFrontier waits for in-flight runs (including ones still inside the
// runIntent entry race that would return their claim to the frontier) to drain,
// then settles the residual open/paused intents to stopped — a stopped task keeps
// no recoverable frontier.
func (s *Server) stopTaskFrontier(t *Task) {
	deadline := time.Now().Add(10 * time.Second)
	for s.engine.inflightCount(t.ID) > 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if n, err := t.Store.StopOpenIntents(); err != nil {
		log.Printf("[task] #%s 停止后清理意图前沿失败: %v", t.ID, err)
	} else if n > 0 {
		log.Printf("[task] #%s 停止后清理 %d 条前沿意图为 stopped", t.ID, n)
	}
	t.Notify()
}

// stopTask permanently terminates a task: planner/workers and the main-agent turn
// are cancelled, queued admission is dropped, and the task enters the stopped
// terminal state. History (sessions, findings, activity) stays browsable.
func (s *Server) stopTask(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	result, err := s.applyTaskStop(t)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, result)
}

// intentSummaryOf 取意图 payload 里的 summary,供删除通知在意图节点消失(真删除)前留档。
func intentSummaryOf(n *db.Node) string {
	if n == nil {
		return ""
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok {
			return s
		}
	}
	return ""
}

func (s *Server) applyIntentControl(ctx context.Context, t *Task, iid int64, action, reason, mode string) (intentControlResult, error) {
	out := intentControlResult{ID: iid}
	node, err := t.Store.GetNode(iid)
	if err != nil {
		return out, err
	}
	if node == nil {
		if inherited, sourceErr := t.Store.GetNodeWithSources(iid); sourceErr == nil && inherited != nil && inherited.Inherited {
			return out, fmt.Errorf("继承意图为只读，不能控制")
		}
		return out, fmt.Errorf("intent not found")
	}
	if node.Kind != db.KindIntent {
		return out, fmt.Errorf("node is not an intent")
	}
	switch action {
	case "pause":
		if node.State != "running" {
			return out, fmt.Errorf("仅运行中的意图可以暂停")
		}
		if err := s.engine.ControlWork(ctx, iid, "pause"); err != nil {
			return out, err
		}
		out.State = "paused"
	case "resume":
		if node.State != "paused" {
			return out, fmt.Errorf("仅已暂停的意图可以恢复")
		}
		changed, err := t.Store.CompareAndSetIntentState(iid, "paused", "open")
		if err != nil {
			return out, err
		}
		if !changed {
			return out, fmt.Errorf("%w: 意图不再是 paused 状态", db.ErrIntentStateConflict)
		}
		t.Notify()
		out.State = "open"
	case "cancel":
		// 删除支持两种模式:
		//   soft(默认,假删除):意图停到 state='deleted'、删除原因记入 delete_reason 字段,
		//     保留意图节点与全部产出/血缘,不再在图上另挂 fact。
		//   hard(真删除):物理删除该意图及"仅由它支撑"的独占子孙节点(级联到叶子),避免留下
		//     孤立数据;共享节点、goal、任务根事实保留。
		// 两种模式都用 cancelled 触发告知 planner(意图内容 + 删除原因),让它据此重规划。
		if node.State != "running" && node.State != "paused" && node.State != "open" {
			return out, fmt.Errorf("仅待领/运行中/已暂停的意图可以删除")
		}
		reason = strings.TrimSpace(reason)
		if reason == "" {
			return out, fmt.Errorf("请填写删除原因")
		}
		if node.State == "running" {
			if err := s.engine.ControlWork(ctx, iid, "cancel"); err != nil {
				return out, err
			}
		}
		summary := intentSummaryOf(node)
		if mode == "hard" {
			cleanup, err := t.Store.CancelIntent(iid)
			if err != nil {
				return out, err
			}
			s.cancelWorkerSide(t.ID, t.ExpID, iid)
			t.NotifyCancelled(iid, summary, reason)
			out.Deleted = &cleanup
			out.State = "" // 节点已删除,前端据 Deleted 从列表移除
		} else {
			if _, err := t.Store.SoftDeleteIntent(iid, reason); err != nil {
				return out, err
			}
			s.cancelWorkerSide(t.ID, t.ExpID, iid)
			t.NotifyCancelled(iid, summary, reason)
			out.State = db.StateIntentDeleted
		}
	default:
		return out, fmt.Errorf("action must be pause|resume|cancel")
	}
	return out, nil
}

func (s *Server) controlTasksBatch(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	var req struct {
		TaskIDs []string `json:"task_ids"`
		Action  string   `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if req.Action != "pause" && req.Action != "resume" && req.Action != "stop" {
		writeErr(w, 400, "action must be pause|resume|stop")
		return
	}
	taskIDs := normalizeBatchTaskIDs(req.TaskIDs)
	if len(taskIDs) == 0 || len(taskIDs) > maxBatchControlIDs {
		writeErr(w, 400, fmt.Sprintf("task_ids 数量必须为 1-%d", maxBatchControlIDs))
		return
	}
	items := make([]batchControlItem, 0, len(taskIDs))
	for _, parsed := range taskIDs {
		item := batchControlItem{ID: parsed.id}
		if !parsed.valid {
			item.Error = "bad task id"
			items = append(items, item)
			continue
		}
		t, ok := s.m.Task(parsed.id)
		if !ok {
			item.Error = "task not found"
			items = append(items, item)
			continue
		}
		var result taskControlResult
		var err error
		if req.Action == "stop" {
			result, err = s.applyTaskStop(t)
		} else {
			result, err = s.applyTaskControl(t, req.Action)
		}
		if err != nil {
			item.Error = err.Error()
		} else {
			item.OK, item.Status, item.Queued = true, result.Status, result.Queued
		}
		items = append(items, item)
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
