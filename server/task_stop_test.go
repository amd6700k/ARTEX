package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestStopCancelsWithNamedCause(t *testing.T) {
	e := NewEngine(nil)
	execCtx := e.execContextFor(context.Background(), "t1")
	workCtx, workCancel := context.WithCancelCause(execCtx)
	defer workCancel(nil)
	e.Pause("t1", agent.AbortStoppedByUser)
	if code, _, _, ok := agent.AbortReason(workCtx); !ok || code != "stopped_by_user" {
		t.Fatalf("code=%q ok=%v, want stopped_by_user", code, ok)
	}
}

func TestStopCauseDoesNotReopenIntent(t *testing.T) {
	if taskExecutionPaused(agent.AbortStoppedByUser) {
		t.Fatal("stop cancellation must not return a running intent to the frontier — a stopped task keeps none")
	}
	if !isTaskStoppedCause(agent.AbortStoppedByUser) {
		t.Fatal("stopped_by_user was not recognized as a task stop cause")
	}
	if isTaskStoppedCause(agent.AbortPausedByUser) || isTaskStoppedCause(agent.AbortGoalMet) ||
		isTaskStoppedCause(nil) || isTaskStoppedCause(context.Canceled) {
		t.Fatal("non-stop causes were misclassified as a task stop")
	}
}

func TestStopTaskRoute(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	task, err := m.CreateTask("stoppable", "terminate me", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	s := newAdmissionTestServer(m, nil)

	request := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/tasks/"+id+"/stop", nil)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		s.stopTask(rec, req)
		return rec
	}

	if rec := request("missing"); rec.Code != http.StatusNotFound {
		t.Fatalf("missing task status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec := request(task.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("stop status=%d body=%s", rec.Code, rec.Body.String())
	}
	state := task.lifecycleSnapshot()
	if state.Status != "stopped" || state.Paused || state.Queued {
		t.Fatalf("stopped task state=%+v", state)
	}
	if !s.engine.IsPaused(task.ID) {
		t.Fatal("stop did not leave the engine pause gate up for the stopped task")
	}
	if ctx := s.engine.execContextFor(context.Background(), task.ID); ctx.Err() == nil {
		t.Fatal("stopped task received a live execution context")
	}

	// Repeated stop is idempotent: the CAS refuses a second terminal write.
	if rec := request(task.ID); rec.Code != http.StatusConflict {
		t.Fatalf("repeat stop status=%d body=%s, want 409", rec.Code, rec.Body.String())
	}
	stored, err := m.pg.GetTask(mustTaskID(t, task.ID))
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil || stored.Status != "stopped" || stored.CompletedAt == nil {
		t.Fatalf("stored task=%+v, want stopped with completed_at", stored)
	}
}

func TestStoppedTaskCannotBeRevived(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	task, err := m.CreateTask("stopped revival", "must stay stopped", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	s := newAdmissionTestServer(m, nil)

	if _, err := s.applyTaskStop(task); err != nil {
		t.Fatal(err)
	}
	if _, err := s.admitTask(task, "resume"); err == nil {
		t.Fatal("a stopped task was revived through admitTask")
	}
	state := task.lifecycleSnapshot()
	if state.Status != "stopped" || state.Queued {
		t.Fatalf("stopped task state changed by admission attempt: %+v", state)
	}
}

func TestApplyTaskStopClearsQueue(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	task, err := m.CreateTask("queued stop", "drop FIFO state", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	if err := m.EnqueueTask(task.ID, "bootstrap"); err != nil {
		t.Fatal(err)
	}
	s := newAdmissionTestServer(m, nil)

	if _, err := s.applyTaskStop(task); err != nil {
		t.Fatal(err)
	}
	stored, err := m.pg.GetTask(mustTaskID(t, task.ID))
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil || stored.Queued || stored.QueueMode != "" || stored.Paused || stored.Status != "stopped" {
		t.Fatalf("stored queued task after stop=%+v", stored)
	}
}

func TestStopBeatsConcurrentTerminalWrites(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	task, err := m.CreateTask("terminal race", "first writer wins", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	s := newAdmissionTestServer(m, nil)

	if _, err := s.applyTaskStop(task); err != nil {
		t.Fatal(err)
	}
	// Late settle/met writers must lose the CAS and keep the user's stop verdict.
	if won, err := m.SetTaskStatusGuarded(task.ID, "timeout"); err != nil || won {
		t.Fatalf("timeout overwrote stopped: won=%v err=%v", won, err)
	}
	if won, err := m.SetTaskStatusGuarded(task.ID, "done"); err != nil || won {
		t.Fatalf("done overwrote stopped: won=%v err=%v", won, err)
	}
	stored, err := m.pg.GetTask(mustTaskID(t, task.ID))
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil || stored.Status != "stopped" {
		t.Fatalf("stored task=%+v, want stopped", stored)
	}
}

func TestStopSettlesFrontierIntents(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer m.Close()
	task, err := m.CreateTask("frontier stop", "no recoverable frontier", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	openID, err := task.Store.AddIntent(map[string]any{"summary": "open intent"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	pausedID, err := task.Store.AddIntent(map[string]any{"summary": "paused intent"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.SetIntentState(pausedID, "paused"); err != nil {
		t.Fatal(err)
	}
	deletedID, err := task.Store.AddIntent(map[string]any{"summary": "deleted intent"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := task.Store.SoftDeleteIntent(deletedID, "cleanup"); err != nil {
		t.Fatal(err)
	}
	s := newAdmissionTestServer(m, nil)

	if _, err := s.applyTaskStop(task); err != nil {
		t.Fatal(err)
	}
	// stopTaskFrontier runs in the background; poll until the frontier settles
	// (no in-flight runs here, so the drain wait is just its scheduling latency).
	settled := false
	for i := 0; i < 100 && !settled; i++ {
		time.Sleep(20 * time.Millisecond)
		node, err := task.Store.GetNode(openID)
		if err == nil && node != nil && node.State == "stopped" {
			settled = true
		}
	}
	if !settled {
		t.Fatal("stopTaskFrontier did not settle the frontier in time")
	}
	for _, tc := range []struct {
		id    int64
		state string
	}{{openID, "stopped"}, {pausedID, "stopped"}} {
		node, err := task.Store.GetNode(tc.id)
		if err != nil || node == nil {
			t.Fatalf("intent %d: node=%+v err=%v", tc.id, node, err)
		}
		if node.State != tc.state {
			t.Fatalf("intent %d state=%q, want %q", tc.id, node.State, tc.state)
		}
	}
	node, err := task.Store.GetNode(deletedID)
	if err != nil || node == nil || node.State != db.StateIntentDeleted {
		t.Fatalf("soft-deleted intent was touched by stop: node=%+v err=%v", node, err)
	}
}
