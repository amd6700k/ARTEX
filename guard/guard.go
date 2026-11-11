// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [内置] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	reg         *hook.Registry
	interceptor *intercept.Interceptor // optional; nil disables user-configured rules

	// 任务白名单闸门（applyAssetGate）：taskID>0 且 assets/rulesFn 至少其一非 nil
	// 时启用。assets 走真实规则装载；rulesFn 是测试缝（注入静态规则，无需 PG）。
	taskID  int64
	assets  *db.AssetStore
	rulesFn func() (block, allow []db.AssetInterceptRule, err error)
}

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

// NewForTask creates a Guard with both the intercept rules and the per-task
// asset whitelist gate (applyAssetGate) enabled.
func NewForTask(ic *intercept.Interceptor, taskID int64, as *db.AssetStore) *Guard {
	g := newGuard(ic)
	g.taskID = taskID
	g.assets = as
	return g
}

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	switch ev.ToolName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Text
	}
	g.record(ev.ToolName, "allow", "", cmd)
	if res := g.applyAssetGate(ctx, ev, cmd); res.Decision == "block" {
		return res
	}
	return g.applyIntercept(ctx, ev)
}

// gateTools 是任务白名单闸门作用的工具集合。只拦真正外发流量的工具，不做
// 全工具文本扫 URL——record_fact/report_finding 之类文本工具的 evidence 里
// 出现域外 URL 不应被误拦。
var gateTools = map[string]bool{
	"Bash":       true,
	"WebFetch":   true,
	"shell_open": true,
	"shell_send": true,
}

// applyAssetGate 是任务级目标白名单闸门：从工具入参提取测试目标，逐个跑
// 任务允许/拦截规则（EvaluateAssetGateOn）。定位是防误伤的策略闸门：
//   - taskID<=0（顶层 chat 等）或 assets/rulesFn 均未设 → 放行（闸门关闭）；
//   - 规则读取失败 → 放行（fail-open，与 insert_assets 资产闸门一致）；
//   - 无启用规则 → 放行且不提取目标（零开销短路）；
//   - 提取不到目标 → 放行（记 debug 日志，仅在白名单启用时走到这里）。
func (g *Guard) applyAssetGate(ctx context.Context, ev hook.Event, cmd string) hook.Result {
	if g.taskID <= 0 || (!gateTools[ev.ToolName]) {
		return hook.Result{}
	}
	if g.rulesFn == nil && g.assets == nil {
		return hook.Result{}
	}
	var block, allow []db.AssetInterceptRule
	var err error
	if g.rulesFn != nil {
		block, allow, err = g.rulesFn()
	} else {
		block, allow, err = g.assets.LoadTaskGateRules(g.taskID)
	}
	if err != nil {
		slog.Debug("guard: 任务白名单规则读取失败，放行", "taskID", g.taskID, "err", err)
		return hook.Result{}
	}
	if len(block) == 0 && !db.HasEnabledRule(allow) {
		return hook.Result{} // 未启用白名单/拦截：不提取目标，零开销
	}
	targets := ExtractTargets(ev.ToolName, ev.Input)
	if len(targets) == 0 {
		slog.Debug("guard: 白名单启用但未提取到目标，放行", "taskID", g.taskID, "tool", ev.ToolName)
		return hook.Result{}
	}
	reason, denied := checkTargetsOnRules(block, allow, targets)
	if !denied {
		return hook.Result{}
	}
	if g.interceptor != nil {
		dec := intercept.Decision{Action: "deny", Message: reason}
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
	}
	return g.block(ev.ToolName, systemBlockMessage(reason), cmd)
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	if !g.interceptor.IsToolEnabled(ev.ToolName) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	dec, matched := g.interceptor.Match(ev.ToolName, ev.Input)
	if !matched {
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	}
	switch dec.Action {
	case "deny":
		// 观测:deny 命中不阻塞审批,直接记一条 denied（历史/任务拦截页可见）。
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an ARTEX platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("禁止执行此工具" / "用户拒绝") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【ARTEX 平台管控·非目标防御】此调用被平台拦截。" +
		"原因：" + reason + "。此操作被禁止。"
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
