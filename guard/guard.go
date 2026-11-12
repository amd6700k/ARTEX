// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [内置] rules, so users can disable or
// delete them), evaluated via applyIntercept. The per-task asset whitelist gate
// (applyAssetGate) is pure-model: calls with network signals are referred to the
// LLM whitelist review (JudgeTaskWhitelist) which judges real destinations as
// either in-scope target traffic or legitimate non-target lookups; a loose
// network-signal prefilter only decides whether to spend a model call.
package guard

import (
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
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

	// judge 是白名单模型复核入口（测试缝）：默认指向 interceptor.JudgeTaskWhitelist，
	// 测试注入 mock。nil 或返回 false = 复核不可用 → 放行（fail-open）。
	judge func(ctx context.Context, tool string, input json.RawMessage, prompt string) (intercept.Decision, bool)
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
	if ic != nil {
		g.judge = ic.JudgeTaskWhitelist
	}
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

// knownNetTools 是预筛用的已知网络工具名（纯模型架构下只判断「这条调用像要
// 联网」）。清单刻意宽松：误中只会多一次模型复核，漏过只会少一次复核（模型
// 本也看不出变量间接目标），两侧都无害。
var knownNetTools = []string{
	"curl", "wget", "nc", "ncat", "netcat", "socat", "openssl", "ping", "dig",
	"nslookup", "whois", "traceroute", "nmap", "masscan", "naabu", "rustscan",
	"unicornscan", "sqlmap", "nikto", "whatweb", "dirb", "hydra", "medusa",
	"testssl.sh", "sslscan", "ffuf", "gobuster", "dirsearch", "wfuzz",
	"feroxbuster", "httpx", "nuclei", "enum4linux", "smbclient", "telnet",
	"ssh", "ftp", "tcpdump", "mitmproxy", "hashcat", "john",
}

var (
	reSignalIPv4   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reSignalIPv6   = regexp.MustCompile(`\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:.]+`)
	reSignalDotted = regexp.MustCompile(`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
)

// hasNetworkSignal 是纯模型闸门的极简预筛：文本里连一个联网信号都没有（无
// scheme、无 IP、无点分域名形、非已知网络工具）→ 判定「不涉及网络访问」，
// 直接放行零模型调用。预筛只影响「是否送模型」，不影响裁决——误中 = 多一次
// 复核（无害），漏过 = 少一次复核（模型本也读不出变量间接目标）。
func hasNetworkSignal(text string) bool {
	if strings.Contains(text, "://") {
		return true
	}
	if reSignalIPv4.MatchString(text) || reSignalIPv6.MatchString(text) || reSignalDotted.MatchString(text) {
		return true
	}
	for _, t := range knownNetTools {
		if strings.Contains(text, t) {
			return true
		}
	}
	return false
}

// applyAssetGate 是任务级目标白名单闸门：纯模型判断（无提取器）——有启用规则
// 且调用带联网信号时，整条入参交模型裁决真实网络访问是否越界：
//   - taskID<=0（顶层 chat 等）或 assets/rulesFn 均未设 → 放行（闸门关闭）；
//   - 规则读取失败 → 放行（fail-open，与 insert_assets 资产闸门一致）；
//   - 无启用规则 → 放行（零开销短路）；
//   - 无联网信号（echo/cat 本地文件等）→ 放行零模型调用（极简预筛）；
//   - 其余 → 模型终审（gateCheck，靶标流量/非靶标联网查询两类口径）。
func (g *Guard) applyAssetGate(ctx context.Context, ev hook.Event, cmd string) hook.Result {
	if g.taskID <= 0 || (!gateTools[ev.ToolName]) {
		return hook.Result{}
	}
	if g.rulesFn == nil && g.assets == nil {
		return hook.Result{}
	}
	block, allow, err := g.loadGateRules()
	if err != nil {
		slog.Debug("guard: 任务白名单规则读取失败，放行", "taskID", g.taskID, "err", err)
		return hook.Result{}
	}
	if len(block) == 0 && !db.HasEnabledRule(allow) {
		return hook.Result{} // 未启用白名单/拦截：零开销
	}
	// 预筛看原始入参（Bash 命令 / WebFetch 的 URL JSON / shell 文本都在其中）。
	if !hasNetworkSignal(string(ev.Input)) {
		return hook.Result{}
	}
	reason, denied := g.gateCheck(ctx, ev.ToolName, ev.Input, block, allow)
	if !denied {
		return hook.Result{}
	}
	return g.block(ev.ToolName, SystemBlockMessage(reason), cmd)
}

// loadGateRules 装载任务闸门规则：assets 走真实装载（全局∪任务 block、任务 allow），
// rulesFn 是测试缝（注入静态规则，无需 PG）。
func (g *Guard) loadGateRules() (block, allow []db.AssetInterceptRule, err error) {
	if g.rulesFn != nil {
		return g.rulesFn()
	}
	return g.assets.LoadTaskGateRules(g.taskID)
}

// gateCheck 是白名单判定核心（PreToolUse 闸门与自定义工具渲染后校验共用）：
// 纯模型判断——判定权 100% 在模型，无提取、无规则匹配。模型通读完整参数找
// 出全部真实网络目的地，按「靶标流量 / 非靶标联网查询」两类口径裁决（提示词
// 见 TaskWhitelistJudgePrompt）：
//   - deny → 拦（模型 reason，[任务白名单] 前缀 → interceptSource 归因 rule）；
//   - allow → 放行并留痕（拦截历史可查）；
//   - ask → 转人工（HandleAsk 复用既有审批链路；无 interceptor/审批不通过/
//     工作已取消 → 拦）；
//   - 复核不可用（judge 未接线/开关关/超时/裁决不可解析）→ 放行（fail-open：
//     模型不可用时任务本身也无法继续，不保留兜底）。
//
// 返回原始拒绝理由（[任务白名单] 前缀，interceptSource 据此归因 rule 来源）。
func (g *Guard) gateCheck(ctx context.Context, toolName string, input json.RawMessage, block, allow []db.AssetInterceptRule) (string, bool) {
	prompt := intercept.TaskWhitelistJudgePrompt(block, allow)
	var dec intercept.Decision
	var judged bool
	if g.judge != nil {
		dec, judged = g.judge(ctx, toolName, input, prompt)
	}
	if !judged {
		slog.Warn("guard: 白名单模型复核不可用，按 fail-open 放行", "taskID", g.taskID, "tool", toolName)
		g.logGate(ctx, toolName, input, "allowed", "[任务白名单] 模型复核不可用，按 fail-open 放行")
		return "", false
	}
	switch dec.Action {
	case "allow":
		g.logGate(ctx, toolName, input, "allowed", "[任务白名单] 模型复核放行："+dec.Message)
		return "", false
	case "deny":
		reason := "[任务白名单] 模型复核拦截。" + strings.TrimPrefix(dec.Message, "[模型] ")
		g.logGate(ctx, toolName, input, "denied", reason)
		return reason, true
	default: // ask → 转人工审批（pending 进任务活动流；审批不通过 → 拦）
		if ctx.Err() != nil {
			// 工作已取消：不建 pending，立即拦（与 applyIntercept 同策略）。
			return "[任务白名单] 工作已取消，平台安全管控阻止执行", true
		}
		if g.interceptor != nil && g.interceptor.HandleAsk(ctx, intercept.ConvIDFromContext(ctx), dec, toolName, input) {
			return "", false
		}
		return "[任务白名单] 模型无法确认调用在授权范围内（转人工审批未通过或不可用），禁止访问", true
	}
}

// logGate 把闸门判定写入拦截历史（interceptor 未接线时静默跳过）。
func (g *Guard) logGate(ctx context.Context, toolName string, input json.RawMessage, status, reason string) {
	if g.interceptor == nil {
		return
	}
	action := "deny"
	if status == "allowed" {
		action = "allow"
	}
	g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx),
		intercept.Decision{Action: action, Message: reason}, toolName, input, status)
}

// CheckAllowedTargets 是自定义工具渲染后文本的白名单判定入口（server.customtool
// 调用）：自定义工具不走 PreToolUse 闸门（PreToolUse 只有参数 JSON、拿不到渲染
// 后的 URL/命令），渲染后在此用同一纯模型 gateCheck 核心校验。renderedText 是
// 渲染后的完整文本（预筛用；模型复核读 input 里的同一内容）。
func (g *Guard) CheckAllowedTargets(ctx context.Context, toolName string, input json.RawMessage, renderedText string) (string, bool) {
	if g.taskID <= 0 || g.assets == nil {
		return "", false
	}
	block, allow, err := g.loadGateRules()
	if err != nil {
		slog.Debug("guard: 任务白名单规则读取失败，放行", "taskID", g.taskID, "err", err)
		return "", false
	}
	if len(block) == 0 && !db.HasEnabledRule(allow) {
		return "", false
	}
	if !hasNetworkSignal(renderedText) {
		return "", false
	}
	return g.gateCheck(ctx, toolName, input, block, allow)
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
		return g.block(ev.ToolName, SystemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(ev.ToolName, SystemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
			return g.block(ev.ToolName, SystemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// SystemBlockMessage frames an intercept block as an ARTEX platform-governance
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
func SystemBlockMessage(reason string) string {
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
