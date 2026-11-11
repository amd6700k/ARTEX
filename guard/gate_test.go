package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// staticRules 返回一个 rulesFn 测试缝：静态规则集，无需 PG。
func staticRules(block, allow []db.AssetInterceptRule) func() ([]db.AssetInterceptRule, []db.AssetInterceptRule, error) {
	return func() ([]db.AssetInterceptRule, []db.AssetInterceptRule, error) {
		return block, allow, nil
	}
}

func bashEvent(cmd string) hook.Event {
	b, _ := json.Marshal(map[string]string{"command": cmd})
	return hook.Event{ToolName: "Bash", Input: b}
}

// allowRule 返回白名单规则：仅允许 10.10.5.238:9001。
func allowRule() []db.AssetInterceptRule {
	return []db.AssetInterceptRule{{Kind: "host_port", Pattern: "10.10.5.238:9001", Enabled: true}}
}

// judgeMock 是 judge 测试缝的 mock：记录调用次数与收到的提示词，回放固定裁决。
type judgeMock struct {
	calls  int
	prompt string
	dec    intercept.Decision
	ok     bool
}

func (m *judgeMock) hook(ctx context.Context, tool string, input json.RawMessage, prompt string) (intercept.Decision, bool) {
	m.calls++
	m.prompt = prompt
	return m.dec, m.ok
}

func TestGateAllowsInWhitelistWithoutReview(t *testing.T) {
	g := NewForTask(nil, 5, nil) // interceptor=nil → judge 未接线
	g.rulesFn = staticRules(nil, allowRule())
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "deny"}}
	g.judge = m.hook

	// 白名单内目标：直接放行，不触发模型复核（零开销路径）。
	res := g.preToolUse(context.Background(), bashEvent("curl http://10.10.5.238:9001/api"))
	if res.Decision == "block" {
		t.Fatalf("白名单内目标应放行: %+v", res)
	}
	if m.calls != 0 {
		t.Fatalf("白名单内不应调用模型复核, calls=%d", m.calls)
	}
}

func TestGateJudgeDenyBlocks(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "deny", Message: "[模型] 10.9.9.9 不在任何允许规则内"}}
	g.judge = m.hook

	res := g.preToolUse(context.Background(), bashEvent("curl http://10.9.9.9/"))
	if res.Decision != "block" {
		t.Fatalf("模型判越界应拦截，got %+v", res)
	}
	msg := res.Message
	if !strings.Contains(msg, "[任务白名单]") || !strings.Contains(msg, "模型复核确认越界") {
		t.Fatalf("拦截文案应含 [任务白名单] 与复核结论: %s", msg)
	}
	if !strings.Contains(msg, "10.9.9.9 不在任何允许规则内") {
		t.Fatalf("拦截文案应含模型 reason: %s", msg)
	}
	if !strings.Contains(msg, "ARTEX 平台管控·非目标防御") {
		t.Fatalf("模型面文案应沿用平台管控前缀: %s", msg)
	}
	// 审计应有 block 记录（reason 含 [任务白名单]，与 applyIntercept 的 deny 同口径）。
	found := false
	for _, e := range g.Audit() {
		if e.Action == "block" && strings.Contains(e.Reason, "[任务白名单]") {
			found = true
		}
	}
	if !found {
		t.Fatalf("审计应含 [任务白名单] 的 block 记录: %+v", g.Audit())
	}
	// 复核提示词应内嵌允许规则清单与提取器线索。
	if !strings.Contains(m.prompt, "WL-1") || !strings.Contains(m.prompt, "10.10.5.238:9001") {
		t.Fatalf("复核提示词应含编号化的允许规则: %s", m.prompt)
	}
	if !strings.Contains(m.prompt, "10.9.9.9") {
		t.Fatalf("复核提示词应含提取器疑似越界线索: %s", m.prompt)
	}
}

func TestGateJudgeAllowPermits(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "allow", Message: "[模型] 全部目标落在 WL-1 内"}}
	g.judge = m.hook

	res := g.preToolUse(context.Background(), bashEvent("curl http://10.9.9.9/"))
	if res.Decision == "block" {
		t.Fatalf("模型复核放行应放行: %+v", res)
	}
}

// 复核不可用（judge 未接线 / 返回 false）→ 放行（fail-open）。
func TestGateJudgeUnavailableFailsOpen(t *testing.T) {
	// judge 未接线（interceptor=nil 且未注入缝）。
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())
	if res := g.preToolUse(context.Background(), bashEvent("curl http://10.9.9.9/")); res.Decision == "block" {
		t.Fatalf("复核不可用应放行: %+v", res)
	}
	// judge 返回 ok=false（开关关/超时/解析失败）。
	g2 := NewForTask(nil, 5, nil)
	g2.rulesFn = staticRules(nil, allowRule())
	m := &judgeMock{ok: false}
	g2.judge = m.hook
	if res := g2.preToolUse(context.Background(), bashEvent("curl http://10.9.9.9/")); res.Decision == "block" {
		t.Fatalf("复核失败应放行: %+v", res)
	}
}

// 模型裁决 ask → 转人工；无 interceptor（建不了 pending）→ 按拦截兜底。
func TestGateAskWithoutInterceptorBlocks(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "ask", Message: "[模型] 目标经变量间接引用，无法确认"}}
	g.judge = m.hook

	res := g.preToolUse(context.Background(), bashEvent("curl http://10.9.9.9/"))
	if res.Decision != "block" {
		t.Fatalf("ask 且无审批链路应拦: %+v", res)
	}
	if !strings.Contains(res.Message, "转人工审批未通过或不可用") {
		t.Fatalf("拦截文案应说明人审不可用: %s", res.Message)
	}
}

func TestGateAllowsUnextractableAndEmpty(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "deny"}}
	g.judge = m.hook

	// 提不出目标（T3）→ 放行且不复核。
	if res := g.preToolUse(context.Background(), bashEvent("echo hi")); res.Decision == "block" {
		t.Fatalf("无目标命令应放行: %+v", res)
	}
	// shell 变量目标提不出 → 放行（已知限制）。
	if res := g.preToolUse(context.Background(), bashEvent(`echo "$FOO"`)); res.Decision == "block" {
		t.Fatalf("变量承载目标应放行（已知限制）: %+v", res)
	}
	if m.calls != 0 {
		t.Fatalf("提不出目标不应触发复核, calls=%d", m.calls)
	}
}

func TestGateClosedWithoutTaskOrRules(t *testing.T) {
	// taskID=0（顶层 chat 等）→ 闸门关闭，即使 rulesFn 会拦一切。
	g := NewForTask(nil, 0, nil)
	g.rulesFn = staticRules(nil, allowRule())
	if res := g.preToolUse(context.Background(), bashEvent("curl http://10.9.9.9/")); res.Decision == "block" {
		t.Fatalf("taskID=0 闸门应关闭: %+v", res)
	}

	// taskID>0 但无任何启用规则 → 放行且不提取（零开销短路）。
	g2 := NewForTask(nil, 5, nil)
	g2.rulesFn = staticRules(nil, nil)
	if res := g2.preToolUse(context.Background(), bashEvent("curl http://10.9.9.9/")); res.Decision == "block" {
		t.Fatalf("无启用规则应放行: %+v", res)
	}
}

func TestGateBlockRuleDeniesDeterministically(t *testing.T) {
	block := []db.AssetInterceptRule{{Kind: "fuzzy_domain", Pattern: ".gov.cn", Enabled: true}}
	allow := []db.AssetInterceptRule{{Kind: "fuzzy_domain", Pattern: "gov.cn", Enabled: true}}
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(block, allow)
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "allow"}}
	g.judge = m.hook

	// block 规则命中：确定性拦截，不经模型复核。
	res := g.preToolUse(context.Background(), bashEvent("curl https://www.gov.cn/"))
	if res.Decision != "block" {
		t.Fatalf("命中拦截规则应被拒（block 优先）: %+v", res)
	}
	if !strings.Contains(res.Message, "命中拦截规则") {
		t.Fatalf("拦截文案应含拦截规则原因: %s", res.Message)
	}
	if m.calls != 0 {
		t.Fatalf("block 规则不应触发模型复核, calls=%d", m.calls)
	}
}

func TestGateNonGateToolUntouched(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "deny"}}
	g.judge = m.hook

	// 文本类工具（evidence 里出现域外 URL）不应被拦。
	ev := hook.Event{ToolName: "record_fact", Input: []byte(`{"note":"see http://10.9.9.9:80/x"}`)}
	if res := g.preToolUse(context.Background(), ev); res.Decision == "block" {
		t.Fatalf("非清单工具不应被闸门拦截: %+v", res)
	}
	if m.calls != 0 {
		t.Fatalf("非清单工具不应触发复核, calls=%d", m.calls)
	}
}

// 两次线上误报的回归锚点：修复提取精度后，这两条命令应零复核直接放行。
func TestGateScreenshotCommandsPassWithoutReview(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "deny"}}
	g.judge = m.hook

	// 截图1：curl -X POST + 单引号头（曾被提取成 POST / application 两个假目标）。
	cmd1 := `cd /app/data/tasks/31/748 && curl -s -m 10 -i -X POST http://10.10.5.238:9001/api/v3/login -H 'Content-Type: application/json' -d '{"username":"minioadmin","password":"minioadmin"}' 2>&1 | head -25`
	if res := g.preToolUse(context.Background(), bashEvent(cmd1)); res.Decision == "block" {
		t.Fatalf("截图1命令应放行: %+v", res)
	}
	// 截图2：heredoc Python 脚本（裸 IP + 相邻端口曾被拆成无端口候选）。
	cmd2 := "cat > ws_handshake.py << 'EOF'\n" +
		"import socket, base64, os, sys, json\n" +
		"def handshake(host, port, path, extra_headers=None, timeout=5):\n" +
		"    key = base64.b64encode(os.urandom(16)).decode()\n" +
		"    s = socket.create_connection((host, port), timeout=timeout)\n" +
		"    return s, buf\n" +
		"host, port = \"10.10.5.238\", 9001\n" +
		"paths = sys.argv[1:] or [\"/ws/objectManager\"]\n" +
		"EOF\npython3 ws_handshake.py /ws/objectManager"
	if res := g.preToolUse(context.Background(), bashEvent(cmd2)); res.Decision == "block" {
		t.Fatalf("截图2命令应放行: %+v", res)
	}
	if m.calls != 0 {
		t.Fatalf("两条误报命令修复后不应触发复核, calls=%d", m.calls)
	}
}
