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

// allowRule 返回白名单规则：仅允许 10.10.5.238:9001（定义靶标范围）。
func allowRule() []db.AssetInterceptRule {
	return []db.AssetInterceptRule{{Kind: "host_port", Pattern: "10.10.5.238:9001", Enabled: true}}
}

// judgeMock 是 judge 测试缝的 mock：记录调用次数与规则参数，回放固定裁决。
// prompt 按收到的规则经 TaskWhitelistJudgePrompt（内置正文）现生成，供文案断言。
type judgeMock struct {
	calls  int
	prompt string
	block  []db.AssetInterceptRule
	allow  []db.AssetInterceptRule
	dec    intercept.Decision
	ok     bool
}

func (m *judgeMock) hook(ctx context.Context, tool string, input json.RawMessage, block, allow []db.AssetInterceptRule) (intercept.Decision, bool) {
	m.calls++
	m.block, m.allow = block, allow
	m.prompt = intercept.TaskWhitelistJudgePrompt(block, allow, "")
	return m.dec, m.ok
}

// 预筛：无联网信号的命令直接放行，零模型调用。
func TestGateZeroSignalSkipsReview(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "deny"}}
	g.judge = m.hook

	for _, cmd := range []string{
		"echo hi",
		"cat /etc/passwd",
		"grep root /var/log/syslog",
		"ls -la /tmp | head -5",
	} {
		if res := g.preToolUse(context.Background(), bashEvent(cmd)); res.Decision == "block" {
			t.Fatalf("无联网信号命令应放行: %s → %+v", cmd, res)
		}
	}
	if m.calls != 0 {
		t.Fatalf("无联网信号命令不应送模型, calls=%d", m.calls)
	}
}

// 预筛：带联网信号的命令触发模型复核（判定权在模型）。
func TestGateNetworkSignalTriggersReview(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "deny", Message: "[模型] 靶标越界"}}
	g.judge = m.hook

	if res := g.preToolUse(context.Background(), bashEvent("nmap -sV example.com")); res.Decision != "block" {
		t.Fatalf("联网信号命令应送模型并按裁决执行: %+v", res)
	}
	if m.calls != 1 {
		t.Fatalf("应恰好调用一次模型, calls=%d", m.calls)
	}
}

func TestGateJudgeDenyBlocks(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "deny", Message: "[模型] 10.9.9.9 是靶标的越界端口目的地，无匹配允许规则"}}
	g.judge = m.hook

	res := g.preToolUse(context.Background(), bashEvent("curl http://10.9.9.9/"))
	if res.Decision != "block" {
		t.Fatalf("模型判拦截应拦截，got %+v", res)
	}
	msg := res.Message
	if !strings.Contains(msg, "[任务白名单]") || !strings.Contains(msg, "模型复核拦截") {
		t.Fatalf("拦截文案应含 [任务白名单] 与复核结论: %s", msg)
	}
	if !strings.Contains(msg, "10.9.9.9 是靶标的越界端口目的地") {
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
	// 提示词应内嵌编号化允许规则与新口径（非靶标联网查询默认放行）。
	if !strings.Contains(m.prompt, "WL-1") || !strings.Contains(m.prompt, "10.10.5.238:9001") {
		t.Fatalf("复核提示词应含编号化的允许规则: %s", m.prompt)
	}
	if !strings.Contains(m.prompt, "非靶标的合法联网查询") || !strings.Contains(m.prompt, "按连接目的地判定") {
		t.Fatalf("复核提示词应含两类流量口径: %s", m.prompt)
	}
}

func TestGateJudgeAllowPermits(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())
	// 模型判非靶标查询放行（OSINT/软件源类联检的预期裁决）。
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "allow", Message: "[模型] 目的地为漏洞库，属非靶标联网查询"}}
	g.judge = m.hook

	res := g.preToolUse(context.Background(), bashEvent("curl -s https://cve.example.com/api?id=10.10.5.238"))
	if res.Decision == "block" {
		t.Fatalf("模型放行应放行: %+v", res)
	}
}

// 复核不可用（judge 未接线 / 返回 false）→ 放行（fail-open）。
func TestGateJudgeUnavailableFailsOpen(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())
	if res := g.preToolUse(context.Background(), bashEvent("curl http://10.9.9.9/")); res.Decision == "block" {
		t.Fatalf("复核不可用应放行: %+v", res)
	}
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
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "ask", Message: "[模型] 目的地经变量间接引用，无法确认"}}
	g.judge = m.hook

	res := g.preToolUse(context.Background(), bashEvent("curl http://10.9.9.9/"))
	if res.Decision != "block" {
		t.Fatalf("ask 且无审批链路应拦: %+v", res)
	}
	if !strings.Contains(res.Message, "转人工审批未通过或不可用") {
		t.Fatalf("拦截文案应说明人审不可用: %s", res.Message)
	}
}

func TestGateClosedWithoutTaskOrRules(t *testing.T) {
	// taskID=0（顶层 chat 等）→ 闸门关闭，即使 rulesFn 会拦一切。
	g := NewForTask(nil, 0, nil)
	g.rulesFn = staticRules(nil, allowRule())
	if res := g.preToolUse(context.Background(), bashEvent("curl http://10.9.9.9/")); res.Decision == "block" {
		t.Fatalf("taskID=0 闸门应关闭: %+v", res)
	}

	// taskID>0 但无任何启用规则 → 放行（零开销短路）。
	g2 := NewForTask(nil, 5, nil)
	g2.rulesFn = staticRules(nil, nil)
	if res := g2.preToolUse(context.Background(), bashEvent("curl http://10.9.9.9/")); res.Decision == "block" {
		t.Fatalf("无启用规则应放行: %+v", res)
	}
}

// block 拦截规则在纯模型架构下同样交模型判定（判定权统一），提示词含 BLK 编号
// 与「对全部流量生效」条款。
func TestGateBlockRuleGoesThroughModel(t *testing.T) {
	block := []db.AssetInterceptRule{{Kind: "fuzzy_domain", Pattern: ".gov.cn", Enabled: true}}
	allow := []db.AssetInterceptRule{{Kind: "fuzzy_domain", Pattern: "gov.cn", Enabled: true}}
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(block, allow)
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "deny", Message: "[模型] 目的地命中 BLK-1 拦截规则"}}
	g.judge = m.hook

	res := g.preToolUse(context.Background(), bashEvent("curl https://www.gov.cn/"))
	if res.Decision != "block" {
		t.Fatalf("模型判命中拦截规则应拦: %+v", res)
	}
	if !strings.Contains(m.prompt, "BLK-1") || !strings.Contains(m.prompt, ".gov.cn") {
		t.Fatalf("复核提示词应含编号化拦截规则: %s", m.prompt)
	}
	if !strings.Contains(m.prompt, "对全部流量生效") {
		t.Fatalf("复核提示词应声明拦截规则覆盖全部流量: %s", m.prompt)
	}
}

func TestGateNonGateToolUntouched(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())
	m := &judgeMock{ok: true, dec: intercept.Decision{Action: "deny"}}
	g.judge = m.hook

	// 文本类工具（evidence 里出现域外 URL）不应被闸门送复核。
	ev := hook.Event{ToolName: "record_fact", Input: []byte(`{"note":"see http://10.9.9.9:80/x"}`)}
	if res := g.preToolUse(context.Background(), ev); res.Decision == "block" {
		t.Fatalf("非清单工具不应被闸门拦截: %+v", res)
	}
	if m.calls != 0 {
		t.Fatalf("非清单工具不应触发复核, calls=%d", m.calls)
	}
}

func TestHasNetworkSignal(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		{"curl http://10.9.9.9/", true},
		{"nmap -sV example.com", true},
		{"dig @8.8.8.8 example.com", true},
		{"ping web01", true},             // 已知网络工具名
		{"./probe 10.0.0.1 -p 80", true}, // IPv4 字面量
		{"echo hi", false},
		{"cat /etc/passwd", false},
		{"grep root /var/log/syslog", false},
		{"ls -la /tmp | head -5", false},
	}
	for _, c := range cases {
		if got := hasNetworkSignal(c.text); got != c.want {
			t.Fatalf("hasNetworkSignal(%q) = %v, want %v", c.text, got, c.want)
		}
	}
}
