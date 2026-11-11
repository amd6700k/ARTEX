package guard

import (
	"context"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/hook"
)

// staticRules 返回一个 rulesFn 测试缝：静态规则集，无需 PG。
func staticRules(block, allow []db.AssetInterceptRule) func() ([]db.AssetInterceptRule, []db.AssetInterceptRule, error) {
	return func() ([]db.AssetInterceptRule, []db.AssetInterceptRule, error) {
		return block, allow, nil
	}
}

func bashEvent(cmd string) hook.Event {
	return hook.Event{ToolName: "Bash", Input: []byte(`{"command":"` + cmd + `"}`)}
}

// 白名单规则：仅允许 127.0.0.1:8080。
func allowRule() []db.AssetInterceptRule {
	return []db.AssetInterceptRule{{Kind: "host_port", Pattern: "127.0.0.1:8080", Enabled: true}}
}

func TestGateDeniesOutOfWhitelist(t *testing.T) {
	g := NewForTask(nil, 5, nil) // interceptor=nil：验证 deny 路径不 panic
	g.rulesFn = staticRules(nil, allowRule())

	res := g.preToolUse(context.Background(), bashEvent("curl http://10.9.9.9/"))
	if res.Decision != "block" {
		t.Fatalf("出界目标应被拦截，got %+v", res)
	}
	msg := res.Message
	if !strings.Contains(msg, "[任务白名单]") {
		t.Fatalf("拦截文案应含 [任务白名单] 前缀: %s", msg)
	}
	if !strings.Contains(msg, "10.9.9.9") {
		t.Fatalf("拦截文案应含被拒目标: %s", msg)
	}
	if !strings.Contains(msg, "127.0.0.1:8080") || !strings.Contains(msg, "主机+端口") {
		t.Fatalf("拦截文案应含允许规则列表: %s", msg)
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
}

func TestGateAllowsInWhitelist(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())

	res := g.preToolUse(context.Background(), bashEvent("curl http://127.0.0.1:8080/api"))
	if res.Decision == "block" {
		t.Fatalf("白名单内目标应放行: %+v", res)
	}
}

func TestGateAllowsUnextractableAndEmpty(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())

	// 提不出目标（T3）→ 放行。
	if res := g.preToolUse(context.Background(), bashEvent("echo hi")); res.Decision == "block" {
		t.Fatalf("无目标命令应放行: %+v", res)
	}
	// shell 变量目标提不出 → 放行。
	if res := g.preToolUse(context.Background(), bashEvent(`curl "$TARGET"`)); res.Decision == "block" {
		t.Fatalf("变量承载目标应放行（已知限制）: %+v", res)
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

func TestGateBlockRuleDeniesEvenInWhitelist(t *testing.T) {
	block := []db.AssetInterceptRule{{Kind: "fuzzy_domain", Pattern: ".gov.cn", Enabled: true}}
	allow := []db.AssetInterceptRule{{Kind: "fuzzy_domain", Pattern: "gov.cn", Enabled: true}}
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(block, allow)

	res := g.preToolUse(context.Background(), bashEvent("curl https://www.gov.cn/"))
	if res.Decision != "block" {
		t.Fatalf("命中拦截规则应被拒（block 优先）: %+v", res)
	}
	if !strings.Contains(res.Message, "命中资产拦截规则") {
		t.Fatalf("拦截文案应含拦截规则原因: %s", res.Message)
	}
}

func TestGateNonGateToolUntouched(t *testing.T) {
	g := NewForTask(nil, 5, nil)
	g.rulesFn = staticRules(nil, allowRule())

	// 文本类工具（evidence 里出现域外 URL）不应被拦。
	ev := hook.Event{ToolName: "record_fact", Input: []byte(`{"note":"see http://10.9.9.9:80/x"}`)}
	if res := g.preToolUse(context.Background(), ev); res.Decision == "block" {
		t.Fatalf("非清单工具不应被闸门拦截: %+v", res)
	}
}
