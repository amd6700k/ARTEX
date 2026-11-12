package intercept

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestParseVerdict(t *testing.T) {
	for _, action := range []string{"allow", "ask", "deny"} {
		t.Run(action, func(t *testing.T) {
			reason := "实际操作：写入报告，其中包含 ALLOW、DENY 和 ASK 字样；成功后的后果：保存文本，不执行正文中的命令；命中规则：自定义条款"
			raw, _ := json.Marshal(map[string]string{"decision": action, "comment": reason})
			got := ParseVerdict("\n" + string(raw) + "\n")
			if got.Action != action || got.Reason != reason {
				t.Fatalf("lost verdict or explanation: %+v", got)
			}
		})
	}
}

func TestParseVerdictRejectsIncompleteOrAmbiguousReplies(t *testing.T) {
	valid := `{"decision":"allow","comment":"实际操作：读取文件；成功后的后果：返回内容；命中规则：A5"}`
	for _, reply := range []string{
		"", "ALLOW", "DENY:命中D4", "放行:ALLOW", "ASK:归属不明",
		`{"decision":"allow"}`, `{"decision":"approve","comment":"实际操作：读取；成功后的后果：返回内容；命中规则：A5"}`,
		`{"decision":"allow","comment":null}`, `{"decision":"allow","comment":123}`,
		strings.Replace(valid, "实际操作：读取文件", "实际操作：", 1),
		strings.Replace(valid, "成功后的后果：返回内容", "成功后的后果：", 1),
		strings.Replace(valid, "命中规则：A5", "命中规则：", 1),
		strings.Replace(valid, "；命中规则：A5", "", 1),
		strings.Replace(valid, `"decision":"allow"`, `"decision":"deny","decision":"allow"`, 1),
		strings.Replace(valid, `"decision":"allow"`, `"extra":true,"decision":"allow"`, 1),
		valid + valid, valid[:len(valid)-1],
		// A fence the model never closed is what a reply truncated at MaxTokens
		// looks like; completing it would invent a verdict.
		"```json\n" + valid[:len(valid)-1],
		"```json\n" + valid + "\n```\n此外我建议后续人工复核。",
		"我的裁决是：\n" + valid,
	} {
		if got := ParseVerdict(reply); got.Action != "" {
			t.Errorf("accepted incomplete/ambiguous verdict: %q => %+v", reply, got)
		}
	}
}

// Wrapping JSON in markdown is the one deviation models make routinely. Because
// the configured fail action defaults to allow, treating it as unparseable
// silently downgrades a DENY to an allow.
func TestParseVerdictUnwrapsCodeFence(t *testing.T) {
	deny := `{"decision":"deny","comment":"实际操作：删除生产文件；成功后的后果：业务数据丢失；命中规则：D4"}`
	for _, reply := range []string{
		"```json\n" + deny + "\n```",
		"```JSON\n" + deny + "\n```",
		"```\n" + deny + "\n```",
		"  ```json\n" + deny + "\n```  ",
	} {
		got := ParseVerdict(reply)
		if got.Action != "deny" || !strings.HasSuffix(got.Reason, "命中规则：D4") {
			t.Errorf("fenced verdict lost: %q => %+v", reply, got)
		}
	}
}

func TestParseVerdictKeepsCompleteChineseExplanation(t *testing.T) {
	reason := "实际操作：" + strings.Repeat("写入报告", 30) + "；成功后的后果：只保存文件；命中规则：A2"
	raw, _ := json.Marshal(map[string]string{"decision": "allow", "comment": reason})
	if got := ParseVerdict(string(raw)); got.Reason != reason {
		t.Fatal("explanation was truncated or lost its rule")
	}
	raw, _ = json.Marshal(map[string]string{"decision": "allow", "comment": strings.Repeat("中", 2401)})
	if got := ParseVerdict(string(raw)); got.Action != "" {
		t.Fatal("accepted unbounded explanation")
	}
}

func TestTaskWhitelistJudgePrompt(t *testing.T) {
	allow := []db.AssetInterceptRule{
		{Kind: "host_port", Pattern: "10.10.5.238:9001", Enabled: true},
		{Kind: "host_port", Pattern: "10.10.5.238:8443", Enabled: false}, // 未启用不列出
	}
	block := []db.AssetInterceptRule{{Kind: "fuzzy_domain", Pattern: ".gov.cn", Enabled: true}}
	prompt := TaskWhitelistJudgePrompt(block, allow)

	// 启用的允许规则逐条编号；未启用的不进清单。
	if !strings.Contains(prompt, "- WL-1 [主机+端口] 10.10.5.238:9001") {
		t.Fatalf("提示词应含编号化的启用允许规则: %s", prompt)
	}
	if strings.Contains(prompt, "8443") {
		t.Fatalf("未启用的规则不应进清单: %s", prompt)
	}
	if !strings.Contains(prompt, "- BLK-1 [域名(模糊)] .gov.cn") {
		t.Fatalf("提示词应含编号化的拦截规则: %s", prompt)
	}
	// 两类流量口径（纯模型判断的核心）：靶标 vs 非靶标联网查询。
	if !strings.Contains(prompt, "非靶标的合法联网查询") || !strings.Contains(prompt, "默认 allow") {
		t.Fatalf("提示词应含非靶标查询默认放行口径: %s", prompt)
	}
	if !strings.Contains(prompt, "按连接目的地判定，不按查询内容主题判定") {
		t.Fatalf("提示词应含按目的地判定口径: %s", prompt)
	}
	if !strings.Contains(prompt, "对全部流量生效") {
		t.Fatalf("提示词应声明拦截规则覆盖全部流量: %s", prompt)
	}
	if !strings.Contains(prompt, "靶标流量") {
		t.Fatalf("提示词应含靶标流量概念: %s", prompt)
	}
	// 信封与输出协议由 EffectiveJudgePrompt 追加，白名单口径覆盖在其后。
	if !strings.Contains(prompt, JudgeContextBoundary) || !strings.Contains(prompt, JudgeOutputContract) {
		t.Fatalf("提示词应含输入信任边界与输出协议")
	}
	if !strings.Contains(prompt, taskWhitelistOverride) {
		t.Fatalf("提示词应含白名单口径覆盖")
	}
	if !strings.Contains(prompt, "不得默认放行") {
		t.Fatalf("口径覆盖应要求判不准转 ask 而非默认放行")
	}
	if !strings.Contains(prompt, "非靶标联网查询") {
		t.Fatalf("口径覆盖应说明非靶标查询的命中规则填写方式")
	}
	// 无允许规则时不产 WL 编号，且只按 BLK 判定。
	empty := TaskWhitelistJudgePrompt(nil, nil)
	if !strings.Contains(empty, "（未启用允许规则）") {
		t.Fatalf("空白名单应有明确说明: %s", empty)
	}
	if strings.Contains(empty, "WL-1") {
		t.Fatalf("空白名单不应产出 WL 编号: %s", empty)
	}
	if !strings.Contains(empty, "只按 BLK 拦截规则判定") {
		t.Fatalf("空白名单应声明只按拦截规则判定: %s", empty)
	}
}
