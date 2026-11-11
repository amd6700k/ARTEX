package db

import "testing"

func TestInterceptSource(t *testing.T) {
	cases := []struct {
		name   string
		ruleID int64
		reason string
		want   string
	}{
		{"规则行命中", 42, "任意原因", "rule"},
		{"模型前缀", 0, "[模型] 判定为危险命令", "model"},
		{"任务白名单前缀", 0, "[任务白名单] 以下目标不在本次任务允许范围内…", "rule"},
		{"其他前缀", 0, "人工审批未通过", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := interceptSource(c.ruleID, c.reason); got != c.want {
				t.Fatalf("interceptSource(%d, %q) = %q, want %q", c.ruleID, c.reason, got, c.want)
			}
		})
	}
}
