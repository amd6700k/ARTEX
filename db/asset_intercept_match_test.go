package db

import "testing"

func rule(kind, pattern string, enabled bool) AssetInterceptRule {
	return AssetInterceptRule{Kind: kind, Pattern: pattern, Enabled: enabled}
}

func TestMatchAssetInterceptRules(t *testing.T) {
	cases := []struct {
		name    string
		rules   []AssetInterceptRule
		domains []string
		ips     []string
		urls    []string
		want    bool
		wantVal string
	}{
		{"内置模糊政府域名命中", []AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)},
			[]string{"www.beijing.gov.cn"}, nil, nil, true, "www.beijing.gov.cn"},
		{"模糊教育域名命中", []AssetInterceptRule{rule("fuzzy_domain", ".edu", true)},
			[]string{"mit.edu"}, nil, nil, true, "mit.edu"},
		{"全等域名命中大小写不敏感", []AssetInterceptRule{rule("exact_domain", "Example.com", true)},
			[]string{"example.com"}, nil, nil, true, "example.com"},
		{"全等域名不命中子域", []AssetInterceptRule{rule("exact_domain", "example.com", true)},
			[]string{"a.example.com"}, nil, nil, false, ""},
		{"全等IP命中", []AssetInterceptRule{rule("exact_ip", "203.0.113.5", true)},
			nil, []string{"203.0.113.5"}, nil, true, "203.0.113.5"},
		{"模糊IP前缀命中", []AssetInterceptRule{rule("fuzzy_ip", "203.0.113.", true)},
			nil, []string{"203.0.113.99"}, nil, true, "203.0.113.99"},
		{"CIDR 命中", []AssetInterceptRule{rule("cidr", "192.168.0.0/16", true)},
			nil, []string{"192.168.5.20"}, nil, true, "192.168.5.20"},
		{"CIDR 不命中", []AssetInterceptRule{rule("cidr", "192.168.0.0/16", true)},
			nil, []string{"10.0.0.1"}, nil, false, ""},
		{"全等URL命中", []AssetInterceptRule{rule("exact_url", "https://a.gov.cn/login", true)},
			nil, nil, []string{"https://a.gov.cn/login"}, true, "https://a.gov.cn/login"},
		{"模糊URL命中路径", []AssetInterceptRule{rule("fuzzy_url", "/admin", true)},
			nil, nil, []string{"https://x.com/admin/panel"}, true, "https://x.com/admin/panel"},
		{"禁用规则不命中", []AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", false)},
			[]string{"www.gov.cn"}, nil, nil, false, ""},
		{"无规则不命中", nil, []string{"www.gov.cn"}, nil, nil, false, ""},
		{"空pattern不命中", []AssetInterceptRule{rule("fuzzy_domain", "  ", true)},
			[]string{"www.gov.cn"}, nil, nil, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, val, ok := MatchAssetInterceptRules(c.rules, c.domains, c.ips, c.urls)
			if ok != c.want {
				t.Fatalf("命中 = %v, 期望 %v (rule=%+v)", ok, c.want, r)
			}
			if ok && val != c.wantVal {
				t.Fatalf("命中值 = %q, 期望 %q", val, c.wantVal)
			}
		})
	}
}

func TestEvaluateAssetGate(t *testing.T) {
	block := []AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)}
	allow := []AssetInterceptRule{rule("fuzzy_domain", "example.com", true)}

	// 1. 命中拦截规则 → 拒绝（拦截原因优先）。
	if d := EvaluateAssetGate(block, allow, []string{"www.gov.cn"}, nil, nil); d.Allowed {
		t.Fatal("命中拦截规则应被拒绝")
	}

	// 2. 未命中拦截、有允许规则但不命中 → 拒绝（不允许）。
	d := EvaluateAssetGate(block, allow, []string{"foo.other.com"}, nil, nil)
	if d.Allowed {
		t.Fatal("有白名单且不命中应被拒绝")
	}
	if d.Reason == "" {
		t.Fatal("拒绝应带原因")
	}

	// 3. 未命中拦截、命中允许规则 → 放行。
	if d := EvaluateAssetGate(block, allow, []string{"api.example.com"}, nil, nil); !d.Allowed {
		t.Fatal("命中白名单应放行")
	}

	// 4. 无允许规则（白名单未启用）→ 未命中拦截即放行。
	if d := EvaluateAssetGate(block, nil, []string{"foo.other.com"}, nil, nil); !d.Allowed {
		t.Fatal("无白名单时未命中拦截应放行")
	}

	// 5. 允许规则全部禁用 → 视为白名单未启用，放行。
	disabledAllow := []AssetInterceptRule{rule("fuzzy_domain", "example.com", false)}
	if d := EvaluateAssetGate(nil, disabledAllow, []string{"foo.other.com"}, nil, nil); !d.Allowed {
		t.Fatal("白名单全禁用时应放行")
	}

	// 6. 拦截优先于允许：同一目标既命中拦截又命中允许 → 拒绝。
	if d := EvaluateAssetGate(
		[]AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)},
		[]AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)},
		[]string{"www.gov.cn"}, nil, nil,
	); d.Allowed {
		t.Fatal("拦截应优先于允许")
	}
}

func TestAssetInterceptCandidates(t *testing.T) {
	// 只带 URL 的服务资产：host 应被拆出并归入域名候选，从而被 fuzzy_domain 命中。
	a := &Asset{Type: "service", URL: "https://portal.beijing.gov.cn:8443/app"}
	tgt := a.interceptCandidates()
	if len(tgt.URLs) != 1 || tgt.URLs[0] != a.URL {
		t.Fatalf("urls = %v", tgt.URLs)
	}
	found := false
	for _, d := range tgt.Domains {
		if d == "portal.beijing.gov.cn" {
			found = true
		}
	}
	if !found {
		t.Fatalf("URL host 未拆入域名候选: %v", tgt.Domains)
	}
	r, _, ok := MatchAssetInterceptRules([]AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)}, tgt.Domains, nil, tgt.URLs)
	if !ok {
		t.Fatalf("仅带 URL 的政府服务资产应被 fuzzy_domain 命中, rule=%+v", r)
	}

	// URL host 是 IP 时应归入 IP 候选，可被 CIDR 命中。
	b := &Asset{Type: "service", URL: "http://10.1.2.3/x"}
	tgtB := b.interceptCandidates()
	if r, _, ok := MatchAssetInterceptRules([]AssetInterceptRule{rule("cidr", "10.0.0.0/8", true)}, nil, tgtB.IPs, nil); !ok {
		t.Fatalf("URL 中的 IP 应被 CIDR 命中, ips=%v rule=%+v", tgtB.IPs, r)
	}
}

func TestParseHostPortPattern(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		host    string
		lo, hi  int
		wantErr bool
	}{
		{"IPv4单端口", "203.0.113.10:8080", "203.0.113.10", 8080, 8080, false},
		{"域名单端口", "example.com:443", "example.com", 443, 443, false},
		{"端口区间", "10.0.0.1:8000-9000", "10.0.0.1", 8000, 9000, false},
		{"CIDR+端口", "192.168.0.0/16:443", "192.168.0.0/16", 443, 443, false},
		{"IPv6括号形式", "[::1]:8080", "::1", 8080, 8080, false},
		{"localhost", "localhost:80", "localhost", 80, 80, false},
		{"裸host报错", "203.0.113.10", "", 0, 0, true},
		{"裸域名报错", "example.com", "", 0, 0, true},
		{"裸IPv6报错", "::1", "", 0, 0, true},
		{"区间倒置报错", "1.2.3.4:9000-8000", "", 0, 0, true},
		{"端口超界报错", "1.2.3.4:70000", "", 0, 0, true},
		{"端口为0报错", "1.2.3.4:0", "", 0, 0, true},
		{"端口非数字报错", "1.2.3.4:abc", "", 0, 0, true},
		{"非法host报错", "in valid host:80", "", 0, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, lo, hi, err := ParseHostPortPattern(c.pattern)
			if c.wantErr {
				if err == nil {
					t.Fatalf("应报错，得到 host=%q lo=%d hi=%d", host, lo, hi)
				}
				return
			}
			if err != nil {
				t.Fatalf("不应报错: %v", err)
			}
			if host != c.host || lo != c.lo || hi != c.hi {
				t.Fatalf("got (%q,%d,%d), want (%q,%d,%d)", host, lo, hi, c.host, c.lo, c.hi)
			}
		})
	}
}

func TestMatchHostPort(t *testing.T) {
	gt := func(hosts ...string) GateTargets { return GateTargets{HostPorts: hosts} }

	cases := []struct {
		name  string
		rule  string
		mode  matchMode
		cands []string
		want  bool
	}{
		// block = 重叠语义
		{"block 单端口相等命中", "1.2.3.4:8080", modeBlock, []string{"1.2.3.4:8080"}, true},
		{"block 端口重叠命中", "1.2.3.4:8000-9000", modeBlock, []string{"1.2.3.4:8500"}, true},
		{"block 区间相交命中", "1.2.3.4:8000-9000", modeBlock, []string{"1.2.3.4:8500-9500"}, true},
		{"block 端口不相交不命中", "1.2.3.4:8080", modeBlock, []string{"1.2.3.4:9090"}, false},
		{"block 主机不同不命中", "1.2.3.4:8080", modeBlock, []string{"5.6.7.8:8080"}, false},
		{"block 全端口候选命中", "1.2.3.4:8080", modeBlock, []string{"1.2.3.4:*"}, true},
		{"block 无端口语义候选命中", "1.2.3.4:8080", modeBlock, []string{"1.2.3.4"}, true},
		{"block 多端口部分重叠命中", "1.2.3.4:8080", modeBlock, []string{"1.2.3.4:80,443,8080"}, true},
		{"block CIDR 覆盖 IP 命中", "192.168.0.0/16:443", modeBlock, []string{"192.168.5.20:443"}, true},
		{"block CIDR 与网段候选重叠命中", "192.168.0.0/16:443", modeBlock, []string{"192.168.5.0/24:443"}, true},
		{"block CIDR 与外网段不命中", "192.168.0.0/16:443", modeBlock, []string{"10.0.0.0/8:443"}, false},
		{"block IPv6 命中", "[::1]:8080", modeBlock, []string{"[::1]:8080"}, true},
		// allow = 包含语义
		{"allow 单端口相等命中", "1.2.3.4:8080", modeAllow, []string{"1.2.3.4:8080"}, true},
		{"allow 区间包含候选命中", "1.2.3.4:8000-9000", modeAllow, []string{"1.2.3.4:8500-8600"}, true},
		{"allow 候选超区间不命中", "1.2.3.4:8000-9000", modeAllow, []string{"1.2.3.4:8000-9500"}, false},
		{"allow 全端口候选不放行", "1.2.3.4:8080", modeAllow, []string{"1.2.3.4:*"}, false},
		{"allow 无端口语义候选不放行", "1.2.3.4:8080", modeAllow, []string{"1.2.3.4"}, false},
		{"allow 多端口须全覆盖", "1.2.3.4:8000-9000", modeAllow, []string{"1.2.3.4:8000,9000"}, true},
		{"allow 多端口超界不命中", "1.2.3.4:8000-9000", modeAllow, []string{"1.2.3.4:8000,9090"}, false},
		{"allow CIDR 覆盖 IP 命中", "192.168.0.0/16:443", modeAllow, []string{"192.168.5.20:443"}, true},
		{"allow CIDR 外 IP 不命中", "192.168.0.0/16:443", modeAllow, []string{"10.0.0.5:443"}, false},
		{"allow 候选网段⊆规则网段命中", "192.168.0.0/16:443", modeAllow, []string{"192.168.5.0/24:443"}, true},
		{"allow 候选网段⊄规则网段不命中", "192.168.5.0/24:443", modeAllow, []string{"192.168.0.0/16:443"}, false},
		{"allow IPv6 包含命中", "[::1]:8080", modeAllow, []string{"[::1]:8080"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := rule("host_port", c.rule, true)
			if _, ok := matchOneOn(r, gt(c.cands...), c.mode); ok != c.want {
				t.Fatalf("rule=%s cands=%v mode=%d: got %v want %v", c.rule, c.cands, c.mode, ok, c.want)
			}
		})
	}
}

func TestEvaluateAssetGateOn(t *testing.T) {
	// 纯 host_port 白名单：显式访问允许端口放行；其他端口拒；无端口命令拒。
	allow := []AssetInterceptRule{rule("host_port", "127.0.0.1:8080", true)}

	if d := EvaluateAssetGateOn(nil, allow, GateTargets{
		IPs: []string{"127.0.0.1"}, HostPorts: []string{"127.0.0.1:8080"},
	}); !d.Allowed {
		t.Fatalf("显式访问允许端口应放行: %+v", d)
	}
	if d := EvaluateAssetGateOn(nil, allow, GateTargets{
		IPs: []string{"127.0.0.1"}, HostPorts: []string{"127.0.0.1:9090"},
	}); d.Allowed {
		t.Fatal("访问其他端口应被拒")
	}
	if d := EvaluateAssetGateOn(nil, allow, GateTargets{IPs: []string{"127.0.0.1"}}); d.Allowed {
		t.Fatal("纯 host_port 白名单下无端口候选应被拒")
	}

	// 老规则语义不变：裸 host 白名单 + 带 URL 目标（URL host 拆入裸候选）照旧命中。
	allowHost := []AssetInterceptRule{rule("exact_ip", "127.0.0.1", true)}
	if d := EvaluateAssetGateOn(nil, allowHost, GateTargets{
		IPs: []string{"127.0.0.1"}, URLs: []string{"http://127.0.0.1:9090/"},
	}); !d.Allowed {
		t.Fatalf("裸 IP 白名单应放行同主机任意端口: %+v", d)
	}

	// allow cidr：目标网段须 ⊆ 规则网段；网段外 IP 拒。
	allowCIDR := []AssetInterceptRule{rule("cidr", "10.0.0.0/16", true)}
	if d := EvaluateAssetGateOn(nil, allowCIDR, GateTargets{CIDRs: []string{"10.0.1.0/24"}}); !d.Allowed {
		t.Fatalf("目标网段 ⊆ 允许网段应放行: %+v", d)
	}
	if d := EvaluateAssetGateOn(nil, allowCIDR, GateTargets{IPs: []string{"192.168.1.1"}}); d.Allowed {
		t.Fatal("网段外 IP 应被拒")
	}

	// block host_port 重叠即拒，即使 allow 也覆盖（block 优先）。
	block := []AssetInterceptRule{rule("host_port", "1.2.3.4:8080", true)}
	allow2 := []AssetInterceptRule{rule("host_port", "1.2.3.4:8000-9000", true)}
	if d := EvaluateAssetGateOn(block, allow2, GateTargets{HostPorts: []string{"1.2.3.4:8080"}}); d.Allowed {
		t.Fatal("block 重叠应优先于 allow")
	}

	// 空 allow 放行回归（白名单未启用）。
	if d := EvaluateAssetGateOn(nil, nil, GateTargets{IPs: []string{"9.9.9.9"}}); !d.Allowed {
		t.Fatal("无规则应放行")
	}
}

func TestHostPortLabel(t *testing.T) {
	if got := AssetInterceptKindLabel("host_port"); got != "主机+端口" {
		t.Fatalf("host_port label = %q", got)
	}
}

func TestInterceptCandidatesHostPorts(t *testing.T) {
	port := 8080
	a := &Asset{Type: "ip", IP: "1.2.3.4", Port: &port, OpenPorts: []map[string]any{{"port": float64(443)}}}
	tgt := a.interceptCandidates()
	if len(tgt.HostPorts) != 2 {
		t.Fatalf("应产出 2 个 host:port 候选（Port+OpenPorts），got %v", tgt.HostPorts)
	}
	// host:port 候选可被 host_port 白名单命中。
	if _, _, ok := matchAssetInterceptRulesOn(
		[]AssetInterceptRule{rule("host_port", "1.2.3.4:443", true)}, tgt, modeAllow,
	); !ok {
		t.Fatalf("资产 host:port 候选应被 host_port 规则命中: %v", tgt.HostPorts)
	}
	// 裸 IP 候选照旧存在（不带端口的老规则语义不变）。
	if _, _, ok := matchAssetInterceptRulesOn(
		[]AssetInterceptRule{rule("exact_ip", "1.2.3.4", true)}, tgt, modeAllow,
	); !ok {
		t.Fatalf("裸 IP 候选应照旧命中 exact_ip: %v", tgt.IPs)
	}
}
