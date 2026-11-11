package guard

import (
	"strings"
	"testing"
)

// targetsKey 把提取结果压成可比较的 "host|port" 集合串（顺序无关）。
func targetsKey(ts []Target) string {
	if len(ts) == 0 {
		return "(none)"
	}
	keys := map[string]bool{}
	for _, t := range ts {
		keys[t.Host+"|"+t.Port] = true
	}
	var out []string
	for k := range keys {
		out = append(out, k)
	}
	// 排序保证输出稳定
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return strings.Join(out, ",")
}

func TestExtractCommandTargets(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want string // targetsKey 形态；多个候选用逗号分隔
	}{
		{"curl 带端口 URL", "curl http://a.com:8080/x", "a.com|8080"},
		{"curl 无端口 URL 合成默认端口", "curl http://1.2.3.4/x", "1.2.3.4|80"},
		{"https 默认端口", "curl https://example.com/api", "example.com|443"},
		{"curl 显式 IP 端口", "curl http://127.0.0.1:9090/", "127.0.0.1|9090"},
		{"nmap 无 -p 全端口保守", "nmap -sV 10.0.0.5", "10.0.0.5|*"},
		{"nmap -p- 全端口", "nmap -sV -p- 10.0.0.5", "10.0.0.5|*"},
		{"nmap -p 指定端口", "nmap -sV -p 8080 10.0.0.5", "10.0.0.5|8080"},
		{"nmap -p 组合端口", "nmap -p 80,443,8000-9000 10.0.0.5", "10.0.0.5|80,443,8000-9000"},
		{"nmap -p 附值形态", "nmap -p8080 10.0.0.5", "10.0.0.5|8080"},
		{"nmap CIDR 目标", "nmap -sV 192.168.1.0/24", "192.168.1.0/24|*"},
		{"ffuf -u 目标", "ffuf -u http://10.0.0.5:8080/FUZZ -w words.txt", "10.0.0.5|8080"},
		{"ffuf -w 文件不是目标", "ffuf -u http://10.0.0.5:8080/FUZZ -w /usr/share/wordlists/common.txt", "10.0.0.5|8080"},
		{"wget -O 输出文件不是目标", "wget -O out.html https://example.com/page", "example.com|443"},
		{"echo 无目标", "echo hi", "(none)"},
		{"echo 提及文件无目标", "echo index.html nginx.conf main.go words.txt out.txt", "(none)"},
		{"ping 裸主机", "ping -c 2 web01.corp.com", "web01.corp.com|"},
		{"curl localhost 端口", "curl localhost:8080/health", "localhost|8080"},
		{"sqlmap -u", "sqlmap -u 'http://target.example.com/item.php?id=1' --batch", "target.example.com|80"},
		{"naabu -host", "naabu -host 10.0.0.5 -p 80,443", "10.0.0.5|80,443"},
		{"管道分段 curl", "curl -s http://10.1.1.1:80/ | grep title", "10.1.1.1|80"},
		{"多命令分段", "nmap -p 80 10.0.0.1; curl http://10.0.0.2:8080/", "10.0.0.1|80,10.0.0.2|8080"},
		{"curl -x 代理不算目标", "curl -x http://127.0.0.1:8080 http://10.9.9.9/", "10.9.9.9|80"},
		{"curl -H 头里的域名不算目标", "curl -H 'Host: evil.example.com' http://10.9.9.9/", "10.9.9.9|80"},
		{"环境变量前缀不影响工具识别", "FOO=bar curl http://10.9.9.9:8080/", "10.9.9.9|8080"},
		{"sudo 前缀不影响工具识别", "sudo nmap -p 443 10.9.9.9", "10.9.9.9|443"},
		{"未知工具整段 T1 URL", "python3 -c \"import requests; requests.get('http://10.7.7.7:9090/api')\"", "10.7.7.7|9090"},
		{"shell 变量引用提不出", "curl \"$TARGET\"", "(none)"},
		{"引号包裹的目标", "curl 'http://10.8.8.8:7070/'", "10.8.8.8|7070"},
		{"文件输出重定向目标不误报", "nmap -oG out.txt -p 80 10.3.3.3", "10.3.3.3|80"},
		// --- 误报修复回归（2026-11-11 线上两次误拦）---
		{"curl -X POST 方法旗标值不是目标", "curl -s -m 10 -i -X POST http://10.9.9.9/x", "10.9.9.9|80"},
		{"引号内空格的头是整体不是孤立词", "curl -H 'Accept: application' http://10.9.9.9/", "10.9.9.9|80"},
		{"引号内管道不切段", "curl 'http://10.8.8.8:7070/a|b'", "10.8.8.8|7070"},
		{"nmap --script 脚本名不是目标", "nmap --script http-vuln-cve2017-5638 -p 8080 10.3.3.3", "10.3.3.3|8080"},
		{"nmap --script-args 值不是目标", "nmap --script-args 'a=1,b=2' -p 443 10.3.3.3", "10.3.3.3|443"},
		{"nc host port 位置对", "nc 10.3.3.3 8080", "10.3.3.3|8080"},
		{"nc -p 端口前缀", "nc -p 8080 10.3.3.3", "10.3.3.3|8080"},
		{"telnet host port 位置对", "telnet 10.3.3.3 25", "10.3.3.3|25"},
		{"wget -O 无扩展名输出文件不是目标", "wget -O out https://example.com/page", "example.com|443"},
		{"hydra -p 密码旗标值不是目标", "hydra -l admin -p pass123 10.3.3.3", "10.3.3.3|"},
		{"全大写常量词不是主机", "curl --retry-max-time POST http://10.9.9.9/", "10.9.9.9|80"},
		// --- 相邻端口合成（heredoc/脚本源码形态；T1 裸 IP 需目标语境才提取）---
		{"Python 赋值 IP 后逗号端口", `host, port = "10.10.5.238", 9001`, "10.10.5.238|9001"},
		{"函数调用元组 IP 后逗号端口", `func_call(("10.0.0.5", 9090))`, "10.0.0.5|9090"},
		{"非法端口范围不合成", `host, port = "10.0.0.5", 70000`, "10.0.0.5|"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := targetsKey(ExtractCommandTargets(c.cmd))
			if got != c.want {
				t.Fatalf("cmd=%q\n  got  %s\n  want %s", c.cmd, got, c.want)
			}
		})
	}
}

func TestExtractTargetsByTool(t *testing.T) {
	// Bash: 从 command 字段提取
	bash := []byte(`{"command":"curl http://10.1.1.1:8080/","description":"probe"}`)
	if got := targetsKey(ExtractTargets("Bash", bash)); got != "10.1.1.1|8080" {
		t.Fatalf("Bash 提取 = %s", got)
	}
	// shell_open 同样走 command
	so := []byte(`{"command":"nmap -p 80 10.1.1.1"}`)
	if got := targetsKey(ExtractTargets("shell_open", so)); got != "10.1.1.1|80" {
		t.Fatalf("shell_open 提取 = %s", got)
	}
	// shell_send 走 text
	ss := []byte(`{"text":"curl http://10.1.1.1:9090/x"}`)
	if got := targetsKey(ExtractTargets("shell_send", ss)); got != "10.1.1.1|9090" {
		t.Fatalf("shell_send 提取 = %s", got)
	}
	// WebFetch：整个 input JSON 走 T1，不依赖字段名
	wf := []byte(`{"url":"https://example.com:8443/admin","prompt":"fetch the page"}`)
	if got := targetsKey(ExtractTargets("WebFetch", wf)); got != "example.com|8443" {
		t.Fatalf("WebFetch 提取 = %s", got)
	}
	// 非清单工具不提取
	if got := ExtractTargets("record_fact", []byte(`{"note":"see http://10.1.1.1:8080"}`)); got != nil {
		t.Fatalf("非清单工具不应提取目标: %v", got)
	}
}

func TestExtractURLTarget(t *testing.T) {
	cases := []struct {
		raw            string
		host, url, prt string
		ok             bool
	}{
		{"http://1.2.3.4:8080/x", "1.2.3.4", "http://1.2.3.4:8080/x", "8080", true},
		{"http://1.2.3.4/x", "1.2.3.4", "http://1.2.3.4/x", "80", true},
		{"https://a.com", "a.com", "https://a.com", "443", true},
		{"http://1.2.3.4:8080/x。", "1.2.3.4", "http://1.2.3.4:8080/x", "8080", true},
		{"ftp://1.2.3.4/x", "", "", "", false},
		{"/just/a/path", "", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			got, ok := ExtractURLTarget(c.raw)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, c.ok, got)
			}
			if ok && (got.Host != c.host || got.URL != c.url || got.Port != c.prt) {
				t.Fatalf("got (%q,%q,%q), want (%q,%q,%q)", got.Host, got.URL, got.Port, c.host, c.url, c.prt)
			}
		})
	}
}

func TestGateTargetsOf(t *testing.T) {
	// 带端口目标：裸 host + host:port 双候选（老规则与新 host_port 规则都能命中）。
	g := gateTargetsOf(Target{Host: "1.2.3.4", Port: "8080"})
	if len(g.IPs) != 1 || g.IPs[0] != "1.2.3.4" || len(g.HostPorts) != 1 || g.HostPorts[0] != "1.2.3.4:8080" {
		t.Fatalf("gateTargetsOf(IP+port) = %+v", g)
	}
	// 无端口语义：只产出裸候选。
	g = gateTargetsOf(Target{Host: "web01.corp.com"})
	if len(g.Domains) != 1 || len(g.HostPorts) != 0 {
		t.Fatalf("gateTargetsOf(bare host) = %+v", g)
	}
	// "*" 不产出 host:port 候选（范围未知，白名单方向无法证明包含）。
	g = gateTargetsOf(Target{Host: "10.0.0.5", Port: "*"})
	if len(g.HostPorts) != 0 || len(g.IPs) != 1 {
		t.Fatalf("gateTargetsOf(wild port) = %+v", g)
	}
	// CIDR 目标进 CIDRs。
	g = gateTargetsOf(Target{Host: "10.0.0.0/24"})
	if len(g.CIDRs) != 1 || len(g.IPs) != 0 {
		t.Fatalf("gateTargetsOf(cidr) = %+v", g)
	}
	// IPv6 端口候选走 JoinHostPort 括号规范。
	g = gateTargetsOf(Target{Host: "::1", Port: "8080"})
	if len(g.HostPorts) != 1 || g.HostPorts[0] != "[::1]:8080" {
		t.Fatalf("gateTargetsOf(ipv6) = %+v", g)
	}
}
