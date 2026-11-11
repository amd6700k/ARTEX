package guard

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// 目标提取与任务白名单判定。
//
// 提取分三层（尽力而为的策略闸门，不是防绕过的安全边界）：
//   T1 高置信（任意文本）：https?:// URL（按 scheme 合成默认端口）、CIDR 串、
//      显式 host:port（域名要求常见 TLD，防 index.html 之类文件名误命中）。
//   T2 工具上下文：按 shell 分段（| / && / ; / 换行）逐段查已知工具表，
//      提取位置参数与 -u/--url、-host 等旗标承载的裸 IP/域名目标；
//      -p/--port 的端口说明赋给同段目标；多端口扫描工具无 -p 时记 Port="*"。
//   T3 提不出：放行（白名单启用时由调用方记 debug 日志）。

// Target 是从工具调用里提取到的一个测试目标。
// Port 语义：""=无端口语义（裸主机）| "8080" | "8000-9000" | "80,443" | "*"(范围未知)。
type Target struct {
	Host string // IP / 域名 / CIDR（IPv6 去括号）；URL 目标同时填 host
	URL  string // 完整 URL（仅 URL 目标非空）
	Port string
	Raw  string // 原始串
}

func (t Target) display() string {
	if t.URL != "" {
		return t.URL
	}
	if t.Port == "" {
		return t.Host
	}
	if strings.Contains(t.Host, ":") && net.ParseIP(t.Host) != nil {
		return "[" + t.Host + "]:" + t.Port
	}
	return t.Host + ":" + t.Port
}

var (
	reURL       = regexp.MustCompile(`https?://[^\s'"<>]+`)
	reIPv4CIDR  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b`)
	reIPv6CIDR  = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:]{0,4}/\d{1,3}\b`)
	reIPv4Port  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b`)
	reIPv6Port  = regexp.MustCompile(`\[[0-9A-Fa-f:.]+\]:\d{1,5}`)
	reDomainPort = regexp.MustCompile(`\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}:\d{1,5}\b`)
	reIPv4      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

// tlds 是 T1 提取 domain:port 与裸域名时接受的常见顶级域白名单（防 main.go:8080、
// nginx.conf:80、words.txt 之类的文件名/日志行被误当目标）。
var tlds = map[string]bool{
	"com": true, "net": true, "org": true, "edu": true, "gov": true, "mil": true,
	"int": true, "info": true, "biz": true, "xyz": true, "top": true, "site": true,
	"online": true, "store": true, "tech": true, "cloud": true, "app": true,
	"dev": true, "io": true, "ai": true, "co": true, "cn": true, "jp": true,
	"kr": true, "us": true, "uk": true, "de": true, "fr": true, "es": true,
	"it": true, "nl": true, "se": true, "no": true, "fi": true, "dk": true,
	"pl": true, "cz": true, "pt": true, "ru": true, "ua": true, "br": true,
	"ar": true, "cl": true, "mx": true, "in": true, "id": true, "sg": true,
	"hk": true, "tw": true, "au": true, "nz": true, "ca": true, "ch": true,
	"at": true, "be": true, "ie": true, "is": true, "th": true, "vn": true,
	"my": true, "ph": true, "ir": true, "il": true, "tr": true, "sa": true,
	"ae": true, "me": true, "tv": true, "cc": true, "sh": true, "so": true,
}

// toolSpec 描述一个已知命令行工具如何承载目标。
type toolSpec struct {
	positional bool // 位置参数是目标
	urlFlag    bool // -u/--url 承载目标
	hostFlag   bool // -host/--host 承载目标
	portFlag   bool // -p/--port 承载端口说明
	multiPort  bool // 无 -p 时按全端口处理（Port="*"，保守）
}

// specIsKnown 区分「已登记工具」（走 T2 token 级提取）与未知工具（整段 T1）。
func specIsKnown(s toolSpec) bool {
	return s.positional || s.urlFlag || s.hostFlag || s.portFlag
}

var commandTools = map[string]toolSpec{
	"curl":        {positional: true},
	"wget":        {positional: true},
	"nc":          {positional: true},
	"ncat":        {positional: true},
	"netcat":      {positional: true},
	"socat":       {positional: true},
	"openssl":     {positional: true},
	"ping":        {positional: true},
	"dig":         {positional: true},
	"nslookup":    {positional: true},
	"host":        {positional: true},
	"whois":       {positional: true},
	"traceroute":  {positional: true},
	"nmap":        {positional: true, portFlag: true, multiPort: true},
	"masscan":     {positional: true, portFlag: true, multiPort: true},
	"naabu":       {positional: true, portFlag: true, multiPort: true, hostFlag: true},
	"rustscan":    {positional: true, portFlag: true, multiPort: true},
	"unicornscan": {positional: true, portFlag: true, multiPort: true},
	"sqlmap":      {positional: true, urlFlag: true},
	"nikto":       {positional: true, hostFlag: true, portFlag: true},
	"whatweb":     {positional: true},
	"dirb":        {positional: true},
	"hydra":       {positional: true},
	"medusa":      {positional: true, hostFlag: true},
	"testssl.sh":  {positional: true},
	"sslscan":     {positional: true},
	"ffuf":        {urlFlag: true},
	"gobuster":    {urlFlag: true},
	"dirsearch":   {urlFlag: true},
	"wfuzz":       {urlFlag: true},
	"feroxbuster": {urlFlag: true},
	"httpx":       {positional: true, urlFlag: true},
	"nuclei":      {positional: true, urlFlag: true},
	"enum4linux":  {positional: true},
	"smbclient":   {positional: true},
	"telnet":      {positional: true},
	"ssh":         {positional: true},
	"ftp":         {positional: true},
}

// skipNextFlags 是「下一 token 是值、不是目标」的旗标。短旗标按前缀匹配
// （-o 覆盖 nmap 的 -oN/-oG/-oX/-oA）。刻意不收录 -n/-f/-r 这类多义短旗标：
// 吞掉后面的真实目标（如 nmap -n 1.2.3.4）比误提取更糟。
var skipNextFlags = []string{
	"-o", "--output", "-w", "--wordlist", "-D", "--dump-header",
	"-c", "--cookie", "-b", "-F", "--form", "-T", "--upload-file",
	"--resolve", "--connect-to", "-A", "--user-agent",
	"-H", "--header", "-d", "--data", "--data-raw", "--data-binary",
	"-l", "--list", "-iL", "--url-file", "-x", "--proxy", "-e", "--interface",
	"--auth", "--auth-file", "--ca-file", "--header-file",
}

// ExtractTargets 按工具名从 PreToolUse 的 input JSON 里提取目标。
// 仅处理 Bash/shell_open（command）、shell_send（text）、WebFetch（input 内 URL）。
func ExtractTargets(toolName string, input json.RawMessage) []Target {
	var text string
	switch toolName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(input, &in) != nil {
			return nil
		}
		text = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(input, &in) != nil {
			return nil
		}
		text = in.Text
	case "WebFetch":
		// 不依赖具体字段名：整个 input JSON 走 T1（URL 高置信正则）。
		return ExtractTextTargets(string(input))
	default:
		return nil
	}
	if strings.TrimSpace(text) == "" {
		return nil
	}
	return ExtractCommandTargets(text)
}

// ExtractCommandTargets 从一条 shell 命令里提取目标：先按 | / && / ; / 换行分段，
// 已知工具走 T2（token 级，旗标值不误判），未知工具整段走 T1（高置信正则兜底）。
func ExtractCommandTargets(cmd string) []Target {
	var out []Target
	repl := strings.NewReplacer("&&", "\n", "||", "\n", "|", "\n", ";", "\n")
	for _, seg := range strings.Split(repl.Replace(cmd), "\n") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		out = append(out, extractSegmentTargets(seg)...)
	}
	return dedupe(out)
}

// segmentState 记录一段命令内的提取状态。
type segmentState struct {
	spec     toolSpec
	hasPort  bool   // 本段已出现 -p/--port
	pendPort string // 待赋给下一个目标的端口说明（来自 -p）
}

// extractSegmentTargets 提取单段命令的目标。
func extractSegmentTargets(seg string) []Target {
	toks := strings.Fields(seg)
	if len(toks) == 0 {
		return nil
	}
	spec, rest := lookupTool(toks)
	st := &segmentState{spec: spec}
	var out []Target
	if specIsKnown(spec) {
		for i := rest; i < len(toks); i++ {
			tok := stripQuotes(toks[i])
			if tok == "" {
				continue
			}
			if strings.HasPrefix(tok, "-") {
				if n := handleFlag(tok, toks, i, st, &out); n > 0 && i+1 < len(toks) {
					i++
				}
				continue
			}
			if t, ok := classifyArg(tok, st); ok {
				out = append(out, t)
			}
		}
		// 多端口扫描工具的端口语义回填：无 -p → 范围未知（保守按全端口 "*"）；
		// 有 -p 但目标出现在 -p 之前（如 naabu -host X -p 80,443）→ 回填端口说明。
		if st.spec.multiPort && !st.hasPort {
			for j := range out {
				if out[j].Port == "" {
					out[j].Port = "*"
				}
			}
		} else if st.spec.multiPort && st.hasPort && st.pendPort != "*" {
			for j := range out {
				if out[j].Port == "" {
					out[j].Port = st.pendPort
				}
			}
		}
		return dedupe(out)
	}
	// 未知工具（python -c、脚本等）：整段文本走 T1 高置信兜底。
	return extractTextTargets(seg)
}

// lookupTool 找出命令词及其工具规格，返回参数区起始下标。
// 跳过前导 sudo/env/nice 等包装器与 VAR=xxx 环境变量赋值；工具名取 basename。
func lookupTool(toks []string) (toolSpec, int) {
	for i, tok := range toks {
		if isWrapper(tok) {
			continue
		}
		if !strings.HasPrefix(tok, "-") && strings.Contains(tok, "=") {
			continue // VAR=val 赋值前缀
		}
		if s, ok := commandTools[baseName(tok)]; ok {
			return s, i + 1
		}
		return toolSpec{}, i + 1 // 未知工具
	}
	return toolSpec{}, len(toks)
}

func isWrapper(tok string) bool {
	switch strings.ToLower(baseName(tok)) {
	case "sudo", "env", "nice", "nohup", "time", "timeout", "stdbuf", "setsid", "xargs":
		return true
	}
	return false
}

func baseName(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

func stripQuotes(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		s = s[1 : len(s)-1]
	}
	return s
}

// handleFlag 处理一个旗标 token，返回额外消费的 token 数（0 或 1）。
func handleFlag(tok string, toks []string, i int, st *segmentState, out *[]Target) int {
	next := func() string {
		if i+1 < len(toks) {
			return stripQuotes(toks[i+1])
		}
		return ""
	}
	// --flag=value / -p8080 附值形态
	attached := ""
	if strings.HasPrefix(tok, "--") {
		if eq := strings.Index(tok, "="); eq >= 0 {
			attached = tok[eq+1:]
			tok = tok[:eq]
		}
	} else if k, rest := splitAttachedShort(tok); rest != "" {
		tok, attached = k, rest
	}
	switch {
	case st.spec.portFlag && (tok == "-p" || tok == "--port"):
		st.hasPort = true
		if attached != "" {
			st.pendPort = normalizePortSpec(attached)
			return 0
		}
		st.pendPort = normalizePortSpec(next())
		return 1
	case st.spec.urlFlag && (tok == "-u" || tok == "--url"):
		v, n := attached, 0
		if v == "" {
			v = next()
			n = 1
		}
		if t, ok := ExtractURLTarget(v); ok {
			*out = append(*out, t)
		}
		return n
	case st.spec.hostFlag && (tok == "-host" || tok == "--host" || tok == "--hostname"):
		v, n := attached, 0
		if v == "" {
			v = next()
			n = 1
		}
		if t, ok := classifyArg(v, st); ok {
			*out = append(*out, t)
		}
		return n
	}
	for _, f := range skipNextFlags {
		if tok == f || (strings.HasPrefix(tok, f) && !strings.HasPrefix(tok, "--")) {
			if attached != "" {
				return 0 // -oGxxx 之类附值已内联
			}
			return 1
		}
	}
	return 0 // 未知旗标：按无值布尔处理
}

// splitAttachedShort 拆出已知短旗标的附值："-p8080" → ("-p", "8080")；
// 未登记的（-sV 等）不拆（返回 rest=""），按无值布尔处理。
func splitAttachedShort(tok string) (string, string) {
	if len(tok) <= 2 || strings.HasPrefix(tok, "--") {
		return tok, ""
	}
	k := tok[:2]
	switch k {
	case "-p", "-u":
		return k, tok[2:]
	}
	for _, f := range skipNextFlags {
		if f == k {
			return k, tok[2:]
		}
	}
	return tok, ""
}

// normalizePortSpec 归一 -p 的端口说明："8080" 原样；"-"/"*" 全端口 → "*"；
// 解析不了的（如 nmap -pT:80）→ "*"（范围未知，保守）。
func normalizePortSpec(spec string) string {
	spec = strings.TrimSpace(stripQuotes(spec))
	if spec == "" || spec == "*" || spec == "-" {
		return "*"
	}
	for _, part := range strings.Split(spec, ",") {
		if _, _, err := parsePortRange(part); err != nil {
			return "*"
		}
	}
	return spec
}

// parsePortRange 解析 "80" 或 "8000-9000"。
func parsePortRange(spec string) (int, int, error) {
	spec = strings.TrimSpace(spec)
	loS, hiS := spec, spec
	if i := strings.Index(spec, "-"); i >= 0 {
		loS, hiS = spec[:i], spec[i+1:]
	}
	lo, err := strconv.Atoi(strings.TrimSpace(loS))
	if err != nil {
		return 0, 0, err
	}
	hi, err := strconv.Atoi(strings.TrimSpace(hiS))
	if err != nil {
		return 0, 0, err
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, strconv.ErrRange
	}
	return lo, hi, nil
}

// classifyArg 把一个位置参数 token 归类为 Target。
func classifyArg(tok string, st *segmentState) (Target, bool) {
	tok = stripQuotes(tok)
	if tok == "" || strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "$") {
		return Target{}, false
	}
	if strings.ContainsAny(tok, " =") || strings.HasPrefix(tok, "/") || strings.HasPrefix(tok, ".") {
		return Target{}, false
	}
	port := st.pendPort
	// URL
	if reURL.MatchString(tok) {
		if t, ok := ExtractURLTarget(tok); ok {
			return t, true
		}
	}
	// CIDR / 带 path 的 host:port
	if strings.Contains(tok, "/") {
		if _, _, err := net.ParseCIDR(tok); err == nil {
			return Target{Host: tok, Port: port, Raw: tok}, true
		}
		// localhost:8080/health 之类：剥掉路径后按 host[:port] 继续分类
		if i := strings.Index(tok, "/"); i > 0 {
			tok = tok[:i]
		} else {
			return Target{}, false
		}
	}
	// IPv4:port
	if reIPv4Port.MatchString(tok) {
		if i := strings.LastIndex(tok, ":"); i > 0 {
			return Target{Host: tok[:i], Port: tok[i+1:], Raw: tok}, true
		}
	}
	// [IPv6]:port
	if strings.HasPrefix(tok, "[") && strings.HasSuffix(tok, "]") {
		h := strings.TrimSuffix(strings.TrimPrefix(tok, "["), "]")
		if net.ParseIP(h) != nil {
			return Target{Host: h, Port: port, Raw: tok}, true
		}
		return Target{}, false
	}
	// 裸 IP（含 IPv6）
	if net.ParseIP(tok) != nil {
		return Target{Host: tok, Port: port, Raw: tok}, true
	}
	// domain:port（域名含单标签如 localhost）
	if i := strings.LastIndex(tok, ":"); i > 0 && strings.Count(tok, ":") == 1 {
		h, p := tok[:i], tok[i+1:]
		if isAllDigits(p) && looksLikeHost(h) {
			return Target{Host: h, Port: p, Raw: tok}, true
		}
	}
	// 裸域名/主机名（须像主机名且不像文件/路径）
	if looksLikeHost(tok) {
		return Target{Host: tok, Port: port, Raw: tok}, true
	}
	return Target{}, false
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// looksLikeHost 判断是否像目标主机：有字母、可含点/连字符/下划线（单标签如
// localhost、web01 也算）；不含冒号；点分形态要求最后一个标签（TLD）在白名单内，
// 以排除 out.txt / words.txt / main.go / nginx.conf 等文件名。
func looksLikeHost(s string) bool {
	if s == "" || len(s) < 3 || len(s) > 253 {
		return false
	}
	hasLetter := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	if !hasLetter {
		return false
	}
	if i := strings.LastIndex(s, "."); i >= 0 {
		if !tlds[strings.ToLower(s[i+1:])] {
			return false
		}
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" {
			return false
		}
	}
	return true
}

// extractTextTargets 对任意文本跑 T1 高置信提取（URL/CIDR/host:port）。
func extractTextTargets(text string) []Target {
	var out []Target
	add := func(t Target) {
		if t.Host == "" && t.URL == "" {
			return
		}
		out = append(out, t)
	}
	for _, m := range reURL.FindAllString(text, -1) {
		if t, ok := ExtractURLTarget(m); ok {
			add(t)
		}
	}
	for _, m := range reIPv4CIDR.FindAllString(text, -1) {
		if _, _, err := net.ParseCIDR(m); err == nil {
			add(Target{Host: m, Raw: m})
		}
	}
	for _, m := range reIPv6CIDR.FindAllString(text, -1) {
		if strings.Count(m, ":") >= 2 {
			if _, _, err := net.ParseCIDR(m); err == nil {
				add(Target{Host: m, Raw: m})
			}
		}
	}
	for _, m := range reIPv4Port.FindAllString(text, -1) {
		if i := strings.LastIndex(m, ":"); i > 0 {
			add(Target{Host: m[:i], Port: m[i+1:], Raw: m})
		}
	}
	for _, m := range reIPv6Port.FindAllString(text, -1) {
		if i := strings.LastIndex(m, ":"); i > 0 {
			h := strings.TrimSuffix(strings.TrimPrefix(m[:i], "["), "]")
			if net.ParseIP(h) != nil {
				add(Target{Host: h, Port: m[i+1:], Raw: m})
			}
		}
	}
	for _, m := range reDomainPort.FindAllString(text, -1) {
		if i := strings.LastIndex(m, ":"); i > 0 {
			h, p := m[:i], m[i+1:]
			if tldOK(h) {
				add(Target{Host: strings.TrimSuffix(h, "."), Port: p, Raw: m})
			}
		}
	}
	// 裸 IPv4：仅在文本带目标语境（已提取到其他目标，或出现已知工具名）时提取，
	// 避免把普通文本里的版本号/数字误当目标；已被 URL/host:port 覆盖的主机不重复提取
	//（同一主机拆出「无端口」候选会让白名单方向无法证明包含而误拒）。
	if len(out) > 0 || hasContextHint(text) {
		for _, m := range reIPv4.FindAllString(text, -1) {
			if net.ParseIP(m) == nil {
				continue
			}
			dup := false
			for _, prev := range out {
				if prev.Host == m {
					dup = true
					break
				}
			}
			if !dup {
				add(Target{Host: m, Raw: m})
			}
		}
	}
	return dedupe(out)
}

// hasContextHint 判断文本里是否有目标语境（已知工具名出现）。
func hasContextHint(text string) bool {
	for name := range commandTools {
		if strings.Contains(text, name) {
			return true
		}
	}
	return false
}

// tldOK 校验域名最后一个标签在常见 TLD 白名单内。
func tldOK(domain string) bool {
	i := strings.LastIndex(domain, ".")
	if i < 0 {
		return false
	}
	return tlds[strings.ToLower(domain[i+1:])]
}

// ExtractTextTargets 是 extractTextTargets 的导出形式，供自定义工具执行点
// （server/customtool.go）对脚本代码/参数做 T1 级提取。
func ExtractTextTargets(text string) []Target {
	return extractTextTargets(text)
}

// ExtractURLTarget 解析一个 URL 串为 Target（scheme 决定默认端口，参照
// server.parseTarget 的端口语义：http→80、https→443）。
func ExtractURLTarget(raw string) (Target, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimRight(raw, ".,;:)]}'\"。，、；：！？）】》") // 去掉句尾标点（含全角）
	if raw == "" {
		return Target{}, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return Target{}, false
	}
	if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		return Target{}, false
	}
	host := u.Hostname()
	if host == "" {
		return Target{}, false
	}
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "http") {
			port = "80"
		} else {
			port = "443"
		}
	}
	return Target{Host: host, URL: raw, Port: port, Raw: raw}, true
}

// dedupe 按 display+port 去重，保持顺序。
func dedupe(in []Target) []Target {
	seen := map[string]bool{}
	var out []Target
	for _, t := range in {
		key := t.display() + "|" + t.Port
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

// gateTargetsOf 把一个 Target 转成闸门候选集：裸 host 进 IPs/Domains/CIDRs
// （不带端口的老规则照旧命中）；带端口语义时额外产出 host:port 候选。
func gateTargetsOf(t Target) db.GateTargets {
	var g db.GateTargets
	if t.URL != "" {
		g.URLs = []string{t.URL}
	}
	h := strings.TrimSpace(t.Host)
	if h == "" {
		return g
	}
	if strings.Contains(h, "/") {
		if _, _, err := net.ParseCIDR(h); err == nil {
			g.CIDRs = []string{h}
		} else {
			return g
		}
	} else if net.ParseIP(h) != nil {
		g.IPs = []string{h}
	} else {
		g.Domains = []string{h}
	}
	if t.Port != "" && t.Port != "*" {
		g.HostPorts = append(g.HostPorts, net.JoinHostPort(h, t.Port))
	}
	return g
}

// CheckTargetsForTask 对提取出的目标执行任务白名单判定。
// taskID<=0 / 无启用规则 → 放行（零开销短路）；规则读取失败 → 放行
// （fail-open，与 insert_assets 资产闸门一致）。denied 时 denyReason 以
// [任务白名单] 开头（interceptSource 据此归因为规则来源），包含被拒目标、
// 当前启用的允许规则列表与引导语，供 agent 自我改写。
func CheckTargetsForTask(as *db.AssetStore, taskID int64, targets []Target) (denyReason string, denied bool, err error) {
	if taskID <= 0 || as == nil || len(targets) == 0 {
		return "", false, nil
	}
	block, allow, err := as.LoadTaskGateRules(taskID)
	if err != nil {
		// 规则读取失败不阻断（防误伤优先），与 agent/tools_insert.go 的闸门同策略。
		slog.Debug("guard: 任务白名单规则读取失败，放行", "taskID", taskID, "err", err)
		return "", false, nil
	}
	reason, denied := checkTargetsOnRules(block, allow, targets)
	return reason, denied, nil
}

// checkTargetsOnRules 是判定核心：对预载入的 block/allow 规则集逐目标评估。
// 任一目标被拒即拒。规则集为空（无 block 且无启用 allow）→ 放行。
func checkTargetsOnRules(block, allow []db.AssetInterceptRule, targets []Target) (denyReason string, denied bool) {
	if len(targets) == 0 || (len(block) == 0 && !db.HasEnabledRule(allow)) {
		return "", false
	}
	type deniedItem struct {
		display string
		reason  string
	}
	var items []deniedItem
	for _, t := range targets {
		if d := db.EvaluateAssetGateOn(block, allow, gateTargetsOf(t)); !d.Allowed {
			items = append(items, deniedItem{display: t.display(), reason: d.Reason})
		}
	}
	if len(items) == 0 {
		return "", false
	}
	var b strings.Builder
	b.WriteString("[任务白名单] 以下目标不在本次任务允许范围内，禁止访问：")
	for i, it := range items {
		if i > 0 {
			b.WriteString("；")
		}
		b.WriteString(it.display + "（" + it.reason + "）")
	}
	if db.HasEnabledRule(allow) {
		b.WriteString("。当前启用的允许规则：")
		first := true
		for _, r := range allow {
			if !r.Enabled {
				continue
			}
			if !first {
				b.WriteString("、")
			}
			first = false
			b.WriteString("[" + db.AssetInterceptKindLabel(r.Kind) + "] " + r.Pattern)
		}
		b.WriteString("。请改写命令，使其只访问白名单内的主机与端口" +
			"（端口扫描请显式加 -p 指定允许的端口），或联系管理员调整任务的允许规则。")
	} else {
		b.WriteString("。本次任务未启用允许规则白名单，命中了上述拦截规则；请更换目标或联系管理员。")
	}
	return b.String(), true
}
