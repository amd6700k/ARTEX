package guard

import (
	"encoding/json"
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
	// portPair: host port 位置对形态（nc 10.0.0.5 8080、telnet host 25）——紧随
	// 裸 host 目标之后的合法端口数字认领为该目标的端口。
	portPair bool
	// extraSkip: 该工具特有的「下一 token 是值」旗标。不进全局表以避免跨工具
	// 冲突（wget -O 有值而 curl -O 无值；hydra -p 是密码不是端口）。
	extraSkip []string
}

// specIsKnown 区分「已登记工具」（走 T2 token 级提取）与未知工具（整段 T1）。
func specIsKnown(s toolSpec) bool {
	return s.positional || s.urlFlag || s.hostFlag || s.portFlag
}

var commandTools = map[string]toolSpec{
	"curl":        {positional: true},
	"wget":        {positional: true, extraSkip: []string{"-O", "--output-document"}},
	"nc":          {positional: true, portFlag: true, portPair: true},
	"ncat":        {positional: true, portFlag: true, portPair: true},
	"netcat":      {positional: true, portFlag: true, portPair: true},
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
	"hydra":       {positional: true, extraSkip: []string{"-l", "-L", "-p", "-P", "-f", "-t", "-W", "--pass"}},
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
	"telnet":      {positional: true, portPair: true},
	"ssh":         {positional: true},
	"ftp":         {positional: true, portPair: true},
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
	"-X", "--request",
	"--script", "--script-args", "--script-args-file",
	"--exclude", "--excludefile", "--resume",
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

// ExtractCommandTargets 从一条 shell 命令里提取目标：先按 | / && / ; / 换行分段
// （引号内的分隔符不切段，防 curl 'http://x/a|b' 被腰斩），已知工具走 T2
// （token 级，旗标值不误判），未知工具整段走 T1（高置信正则兜底）。
func ExtractCommandTargets(cmd string) []Target {
	var out []Target
	for _, seg := range splitSegments(cmd) {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		out = append(out, extractSegmentTargets(seg)...)
	}
	return dedupe(out)
}

// splitSegments 按引号外的 | / && / || / ; / 换行切段。单独 &（后台）维持不切段。
func splitSegments(cmd string) []string {
	var segs []string
	var cur strings.Builder
	var inSingle, inDouble bool
	runes := []rune(cmd)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case inSingle:
			if r == '\'' {
				inSingle = false
			}
			cur.WriteRune(r)
		case inDouble:
			if r == '"' {
				inDouble = false
			}
			cur.WriteRune(r)
		case r == '\'':
			inSingle = true
			cur.WriteRune(r)
		case r == '"':
			inDouble = true
			cur.WriteRune(r)
		case r == '|' || r == ';' || r == '\n':
			segs = append(segs, cur.String())
			cur.Reset()
			if i+1 < len(runes) && runes[i+1] == r && r != '\n' {
				i++ // 吞掉 || / ;; 的第二个字符
			}
		case r == '&':
			// && 是分隔符；单独 &（后台）维持不切段。
			if i+1 < len(runes) && runes[i+1] == '&' {
				segs = append(segs, cur.String())
				cur.Reset()
				i++
			} else {
				cur.WriteRune(r)
			}
		default:
			cur.WriteRune(r)
		}
	}
	return append(segs, cur.String())
}

// tokenizeSegment 按引号外空白切 token：引号内的空格不切分，引号字符保留在
// token 里（stripQuotes 依赖成对引号剥壳）。strings.Fields 不感知引号，会把
// 'Content-Type: application/json' 撕成两半、让 -H 只吃到前一半，剩下一半
// 落成孤立位置参数被误当目标。
func tokenizeSegment(seg string) []string {
	var toks []string
	var cur strings.Builder
	var inSingle, inDouble bool
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range seg {
		switch {
		case inSingle:
			if r == '\'' {
				inSingle = false
			}
			cur.WriteRune(r)
		case inDouble:
			if r == '"' {
				inDouble = false
			}
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			inSingle, inDouble = r == '\'', r == '"'
			cur.WriteRune(r)
		case r == ' ' || r == '\t' || r == '\r':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return toks
}

// segmentState 记录一段命令内的提取状态。
type segmentState struct {
	spec     toolSpec
	hasPort  bool   // 本段已出现 -p/--port
	pendPort string // 待赋给下一个目标的端口说明（来自 -p）
}

// extractSegmentTargets 提取单段命令的目标。
func extractSegmentTargets(seg string) []Target {
	toks := tokenizeSegment(seg)
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
				continue
			}
			// host port 位置对：nc/telnet 等的目标后紧跟合法端口数字 → 认领为
			// 该目标的端口（数字 token 本身 classifyArg 必拒，不会重复计目标）。
			if st.spec.portPair && len(out) > 0 && isAllDigits(tok) {
				if last := &out[len(out)-1]; last.Port == "" && last.Host != "" {
					if _, _, err := parsePortRange(tok); err == nil {
						last.Port = tok
					}
				}
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
	for _, f := range st.spec.extraSkip {
		if tok == f || (strings.HasPrefix(tok, f) && !strings.HasPrefix(tok, "--")) {
			if attached != "" {
				return 0
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
	// 纯字母全大写裸词（POST/GET/JSON 等常量风格 token）不是常规主机名：未知值
	// 旗标泄漏为位置参数时（curl -X POST）防止误提取。含数字的（web01/PC-01）不受影响。
	if !strings.Contains(s, ".") && !strings.ContainsAny(s, "0123456789") && s == strings.ToUpper(s) {
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
	//（同一主机拆出「无端口」候选会让白名单方向无法证明包含而误拒）。紧邻的
	// 逗号分隔数字（host, port = "10.0.0.5", 9001）认领为端口。
	if len(out) > 0 || hasContextHint(text) {
		for _, loc := range reIPv4.FindAllStringIndex(text, -1) {
			m := text[loc[0]:loc[1]]
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
				add(Target{Host: m, Port: adjacentPort(text[loc[1]:]), Raw: m})
			}
		}
	}
	return dedupe(out)
}

// reAdjacentPort 认领 IP 后「引号/括号 + 逗号 + 数字」形态的端口：Python/JS 里
// host, port = "10.0.0.5", 9001、connect(("10.0.0.5", 9001))、"10.0.0.5",9001。
// 只认逗号分隔形态——任意文本里的裸空格数字误当端口的风险太大。
var reAdjacentPort = regexp.MustCompile(`^['")\]\}]{0,2}\s*,\s*(\d{1,5})\b`)

// adjacentPort 在 IP 匹配结束后的文本片段里找相邻端口；非法端口范围不认领
// （保持无端口候选，由白名单方向照常判定）。
func adjacentPort(rest string) string {
	window := rest
	if len(window) > 16 {
		window = window[:16]
	}
	if m := reAdjacentPort.FindStringSubmatch(window); m != nil {
		if _, _, err := parsePortRange(m[1]); err == nil {
			return m[1]
		}
	}
	return ""
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

// gateVerdict 是一次白名单判定的结构化结果：blockHit 与 allowDenied 区分两类
// 拒绝来源——block 规则是用户显式配置，命中即确定性拦截（不经模型）；allow
// 越界则交给模型复核终审（见 guard.gateCheck）。
type gateVerdict struct {
	blockHit    bool
	allowDenied bool
	denyReason  string // 原始拒绝理由（[任务白名单] 前缀，interceptSource 据此归因）
	suspected   string // 被拒目标清单（模型复核提示词的提取器线索）
}

// deniedTarget 是一个被拒目标及其可读原因。
type deniedTarget struct {
	display string
	reason  string
}

// checkTargetsOnRules 是判定核心：对预载入的 block/allow 规则集逐目标评估，
// 两遍评估分离拒绝来源（block-only 重叠语义 / allow-only 包含语义，
// EvaluateAssetGateOn 的合并结果无法区分两类拒绝）。任一目标被拒即拒。
func checkTargetsOnRules(block, allow []db.AssetInterceptRule, targets []Target) gateVerdict {
	if len(targets) == 0 || (len(block) == 0 && !db.HasEnabledRule(allow)) {
		return gateVerdict{}
	}
	var blockItems, allowItems []deniedTarget
	for _, t := range targets {
		g := gateTargetsOf(t)
		if d := db.EvaluateAssetGateOn(block, nil, g); !d.Allowed {
			blockItems = append(blockItems, deniedTarget{t.display(), d.Reason})
			continue
		}
		if d := db.EvaluateAssetGateOn(nil, allow, g); !d.Allowed {
			allowItems = append(allowItems, deniedTarget{t.display(), d.Reason})
		}
	}
	switch {
	case len(blockItems) > 0:
		return gateVerdict{blockHit: true,
			denyReason: joinDenyReason("以下目标命中拦截规则，禁止访问：", blockItems,
				"。拦截规则为显式配置，直接拦截；请更换目标，或联系管理员调整拦截规则。"),
			suspected: suspectedOf(blockItems),
		}
	case len(allowItems) > 0:
		var tail string
		if db.HasEnabledRule(allow) {
			tail = "。当前启用的允许规则："
			first := true
			for _, r := range allow {
				if !r.Enabled {
					continue
				}
				if !first {
					tail += "、"
				}
				first = false
				tail += "[" + db.AssetInterceptKindLabel(r.Kind) + "] " + r.Pattern
			}
			tail += "。请改写命令，使其只访问白名单内的主机与端口" +
				"（端口扫描请显式加 -p 指定允许的端口），或联系管理员调整任务的允许规则。"
		} else {
			tail = "。本次任务未启用允许规则白名单，命中了上述拦截规则；请更换目标或联系管理员。"
		}
		return gateVerdict{allowDenied: true,
			denyReason: joinDenyReason("以下目标不在本次任务允许范围内，禁止访问：", allowItems, tail),
			suspected:  suspectedOf(allowItems),
		}
	}
	return gateVerdict{}
}

func joinDenyReason(head string, items []deniedTarget, tail string) string {
	var b strings.Builder
	b.WriteString("[任务白名单] " + head)
	for i, it := range items {
		if i > 0 {
			b.WriteString("；")
		}
		b.WriteString(it.display + "（" + it.reason + "）")
	}
	b.WriteString(tail)
	return b.String()
}

func suspectedOf(items []deniedTarget) string {
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = it.display
	}
	return strings.Join(parts, "；")
}
