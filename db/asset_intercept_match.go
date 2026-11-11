package db

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// 资产拦截规则的匹配/执行层。asset_intercept.go 只负责规则存储，这里负责把
// 「目标资产」的域名/IP/URL 与启用中的规则做匹配。供 agent 工具（add_intent、
// insert_assets）在下发意图 / 插入资产前调用，命中则拒绝；guard 闸门
// （guard 包）也用它对工具调用提取出的目标做白名单判定。

// AssetInterceptKindLabel 返回 kind 的中文标签，用于给 agent 的说明消息。
func AssetInterceptKindLabel(kind string) string {
	switch kind {
	case "exact_domain":
		return "域名(全等)"
	case "exact_ip":
		return "IP(全等)"
	case "exact_url":
		return "URL(全等)"
	case "fuzzy_domain":
		return "域名(模糊)"
	case "fuzzy_ip":
		return "IP(模糊)"
	case "fuzzy_url":
		return "URL(模糊)"
	case "cidr":
		return "CIDR 网段"
	case "host_port":
		return "主机+端口"
	}
	return kind
}

// Reason 返回一条可读的命中原因，形如：命中资产拦截规则 [域名(模糊): .gov.cn]（备注）。
func (r AssetInterceptRule) Reason() string {
	s := fmt.Sprintf("命中资产拦截规则 [%s: %s]", AssetInterceptKindLabel(r.Kind), r.Pattern)
	if note := strings.TrimSpace(r.Note); note != "" {
		s += "（" + note + "）"
	}
	return s
}

// GateTargets 是闸门判定的一组候选串。前三个字段与旧接口的 domains/ips/urls
// 一一对应；HostPorts 是带端口的目标（host:port / host:lo-hi / host:80,443 /
// host:*，IPv6 经 net.JoinHostPort 规范化为 [h]:port）；CIDRs 是网段串。
type GateTargets struct {
	Domains   []string
	IPs       []string
	URLs      []string
	HostPorts []string
	CIDRs     []string
}

// matchMode 区分 host_port（以及 cidr-in-cidr）两种方向语义：
// block 按重叠判定（目标范围与规则范围有交集即命中），
// allow 按包含判定（目标范围必须完全落在规则范围内才放行）。
type matchMode int

const (
	modeBlock matchMode = iota
	modeAllow
)

// ParseHostPortPattern 解析 host_port 规则的 pattern：`<host>[:<portSpec>]`。
// host ∈ IPv4 | 域名 | [IPv6] | CIDR(v4/v6)；portSpec ∈ `8080` | `8000-9000`。
// 校验要求必须带端口——裸 host 请用 exact_ip/exact_domain/cidr 等既有 kind。
// 返回去括号后的 host 与端口区间 [lo, hi]。
func ParseHostPortPattern(p string) (host string, lo, hi int, err error) {
	s := strings.TrimSpace(p)
	if s == "" {
		return "", 0, 0, fmt.Errorf("pattern 为空")
	}
	rest := s
	switch {
	case strings.HasPrefix(rest, "["): // [IPv6]:port
		end := strings.Index(rest, "]")
		if end < 0 {
			return "", 0, 0, fmt.Errorf("IPv6 缺少右括号：%s", s)
		}
		host = rest[1:end]
		rest = rest[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", 0, 0, fmt.Errorf("必须带端口（裸主机请用 exact_ip/exact_domain/cidr 等 kind）：%s", s)
		}
		rest = rest[1:]
	default:
		// IPv6 不带括号（含多个冒号）无法区分端口，要求括号形式。
		if strings.Count(rest, ":") > 1 {
			return "", 0, 0, fmt.Errorf("IPv6 需用 [..] 括号形式（如 [::1]:8080）：%s", s)
		}
		if i := strings.LastIndex(rest, ":"); i >= 0 {
			host = rest[:i]
			rest = rest[i+1:]
		} else {
			return "", 0, 0, fmt.Errorf("必须带端口（裸主机请用 exact_ip/exact_domain/cidr 等 kind）：%s", s)
		}
	}
	lo, hi, err = parsePortSpec(rest)
	if err != nil {
		return "", 0, 0, err
	}
	if host == "" {
		return "", 0, 0, fmt.Errorf("host 为空：%s", s)
	}
	if err := validateHostPart(host); err != nil {
		return "", 0, 0, err
	}
	return host, lo, hi, nil
}

// parsePortSpec 解析端口说明：`8080` 或 `8000-9000`，返回 [lo, hi]。
func parsePortSpec(spec string) (int, int, error) {
	spec = strings.TrimSpace(spec)
	loS, hiS := spec, spec
	if i := strings.Index(spec, "-"); i >= 0 {
		loS, hiS = spec[:i], spec[i+1:]
	}
	lo, err := strconv.Atoi(strings.TrimSpace(loS))
	if err != nil {
		return 0, 0, fmt.Errorf("端口不是数字：%q", spec)
	}
	hi, err := strconv.Atoi(strings.TrimSpace(hiS))
	if err != nil {
		return 0, 0, fmt.Errorf("端口不是数字：%q", spec)
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("端口区间无效（须 1-65535 且起≤止）：%q", spec)
	}
	return lo, hi, nil
}

// isHostname 判断 s 是否形如主机名（字母数字连字符的点分段，至少含一个字母）。
func isHostname(s string) bool {
	if s == "" {
		return false
	}
	hasLetter := false
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" || len(l) > 253 {
			return false
		}
		for _, r := range l {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
				hasLetter = true
			case r >= '0' && r <= '9', r == '-', r == '_':
			default:
				return false
			}
		}
	}
	return hasLetter
}

// validateHostPart 校验 host ∈ IP | CIDR | 主机名。
func validateHostPart(host string) error {
	if net.ParseIP(host) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(host); err == nil {
		return nil
	}
	if isHostname(host) {
		return nil
	}
	return fmt.Errorf("host 不是有效的 IP/网段/域名：%s", host)
}

// parseHostPortCandidate 解析 HostPorts 候选串（我们自己产出的规范形态）：
// `host:80`、`host:8000-9000`、`host:80,443`、`host:*`，IPv6 为 `[h]:port`。
// 返回去括号 host、端口区间列表；wild 表示 `*`（任意端口、范围未知）；
// 无端口语义的候选 ranges 为空且 wild=false（视同任意端口的重叠方向）。
func parseHostPortCandidate(s string) (host string, ranges [][2]int, wild bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil, false
	}
	pspec := ""
	if strings.HasPrefix(s, "[") { // [IPv6]:port
		end := strings.Index(s, "]")
		if end < 0 {
			return s, nil, false
		}
		host = s[1:end]
		if strings.HasPrefix(s[end+1:], ":") {
			pspec = s[end+2:]
		}
	} else if i := strings.LastIndex(s, ":"); i >= 0 && strings.Count(s, ":") == 1 {
		host = s[:i]
		pspec = s[i+1:]
	} else {
		return s, nil, false // 裸 host（不应出现，防御性处理）
	}
	pspec = strings.TrimSpace(pspec)
	if pspec == "" {
		return host, nil, false
	}
	if pspec == "*" {
		return host, nil, true
	}
	for _, part := range strings.Split(pspec, ",") {
		lo, hi, err := parsePortSpec(part)
		if err != nil {
			return host, nil, true // 端口解析不了 → 范围未知（保守）
		}
		ranges = append(ranges, [2]int{lo, hi})
	}
	return host, ranges, false
}

// hostPortHostMatch 判断规则 host 与候选 host 是否指向同一目标。
// modeAllow 用包含语义：候选范围必须落在规则范围内（CIDR ⊆ CIDR、CIDR ⊆ 单 IP
// 仅限同地址的满前缀）；modeBlock 用重叠语义（CIDR 之间有交集即命中）。
func hostPortHostMatch(ruleHost, candHost string, mode matchMode) bool {
	rAddr, rAddrErr := netip.ParseAddr(ruleHost)
	rPre, rPreErr := netip.ParsePrefix(ruleHost)
	cAddr, cAddrErr := netip.ParseAddr(candHost)
	cPre, cPreErr := netip.ParsePrefix(candHost)
	switch {
	case rAddrErr == nil && cAddrErr == nil:
		return rAddr == cAddr
	case rAddrErr == nil && cPreErr == nil: // 规则 IP，候选网段
		if mode == modeAllow {
			bits := 32
			if rAddr.Is6() {
				bits = 128
			}
			return cPre.Masked() == netip.PrefixFrom(rAddr, bits).Masked()
		}
		return cPre.Contains(rAddr)
	case rPreErr == nil && cAddrErr == nil: // 规则网段，候选 IP
		return rPre.Contains(cAddr)
	case rPreErr == nil && cPreErr == nil: // 网段，网段
		if mode == modeBlock {
			return rPre.Overlaps(cPre)
		}
		rp, cp := rPre.Masked(), cPre.Masked()
		return rp.Overlaps(cp) && cp.Bits() >= rp.Bits()
	default:
		return strings.EqualFold(strings.TrimSuffix(ruleHost, "."), strings.TrimSuffix(candHost, "."))
	}
}

// matchOneOn 判断单条启用规则是否命中候选集，返回命中的具体值。
// host_port 只与 HostPorts 候选匹配；其余 kind 与旧语义完全一致
// （cidr 在 allow 模式额外支持候选网段 ⊆ 规则网段）。
func matchOneOn(r AssetInterceptRule, t GateTargets, mode matchMode) (string, bool) {
	p := strings.TrimSpace(r.Pattern)
	if p == "" {
		return "", false
	}
	switch r.Kind {
	case "exact_domain":
		for _, d := range t.Domains {
			if strings.EqualFold(strings.TrimSpace(d), p) {
				return d, true
			}
		}
	case "exact_ip":
		for _, ip := range t.IPs {
			if strings.TrimSpace(ip) == p {
				return ip, true
			}
		}
	case "exact_url":
		for _, u := range t.URLs {
			if strings.TrimSpace(u) == p {
				return u, true
			}
		}
	case "fuzzy_domain":
		lp := strings.ToLower(p)
		for _, d := range t.Domains {
			if d != "" && strings.Contains(strings.ToLower(d), lp) {
				return d, true
			}
		}
	case "fuzzy_ip":
		for _, ip := range t.IPs {
			if ip != "" && strings.Contains(ip, p) {
				return ip, true
			}
		}
	case "fuzzy_url":
		lp := strings.ToLower(p)
		for _, u := range t.URLs {
			if u != "" && strings.Contains(strings.ToLower(u), lp) {
				return u, true
			}
		}
	case "cidr":
		_, ipnet, err := net.ParseCIDR(p)
		if err != nil {
			return "", false
		}
		for _, ip := range t.IPs {
			if pip := net.ParseIP(strings.TrimSpace(ip)); pip != nil && ipnet.Contains(pip) {
				return ip, true
			}
		}
		if mode == modeAllow {
			// 白名单方向：目标网段整体落在规则网段内才算命中（扫描 /24 需允许规则覆盖该 /24）。
			for _, c := range t.CIDRs {
				if _, cnet, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil &&
					ipnet.Contains(cnet.IP) && netIPNetBits(cnet) >= netIPNetBits(ipnet) {
					return c, true
				}
			}
		}
	case "host_port":
		rh, lo, hi, err := ParseHostPortPattern(p)
		if err != nil {
			return "", false
		}
		for _, c := range t.HostPorts {
			ch, ranges, wild := parseHostPortCandidate(c)
			if ch == "" || !hostPortHostMatch(rh, ch, mode) {
				continue
			}
			if mode == modeBlock {
				// 重叠语义：无端口语义（* / 解析不出 / 裸 host）视同任意端口，必命中。
				if wild || len(ranges) == 0 {
					return c, true
				}
				for _, rg := range ranges {
					if rg[0] <= hi && lo <= rg[1] {
						return c, true
					}
				}
			} else {
				// 包含语义：候选端口必须全部落在规则区间内；
				// * / 无端口说明范围未知，无法证明 ⊆，不放行（逼 agent 显式 -p）。
				if wild || len(ranges) == 0 {
					continue
				}
				covered := true
				for _, rg := range ranges {
					if rg[0] < lo || rg[1] > hi {
						covered = false
						break
					}
				}
				if covered {
					return c, true
				}
			}
		}
	}
	return "", false
}

// netIPNetBits 返回 IPNet 的前缀长度（v4 按 32 位计）。
func netIPNetBits(n *net.IPNet) int {
	bits, _ := n.Mask.Size()
	return bits
}

// matchOne 是旧签名（domains/ips/urls 三元组）的兼容入口，保持原语义（block 方向）。
func matchOne(r AssetInterceptRule, domains, ips, urls []string) (string, bool) {
	return matchOneOn(r, GateTargets{Domains: domains, IPs: ips, URLs: urls}, modeBlock)
}

// MatchAssetInterceptRules 返回第一条命中给定 域名/IP/URL 候选串的启用规则，及命中的具体值。
// 供 insert_assets 用原始输入（尚未落库的 assetInputItem）匹配。
func MatchAssetInterceptRules(rules []AssetInterceptRule, domains, ips, urls []string) (AssetInterceptRule, string, bool) {
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if v, ok := matchOneOn(r, GateTargets{Domains: domains, IPs: ips, URLs: urls}, modeBlock); ok {
			return r, v, true
		}
	}
	return AssetInterceptRule{}, "", false
}

// matchAssetInterceptRulesOn 是 MatchAssetInterceptRules 的 GateTargets/mode 版本。
func matchAssetInterceptRulesOn(rules []AssetInterceptRule, t GateTargets, mode matchMode) (AssetInterceptRule, string, bool) {
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if v, ok := matchOneOn(r, t, mode); ok {
			return r, v, true
		}
	}
	return AssetInterceptRule{}, "", false
}

// interceptCandidates 提取一个已落库资产用于拦截匹配的候选集。
// URL 的 host 会被拆出并归类，使「只带 URL」的服务类资产也能被 域名/IP 规则命中；
// 已知端口（Port / OpenPorts / URL 显式或按 scheme 默认端口）会额外产出 host:port
// 候选，使 host_port 白名单规则也能命中资产。
func (a *Asset) interceptCandidates() GateTargets {
	var t GateTargets
	add := func(dst *[]string, s string) {
		if s = strings.TrimSpace(s); s != "" {
			*dst = append(*dst, s)
		}
	}
	addHost := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" {
			return
		}
		if _, _, err := net.ParseCIDR(h); err == nil {
			add(&t.CIDRs, h)
			return
		}
		if net.ParseIP(h) != nil {
			add(&t.IPs, h)
		} else {
			add(&t.Domains, h)
		}
	}
	addHostPort := func(h string, port string) {
		h = strings.TrimSpace(h)
		if h == "" || port == "" {
			return
		}
		add(&t.HostPorts, net.JoinHostPort(h, port))
	}
	add(&t.Domains, a.Domain)
	add(&t.Domains, a.RootDomain)
	for _, d := range a.BoundDomains {
		add(&t.Domains, d)
	}
	addHost(a.IP)
	if a.IP != "" && net.ParseIP(strings.TrimSpace(a.IP)) != nil {
		ip := strings.TrimSpace(a.IP)
		if a.Port != nil && *a.Port > 0 {
			addHostPort(ip, strconv.Itoa(*a.Port))
		}
		for _, op := range a.OpenPorts {
			if p := portFromAny(op["port"]); p > 0 {
				addHostPort(ip, strconv.Itoa(p))
			}
		}
	}
	if a.URL != "" {
		add(&t.URLs, a.URL)
		if u, err := url.Parse(a.URL); err == nil {
			if h := u.Hostname(); h != "" {
				addHost(h)
				port := u.Port()
				if port == "" {
					port = defaultSchemePort(u.Scheme)
				}
				addHostPort(h, port)
			}
		}
	}
	return t
}

// defaultSchemePort 按 URL scheme 合成默认端口（http→80，其余→443），与
// server.parseTarget 的端口语义一致；无法识别的 scheme 返回空（无端口语义）。
func defaultSchemePort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// portFromAny 从 open_ports 的 port 字段（JSON 解码后多为 float64）取端口号。
func portFromAny(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

// InterceptLabel 返回资产的简短标识，用于给 agent 的说明消息。
func (a *Asset) InterceptLabel() string {
	var target string
	switch {
	case a.Domain != "":
		target = a.Domain
	case a.URL != "":
		target = a.URL
	case a.IP != "":
		target = a.IP
	default:
		target = fmt.Sprintf("#%d", a.ID)
	}
	return fmt.Sprintf("资产#%d[%s] %s", a.ID, a.Type, target)
}

// hasEnabledRule 判断规则集里是否存在任一启用规则。
func hasEnabledRule(rules []AssetInterceptRule) bool {
	for _, r := range rules {
		if r.Enabled {
			return true
		}
	}
	return false
}

// HasEnabledRule 是 hasEnabledRule 的导出形式，供 guard 闸门等包外调用方在
// 提取目标前做「无启用规则 → 零开销放行」短路。
func HasEnabledRule(rules []AssetInterceptRule) bool { return hasEnabledRule(rules) }

// AssetGateDecision 是「先拦截后允许」闸门对一组候选串的判定结果。
type AssetGateDecision struct {
	Allowed bool
	Reason  string // 被拒原因（不含资产标识）；Allowed=true 时为空
}

// EvaluateAssetGate 执行任务级闸门判定：
//  1. 命中任一启用的 blockRules → 拒绝（拦截原因）。
//  2. 否则若 allowRules 存在启用项且都不命中 → 拒绝（不在允许范围）。
//  3. 否则放行。
//
// allowRules 为空/无启用项时，允许闸门不生效（即不启用白名单，全部放行），
// 避免「未配置允许规则」把所有资产挡掉。
func EvaluateAssetGate(blockRules, allowRules []AssetInterceptRule, domains, ips, urls []string) AssetGateDecision {
	return EvaluateAssetGateOn(blockRules, allowRules, GateTargets{Domains: domains, IPs: ips, URLs: urls})
}

// EvaluateAssetGateOn 是 EvaluateAssetGate 的 GateTargets 版本，供 guard 闸门
// 对带端口/网段的目标做判定。block 方向按重叠匹配，allow 方向按包含匹配
// （host_port：端口区间须完全覆盖；cidr：候选网段须是规则网段的子网）。
func EvaluateAssetGateOn(blockRules, allowRules []AssetInterceptRule, t GateTargets) AssetGateDecision {
	if rule, _, ok := matchAssetInterceptRulesOn(blockRules, t, modeBlock); ok {
		return AssetGateDecision{Allowed: false, Reason: rule.Reason()}
	}
	if hasEnabledRule(allowRules) {
		if _, _, ok := matchAssetInterceptRulesOn(allowRules, t, modeAllow); !ok {
			return AssetGateDecision{Allowed: false, Reason: "不在任务允许(白名单)范围内，不允许测试"}
		}
	}
	return AssetGateDecision{Allowed: true}
}

// AssetInterceptHit 描述一个被闸门拒绝的资产（拦截命中 或 不在允许范围）。
type AssetInterceptHit struct {
	Asset  *Asset
	Reason string // 可读原因
}

// Describe 返回一条可读的说明：资产信息 + 原因。
func (h AssetInterceptHit) Describe() string {
	return fmt.Sprintf("%s → %s", h.Asset.InterceptLabel(), h.Reason)
}

// ListAssetInterceptRules 是 *DB 同名方法的透传，让只持有 AssetStore 的调用方
// （如 agent 工具）也能读取规则。
func (s *AssetStore) ListAssetInterceptRules() ([]AssetInterceptRule, error) {
	return s.db.ListAssetInterceptRules()
}

// LoadTaskGateRules 装载闸门规则集：拦截规则 = 全局 ∪ 任务级 block；
// 允许规则 = 任务级 allow（仅本任务）。供 CheckAssetsIntercept 与 guard 闸门复用。
func (s *AssetStore) LoadTaskGateRules(taskID int64) (block, allow []AssetInterceptRule, err error) {
	block, err = s.db.ListAssetInterceptRules()
	if err != nil {
		return nil, nil, err
	}
	if taskID > 0 {
		tb, ta, err := s.TaskInterceptRulesSplit(taskID)
		if err != nil {
			return nil, nil, err
		}
		block = append(block, tb...)
		allow = ta
	}
	return block, allow, nil
}

// CheckAssetsIntercept 按 id 载入资产，逐个执行「先拦截后允许」闸门判定，返回所有
// 被拒的资产。拦截规则 = 全局 ∪ 任务级 block；允许规则 = 任务级 allow（仅本任务）。
// 无 id 时快速返回。用全局 GetByIDs（不受任务范围过滤）以保证拦截不被 scope 削弱。
func (s *AssetStore) CheckAssetsIntercept(taskID int64, ids []int64) ([]AssetInterceptHit, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	blockRules, allowRules, err := s.LoadTaskGateRules(taskID)
	if err != nil {
		return nil, err
	}
	// 既无拦截规则、也无启用的允许规则 → 无需判定，全部放行。
	if len(blockRules) == 0 && !hasEnabledRule(allowRules) {
		return nil, nil
	}
	assets, err := s.GetByIDs(ids)
	if err != nil {
		return nil, err
	}
	var hits []AssetInterceptHit
	for _, a := range assets {
		if d := EvaluateAssetGateOn(blockRules, allowRules, a.interceptCandidates()); !d.Allowed {
			hits = append(hits, AssetInterceptHit{Asset: a, Reason: d.Reason})
		}
	}
	return hits, nil
}
