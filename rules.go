package traefik_modsecurity_plugin

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// Rule actions.
const (
	ActionBlock    = "block"
	ActionSkipBody = "skip-body"
	ActionSkipWaf  = "skip-waf"
)

// Rule matches requests and decides how the plugin treats them.
// All conditions that are set must match.
type Rule struct {
	Name        string   `json:"name,omitempty"`
	Action      string   `json:"action,omitempty"`
	LogOnly     bool     `json:"logOnly,omitempty"`
	Method      []string `json:"method,omitempty"`
	MethodNot   []string `json:"methodNot,omitempty"`
	Path        string   `json:"path,omitempty"`
	PathNot     string   `json:"pathNot,omitempty"`
	Query       string   `json:"query,omitempty"`
	Header      string   `json:"header,omitempty"`
	HeaderValue string   `json:"headerValue,omitempty"`
	ClientIP    []string `json:"clientIp,omitempty"`
}

type ruleSet struct {
	includes []string
	rules    []Rule
}

// ruleSets mirror the security config of the php-nginx base image.
var ruleSets = map[string]ruleSet{
	"basic": {
		rules: []Rule{
			{Name: "basic/dot-files", Action: ActionBlock, Path: `/\.`, PathNot: `/\.well-known(/|$)`},
			{Name: "basic/development-files", Action: ActionBlock, Path: `(?i)(package\.json|gulpfile\.js|phpstan\.neon|composer\.(json|lock))`},
			{Name: "basic/block-user-agents", Action: ActionBlock, Header: "User-Agent", HeaderValue: `Indy Library|libwww-perl|GetRight|GetWeb!|Go!Zilla|Download Demon|Go-Ahead-Got-It|TurnitinBot|GrabNet`},
		},
	},
	"typo3": {
		includes: []string{"basic"},
		rules: []Rule{
			{Name: "typo3/backend-file-upload", Action: ActionSkipBody, Method: []string{http.MethodPost}, Path: `^/typo3/(ajax/file/(process|reference/create)|file/(commit|replace))$`},
			{Name: "typo3/limit-methods", Action: ActionBlock, MethodNot: []string{http.MethodGet, http.MethodHead, http.MethodPost}},
			{Name: "typo3/script-execution", Action: ActionBlock, Path: `(?i)^/(fileadmin|media|uploads|typo3temp)/.*\.(php\d*|phtml|phpt|phar|phps|pht|cgi|fcgi|pl|py|rb|sh|shtml)($|/)`},
			{Name: "typo3/flexforms", Action: ActionBlock, Path: `(?i)flexform[^.]*\.xml`},
			{Name: "typo3/locallang", Action: ActionBlock, Path: `(?i)locallang[^.]*\.(xml|xlf)$`},
			{Name: "typo3/static-typoscript", Action: ActionBlock, Path: `(?i)ext_conf_template\.txt|ext_typoscript_constants\.txt|ext_typoscript_setup\.txt`},
			{Name: "typo3/protected-files", Action: ActionBlock, Path: `(?i)(\.(bak|co?nf|cfg|ya?ml|ts|typoscript|tsconfig|tsc|tss|dist|fla|in[ci]|log|psd|sh|sql|sqlite|sw[op])|~)$`},
			{Name: "typo3/recycler-and-temp", Action: ActionBlock, Path: `_(recycler|temp)_/`},
			{Name: "typo3/fileadmin-templates", Action: ActionBlock, Path: `fileadmin/templates/.*\.(txt|ts|typoscript|tsc|tss)$`},
			{Name: "typo3/libraries", Action: ActionBlock, Path: `^/(vendor|typo3_src|typo3temp/var)`},
			{Name: "typo3/protected-extension-dirs", Action: ActionBlock, Path: `(typo3conf/ext|typo3/sysext|typo3/ext)/[^/]+/(Configuration|Resources/Private|Tests?|Documentation|docs?)/`},
			{Name: "typo3/local-configuration", Action: ActionBlock, Path: `^/typo3conf/system/`},
			{Name: "typo3/distribution-files", Action: ActionBlock, Path: `(?i)/(ChangeLog|(INSTALL|README|CHANGELOG|LICENSE|COPYING|AGENTS|CLAUDE|GEMINI)\.(md|txt|rst))$`},
		},
	},
}

type compiledRule struct {
	name        string
	action      string
	logOnly     bool
	methods     map[string]bool
	methodsNot  map[string]bool
	path        *regexp.Regexp
	pathNot     *regexp.Regexp
	query       *regexp.Regexp
	header      string
	headerValue *regexp.Regexp
	clientNets  []*net.IPNet
}

var repeatedSlashes = regexp.MustCompile(`//+`)

// buildRules returns project rules followed by the rules of the selected sets.
// A project rule replaces a set rule of the same name; disabled names are dropped.
func buildRules(project []Rule, sets []string, disabled []string) ([]compiledRule, []string, error) {
	var warnings []string
	projectNames := map[string]bool{}
	var ordered []Rule
	for _, rule := range project {
		if rule.Name == "" {
			return nil, nil, fmt.Errorf("every rule needs a name")
		}
		if projectNames[rule.Name] {
			return nil, nil, fmt.Errorf("rule %q is defined twice", rule.Name)
		}
		projectNames[rule.Name] = true
		ordered = append(ordered, rule)
	}

	setRules, err := expandRuleSets(sets)
	if err != nil {
		return nil, nil, err
	}
	known := map[string]bool{}
	for _, rule := range setRules {
		known[rule.Name] = true
	}
	disabledNames := map[string]bool{}
	for _, name := range disabled {
		disabledNames[name] = true
		if !known[name] {
			warnings = append(warnings, fmt.Sprintf("disableRules: %q is not part of the selected rule sets", name))
		}
	}
	for _, rule := range setRules {
		if !projectNames[rule.Name] && !disabledNames[rule.Name] {
			ordered = append(ordered, rule)
		}
	}

	compiled := make([]compiledRule, 0, len(ordered))
	for _, rule := range ordered {
		c, err := compileRule(rule)
		if err != nil {
			return nil, nil, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
		compiled = append(compiled, c)
	}
	return compiled, warnings, nil
}

func expandRuleSets(names []string) ([]Rule, error) {
	var rules []Rule
	seen := map[string]bool{}
	var add func(name string) error
	add = func(name string) error {
		if seen[name] {
			return nil
		}
		set, ok := ruleSets[name]
		if !ok {
			return fmt.Errorf("unknown rule set %q", name)
		}
		seen[name] = true
		for _, include := range set.includes {
			if err := add(include); err != nil {
				return err
			}
		}
		rules = append(rules, set.rules...)
		return nil
	}
	for _, name := range names {
		if err := add(name); err != nil {
			return nil, err
		}
	}
	return rules, nil
}

func compileRule(rule Rule) (compiledRule, error) {
	c := compiledRule{
		name:       rule.Name,
		action:     rule.Action,
		logOnly:    rule.LogOnly,
		methods:    methodSet(rule.Method),
		methodsNot: methodSet(rule.MethodNot),
		header:     rule.Header,
	}
	switch rule.Action {
	case ActionBlock, ActionSkipBody, ActionSkipWaf:
	default:
		return c, fmt.Errorf("unknown action %q", rule.Action)
	}
	if rule.HeaderValue != "" && rule.Header == "" {
		return c, fmt.Errorf("headerValue needs header")
	}

	var err error
	if c.path, err = compileOptional(rule.Path); err != nil {
		return c, err
	}
	if c.pathNot, err = compileOptional(rule.PathNot); err != nil {
		return c, err
	}
	if c.query, err = compileOptional(rule.Query); err != nil {
		return c, err
	}
	if c.headerValue, err = compileOptional(rule.HeaderValue); err != nil {
		return c, err
	}
	for _, value := range rule.ClientIP {
		network, err := parseNetwork(value)
		if err != nil {
			return c, err
		}
		c.clientNets = append(c.clientNets, network)
	}
	return c, nil
}

func compileOptional(expr string) (*regexp.Regexp, error) {
	if expr == "" {
		return nil, nil
	}
	return regexp.Compile(expr)
}

func methodSet(methods []string) map[string]bool {
	if len(methods) == 0 {
		return nil
	}
	set := make(map[string]bool, len(methods))
	for _, method := range methods {
		set[strings.ToUpper(method)] = true
	}
	return set
}

func parseNetwork(value string) (*net.IPNet, error) {
	if !strings.Contains(value, "/") {
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("invalid client IP %q", value)
		}
		bits := 128
		if ip.To4() != nil {
			ip = ip.To4()
			bits = 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return nil, fmt.Errorf("invalid client IP range %q", value)
	}
	return network, nil
}

// matches compares path with repeated slashes collapsed, as nginx does before
// matching its locations.
func (r *compiledRule) matches(req *http.Request, path, clientIP string) bool {
	if r.methods != nil && !r.methods[req.Method] {
		return false
	}
	if r.methodsNot != nil && r.methodsNot[req.Method] {
		return false
	}
	if r.path != nil && !r.path.MatchString(path) {
		return false
	}
	if r.pathNot != nil && r.pathNot.MatchString(path) {
		return false
	}
	if r.query != nil && !r.query.MatchString(req.URL.RawQuery) {
		return false
	}
	if r.header != "" {
		values := req.Header.Values(r.header)
		if r.headerValue == nil {
			if len(values) == 0 {
				return false
			}
		} else if !anyMatches(r.headerValue, values) {
			return false
		}
	}
	if len(r.clientNets) > 0 && !inNetworks(clientIP, r.clientNets) {
		return false
	}
	return true
}

func anyMatches(expr *regexp.Regexp, values []string) bool {
	for _, value := range values {
		if expr.MatchString(value) {
			return true
		}
	}
	return false
}

func inNetworks(clientIP string, networks []*net.IPNet) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func normalizedPath(req *http.Request) string {
	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	return repeatedSlashes.ReplaceAllString(path, "/")
}
