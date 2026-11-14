package traefik_modsecurity_plugin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func ruleConfig(sets []string, disabled []string, rules ...Rule) *Config {
	config := CreateConfig()
	config.StatusHeader = "X-Waf-Status"
	config.RuleSets = sets
	config.DisableRules = disabled
	config.Rules = rules
	return config
}

func serve(handler http.Handler, method, target string, header http.Header) (*httptest.ResponseRecorder, *http.Request) {
	req := httptest.NewRequest(method, "http://example.com"+target, nil)
	for name, values := range header {
		req.Header[name] = values
	}
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	return rw, req
}

func TestTypo3RuleSetBlocksWhatTheBaseImageBlocks(t *testing.T) {
	handler, calls := newTestMiddleware(t, http.StatusOK, ruleConfig([]string{"typo3"}, nil), nil)

	blocked := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/.git/config"},
		{http.MethodGet, "/.env"},
		{http.MethodGet, "/package.json"},
		{http.MethodGet, "/typo3conf/ext/site/gulpfile.js"},
		{http.MethodGet, "/composer.lock"},
		{http.MethodPut, "/"},
		{http.MethodDelete, "/news"},
		{http.MethodGet, "/fileadmin/shell.php"},
		{http.MethodGet, "/uploads/x.phtml/extra"},
		{http.MethodGet, "/typo3conf/ext/site/Configuration/FlexForms/flexform_slider.xml"},
		{http.MethodGet, "/typo3conf/ext/site/Resources/Private/Language/locallang.xlf"},
		{http.MethodGet, "/typo3conf/ext/site/ext_typoscript_setup.txt"},
		{http.MethodGet, "/backup.sql"},
		{http.MethodGet, "/index.php~"},
		{http.MethodGet, "/fileadmin/_recycler_/old.pdf"},
		{http.MethodGet, "/fileadmin/templates/setup.typoscript"},
		{http.MethodGet, "/vendor/autoload.php"},
		{http.MethodGet, "//vendor/autoload.php"},
		{http.MethodGet, "/typo3conf/ext/news/Tests/Unit/x.php"},
		{http.MethodGet, "/typo3conf/system/settings.php"},
		{http.MethodGet, "/typo3conf/ext/news/README.md"},
		{http.MethodGet, "/ChangeLog"},
	}
	for _, tc := range blocked {
		rw, req := serve(handler, tc.method, tc.path, nil)
		assert.Equal(t, http.StatusForbidden, rw.Code, "%s %s", tc.method, tc.path)
		assert.Equal(t, "blocked", req.Header.Get("X-Waf-Status"), "%s %s", tc.method, tc.path)
	}
	assert.Equal(t, int32(0), atomic.LoadInt32(calls), "blocked requests must not reach the WAF")

	allowed := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/"},
		{http.MethodGet, "/.well-known/acme-challenge/token"},
		{http.MethodGet, "/fileadmin/images/logo.png"},
		{http.MethodGet, "/typo3/"},
		{http.MethodPost, "/typo3/ajax/record/process"},
		{http.MethodHead, "/news/readme"},
		{http.MethodGet, "/typo3conf/ext/site/Resources/Public/Css/main.css"},
		{http.MethodGet, "/aktuelles/changelog-2026"},
	}
	for _, tc := range allowed {
		rw, req := serve(handler, tc.method, tc.path, nil)
		assert.Equal(t, http.StatusOK, rw.Code, "%s %s", tc.method, tc.path)
		assert.Equal(t, "ok", req.Header.Get("X-Waf-Status"), "%s %s", tc.method, tc.path)
	}
}

func TestBasicRuleSetLeavesTypo3RulesOut(t *testing.T) {
	handler, _ := newTestMiddleware(t, http.StatusOK, ruleConfig([]string{"basic"}, nil), nil)

	rw, _ := serve(handler, http.MethodPut, "/api/item", nil)
	assert.Equal(t, http.StatusOK, rw.Code)

	rw, _ = serve(handler, http.MethodGet, "/.env", nil)
	assert.Equal(t, http.StatusForbidden, rw.Code)

	rw, _ = serve(handler, http.MethodGet, "/", http.Header{"User-Agent": {"libwww-perl/6.0"}})
	assert.Equal(t, http.StatusForbidden, rw.Code)
}

func TestDisabledRuleNoLongerApplies(t *testing.T) {
	handler, _ := newTestMiddleware(t, http.StatusOK, ruleConfig([]string{"typo3"}, []string{"basic/block-user-agents"}), nil)

	rw, _ := serve(handler, http.MethodGet, "/", http.Header{"User-Agent": {"libwww-perl/6.0"}})
	assert.Equal(t, http.StatusOK, rw.Code)
}

func TestProjectRuleReplacesSetRuleOfSameName(t *testing.T) {
	config := ruleConfig([]string{"typo3"}, nil, Rule{
		Name:      "typo3/limit-methods",
		Action:    ActionBlock,
		MethodNot: []string{"GET", "HEAD", "POST", "PUT"},
	})
	handler, _ := newTestMiddleware(t, http.StatusOK, config, nil)

	rw, _ := serve(handler, http.MethodPut, "/", nil)
	assert.Equal(t, http.StatusOK, rw.Code)
	rw, _ = serve(handler, http.MethodDelete, "/", nil)
	assert.Equal(t, http.StatusForbidden, rw.Code)
}

func TestProjectRulesAreCheckedBeforeSets(t *testing.T) {
	config := ruleConfig([]string{"typo3"}, nil, Rule{
		Name:   "allow-release-notes",
		Action: ActionSkipWaf,
		Path:   `^/downloads/README\.md$`,
	})
	handler, calls := newTestMiddleware(t, http.StatusForbidden, config, nil)

	rw, req := serve(handler, http.MethodGet, "/downloads/README.md", nil)
	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, "skipped", req.Header.Get("X-Waf-Status"))
	assert.Equal(t, int32(0), atomic.LoadInt32(calls))
}

func TestSkipWafRuleCanBeLimitedToClientNetworks(t *testing.T) {
	config := ruleConfig(nil, nil, Rule{
		Name:     "monitoring",
		Action:   ActionSkipWaf,
		Path:     `^/healthz$`,
		ClientIP: []string{"10.0.0.0/8", "192.0.2.10"},
	})
	handler, _ := newTestMiddleware(t, http.StatusForbidden, config, nil)

	for addr, want := range map[string]int{
		"10.1.2.3:1000":   http.StatusOK,
		"192.0.2.10:1000": http.StatusOK,
		"192.0.2.11:1000": http.StatusForbidden,
	} {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/healthz", nil)
		req.RemoteAddr = addr
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, req)
		assert.Equal(t, want, rw.Code, addr)
	}
}

func TestQueryAndHeaderConditions(t *testing.T) {
	config := ruleConfig(nil, nil, Rule{
		Name:        "block-old-api",
		Action:      ActionBlock,
		Query:       `(^|&)type=1533906435(&|$)`,
		Header:      "Accept",
		HeaderValue: `json`,
	})
	handler, _ := newTestMiddleware(t, http.StatusOK, config, nil)

	rw, _ := serve(handler, http.MethodGet, "/?type=1533906435", http.Header{"Accept": {"application/json"}})
	assert.Equal(t, http.StatusForbidden, rw.Code)
	rw, _ = serve(handler, http.MethodGet, "/?type=1533906435", http.Header{"Accept": {"text/html"}})
	assert.Equal(t, http.StatusOK, rw.Code)
	rw, _ = serve(handler, http.MethodGet, "/?type=1", http.Header{"Accept": {"application/json"}})
	assert.Equal(t, http.StatusOK, rw.Code)
}

func TestLogOnlyRuleDoesNotBlock(t *testing.T) {
	config := ruleConfig(nil, nil, Rule{Name: "try-out", Action: ActionBlock, Path: `^/wp-login\.php$`, LogOnly: true})
	handler, calls := newTestMiddleware(t, http.StatusOK, config, nil)

	rw, req := serve(handler, http.MethodGet, "/wp-login.php", nil)
	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, "ok", req.Header.Get("X-Waf-Status"))
	assert.Equal(t, int32(1), atomic.LoadInt32(calls))
}

func TestInvalidRuleConfigurationFailsAtStartup(t *testing.T) {
	cases := map[string]*Config{
		"unknown set":       ruleConfig([]string{"wordpress"}, nil),
		"unknown action":    ruleConfig(nil, nil, Rule{Name: "x", Action: "allow"}),
		"invalid regexp":    ruleConfig(nil, nil, Rule{Name: "x", Action: ActionBlock, Path: `(`}),
		"missing name":      ruleConfig(nil, nil, Rule{Action: ActionBlock}),
		"duplicate name":    ruleConfig(nil, nil, Rule{Name: "x", Action: ActionBlock}, Rule{Name: "x", Action: ActionBlock}),
		"invalid client ip": ruleConfig(nil, nil, Rule{Name: "x", Action: ActionBlock, ClientIP: []string{"10.0.0"}}),
		"value w/o header":  ruleConfig(nil, nil, Rule{Name: "x", Action: ActionBlock, HeaderValue: "a"}),
	}
	for name, config := range cases {
		config.ModSecurityUrl = "http://waf"
		_, err := New(context.Background(), http.NotFoundHandler(), config, "test")
		assert.Error(t, err, name)
	}
}

func TestUnknownDisabledRuleOnlyWarns(t *testing.T) {
	config := ruleConfig([]string{"typo3"}, []string{"typo3/does-not-exist"})
	config.ModSecurityUrl = "http://waf"
	_, err := New(context.Background(), http.NotFoundHandler(), config, "test")
	assert.NoError(t, err)
}

func TestSkipBodyRuleChecksUrlButNotBody(t *testing.T) {
	var wafBody string
	var wafContentType string
	config := ruleConfig([]string{"typo3"}, nil)
	handler, calls := newTestMiddleware(t, http.StatusOK, config, func(r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		wafBody = string(b)
		wafContentType = r.Header.Get("Content-Type")
	})

	req := httptest.NewRequest(http.MethodPost, "http://example.com/typo3/ajax/file/process?token=1", strings.NewReader("file-content"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	assert.Equal(t, int32(1), atomic.LoadInt32(calls))
	assert.Empty(t, wafBody)
	assert.Empty(t, wafContentType)
	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, "file-content", rw.Body.String(), "the service still receives the body")
}
