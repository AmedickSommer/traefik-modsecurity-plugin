package traefik_modsecurity_plugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func donationRule() Rule {
	return Rule{
		Name:            "donation-flood",
		Action:          ActionRateLimit,
		Method:          []string{http.MethodPost},
		Path:            `^/spenden`,
		Limit:           3,
		LimitPeriodSecs: 60,
		LimitBy:         LimitByIPFingerprint,
		JailSecs:        600,
	}
}

func rateLimitedMiddleware(t *testing.T, rule Rule) (http.Handler, *fakeClock, *int32) {
	t.Helper()
	handler, calls := newTestMiddleware(t, http.StatusOK, ruleConfig(nil, nil, rule), nil)
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	handler.(*Modsecurity).rules[0].limiter.now = clock.Now
	return handler, clock, calls
}

func post(handler http.Handler, ip, userAgent, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://example.com"+path, nil)
	req.RemoteAddr = ip + ":40000"
	req.Header.Set("User-Agent", userAgent)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	return rw
}

func TestRateLimitJailsClientAboveLimit(t *testing.T) {
	handler, _, calls := rateLimitedMiddleware(t, donationRule())

	for i := 0; i < 3; i++ {
		assert.Equal(t, http.StatusOK, post(handler, "203.0.113.1", "bot", "/spenden").Code)
	}
	rw := post(handler, "203.0.113.1", "bot", "/spenden")
	assert.Equal(t, http.StatusTooManyRequests, rw.Code)
	assert.EqualValues(t, 3, *calls, "the rejected request must not reach the WAF")
}

func TestRateLimitJailCoversEveryRequestThroughTheMiddleware(t *testing.T) {
	handler, _, _ := rateLimitedMiddleware(t, donationRule())
	for i := 0; i < 4; i++ {
		post(handler, "203.0.113.1", "bot", "/spenden")
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/other", nil)
	req.RemoteAddr = "203.0.113.1:40000"
	req.Header.Set("User-Agent", "bot")
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	assert.Equal(t, http.StatusTooManyRequests, rw.Code)
}

func TestRateLimitKeepsBrowsersBehindOneIpApart(t *testing.T) {
	handler, _, _ := rateLimitedMiddleware(t, donationRule())
	for i := 0; i < 4; i++ {
		post(handler, "203.0.113.1", "bot", "/spenden")
	}

	assert.Equal(t, http.StatusOK, post(handler, "203.0.113.1", "Firefox", "/spenden").Code)
	assert.Equal(t, http.StatusOK, post(handler, "203.0.113.2", "bot", "/spenden").Code)
}

func TestRateLimitByIpIgnoresHeaders(t *testing.T) {
	rule := donationRule()
	rule.LimitBy = LimitByIP
	handler, _, _ := rateLimitedMiddleware(t, rule)

	for i, userAgent := range []string{"a", "b", "c"} {
		assert.Equal(t, http.StatusOK, post(handler, "203.0.113.1", userAgent, "/spenden").Code, i)
	}
	assert.Equal(t, http.StatusTooManyRequests, post(handler, "203.0.113.1", "d", "/spenden").Code)
}

func TestRateLimitCountsOnlyWithinThePeriod(t *testing.T) {
	handler, clock, _ := rateLimitedMiddleware(t, donationRule())

	for i := 0; i < 6; i++ {
		assert.Equal(t, http.StatusOK, post(handler, "203.0.113.1", "bot", "/spenden").Code, i)
		clock.now = clock.now.Add(21 * time.Second)
	}
}

func TestRateLimitReleasesJailAfterJailSecs(t *testing.T) {
	handler, clock, _ := rateLimitedMiddleware(t, donationRule())
	for i := 0; i < 4; i++ {
		post(handler, "203.0.113.1", "bot", "/spenden")
	}

	clock.now = clock.now.Add(599 * time.Second)
	assert.Equal(t, http.StatusTooManyRequests, post(handler, "203.0.113.1", "bot", "/spenden").Code)
	clock.now = clock.now.Add(time.Second)
	assert.Equal(t, http.StatusOK, post(handler, "203.0.113.1", "bot", "/spenden").Code)
}

func TestRateLimitIgnoresRequestsOutsideTheRule(t *testing.T) {
	handler, _, _ := rateLimitedMiddleware(t, donationRule())

	for i := 0; i < 10; i++ {
		assert.Equal(t, http.StatusOK, post(handler, "203.0.113.1", "bot", "/news").Code)
	}
}

func TestRateLimitLogOnlyNeverJails(t *testing.T) {
	rule := donationRule()
	rule.LogOnly = true
	handler, _, _ := rateLimitedMiddleware(t, rule)

	for i := 0; i < 10; i++ {
		assert.Equal(t, http.StatusOK, post(handler, "203.0.113.1", "bot", "/spenden").Code)
	}
}

func TestRateLimitSweepDropsIdleClients(t *testing.T) {
	handler, clock, _ := rateLimitedMiddleware(t, donationRule())
	limiter := handler.(*Modsecurity).rules[0].limiter
	for i := 0; i < 4; i++ {
		post(handler, "203.0.113.1", "bot", "/spenden")
	}
	post(handler, "203.0.113.2", "bot", "/spenden")

	clock.now = clock.now.Add(time.Hour)
	post(handler, "203.0.113.3", "bot", "/spenden")
	assert.Len(t, limiter.hits, 1)
	assert.Empty(t, limiter.jailed)
}

func TestRateLimitConfigErrorsFailNew(t *testing.T) {
	broken := map[string]func(*Rule){
		"no limit":            func(r *Rule) { r.Limit = 0 },
		"no period":           func(r *Rule) { r.LimitPeriodSecs = 0 },
		"negative jail":       func(r *Rule) { r.JailSecs = -1 },
		"unknown limitBy":     func(r *Rule) { r.LimitBy = "cookie" },
		"limit on block rule": func(r *Rule) { r.Action = ActionBlock },
	}
	for name, breakRule := range broken {
		rule := donationRule()
		breakRule(&rule)
		config := ruleConfig(nil, nil, rule)
		config.ModSecurityUrl = "http://waf"
		_, err := New(context.Background(), http.NotFoundHandler(), config, "test")
		require.Error(t, err, name)
	}
}

func TestRateLimitJailDefaultsToThePeriod(t *testing.T) {
	rule := donationRule()
	rule.JailSecs = 0
	limiter, err := newRateLimiter(rule)
	require.NoError(t, err)
	assert.Equal(t, time.Minute, limiter.jailTime)
}
