package traefik_modsecurity_plugin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestMiddleware(t *testing.T, wafStatus int, config *Config, onWaf func(*http.Request)) (http.Handler, *int32) {
	t.Helper()
	var wafCalls int32
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&wafCalls, 1)
		if onWaf != nil {
			onWaf(r)
		}
		w.WriteHeader(wafStatus)
	}))
	t.Cleanup(waf.Close)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	if config == nil {
		config = CreateConfig()
	}
	config.ModSecurityUrl = waf.URL
	handler, err := New(context.Background(), next, config, "test")
	require.NoError(t, err)
	return handler, &wafCalls
}

func TestWebsocketHandshakeIsInspectedWithoutHopHeaders(t *testing.T) {
	var seen http.Header
	handler, calls := newTestMiddleware(t, http.StatusOK, nil, func(r *http.Request) { seen = r.Header.Clone() })

	req := httptest.NewRequest(http.MethodGet, "http://example.com/echo?x=1", nil)
	req.Header.Set("Connection", "Upgrade, X-Hop")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("X-Hop", "1")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	assert.Equal(t, int32(1), atomic.LoadInt32(calls))
	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Empty(t, seen.Get("Upgrade"))
	assert.Empty(t, seen.Get("Connection"))
	assert.Empty(t, seen.Get("X-Hop"))
	assert.Equal(t, "dGhlIHNhbXBsZSBub25jZQ==", seen.Get("Sec-WebSocket-Key"))
	assert.Equal(t, "websocket", req.Header.Get("Upgrade"), "the backend still receives the upgrade")
}

func TestWafReceivesOriginalHostAndClient(t *testing.T) {
	var host string
	var seen http.Header
	handler, _ := newTestMiddleware(t, http.StatusOK, nil, func(r *http.Request) {
		host = r.Host
		seen = r.Header.Clone()
	})

	req := httptest.NewRequest(http.MethodGet, "https://www.example.com/page", nil)
	req.RemoteAddr = "203.0.113.7:51234"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, "www.example.com", host)
	assert.Equal(t, "203.0.113.7", seen.Get("X-Forwarded-For"))
	assert.Equal(t, "www.example.com", seen.Get("X-Forwarded-Host"))
	assert.Equal(t, "https", seen.Get("X-Forwarded-Proto"))
}

func TestWafKeepsForwardedHeadersSetByTraefik(t *testing.T) {
	var seen http.Header
	handler, _ := newTestMiddleware(t, http.StatusOK, nil, func(r *http.Request) { seen = r.Header.Clone() })

	req := httptest.NewRequest(http.MethodGet, "http://www.example.com/", nil)
	req.RemoteAddr = "172.18.0.5:4000"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	req.Header.Set("X-Forwarded-Proto", "https")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, "198.51.100.1", seen.Get("X-Forwarded-For"))
	assert.Equal(t, "https", seen.Get("X-Forwarded-Proto"))
}

func TestBodyAboveMaxBodySizeIsRejected(t *testing.T) {
	config := CreateConfig()
	config.MaxBodySize = 10
	handler, calls := newTestMiddleware(t, http.StatusOK, config, nil)

	withLength := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader(strings.Repeat("a", 11)))
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, withLength)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rw.Code)

	chunked := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader(strings.Repeat("a", 11)))
	chunked.ContentLength = -1
	rw = httptest.NewRecorder()
	handler.ServeHTTP(rw, chunked)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rw.Code)

	assert.Equal(t, int32(0), atomic.LoadInt32(calls))
}

func TestBodyWithinMaxBodySizeReachesBackend(t *testing.T) {
	config := CreateConfig()
	config.MaxBodySize = 10
	handler, _ := newTestMiddleware(t, http.StatusOK, config, nil)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("0123456789"))
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Code)
	assert.Equal(t, "0123456789", rw.Body.String())
}

func TestNegativeMaxBodySizeIsRejected(t *testing.T) {
	config := CreateConfig()
	config.ModSecurityUrl = "http://waf"
	config.MaxBodySize = -1
	_, err := New(context.Background(), http.NotFoundHandler(), config, "test")
	assert.Error(t, err)
}

func TestJailTracksClientIPAcrossSourcePorts(t *testing.T) {
	config := CreateConfig()
	config.JailEnabled = true
	config.BadRequestsThresholdCount = 2
	handler, _ := newTestMiddleware(t, http.StatusForbidden, config, nil)

	for i, port := range []string{"1000", "1001", "1002"} {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.RemoteAddr = "203.0.113.7:" + port
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, req)
		if i < 2 {
			assert.Equal(t, http.StatusForbidden, rw.Code)
		} else {
			assert.Equal(t, http.StatusTooManyRequests, rw.Code)
		}
	}
}

func TestExpiredJailReleasesClientWithoutDeadlock(t *testing.T) {
	config := CreateConfig()
	config.JailEnabled = true
	config.BadRequestsThresholdCount = 1
	config.JailTimeDurationSecs = 0
	handler, _ := newTestMiddleware(t, http.StatusForbidden, config, nil)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			handler.ServeHTTP(httptest.NewRecorder(), req)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("request blocked while releasing a client from jail")
	}
}

func TestAbsoluteFormRequestTargetIsInspected(t *testing.T) {
	var uri string
	handler, calls := newTestMiddleware(t, http.StatusForbidden, nil, func(r *http.Request) { uri = r.RequestURI })

	req := httptest.NewRequest(http.MethodGet, "http://example.com/a?f=..%2Fetc", nil)
	req.RequestURI = "http://example.com/a?f=..%2Fetc"
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)

	assert.Equal(t, int32(1), atomic.LoadInt32(calls))
	assert.Equal(t, http.StatusForbidden, rw.Code)
	assert.Equal(t, "/a?f=..%2Fetc", uri)
}

func TestBlockResponseKeepsOnlyStatusContentTypeAndBody(t *testing.T) {
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<h1>403 Forbidden</h1>"))
	}))
	t.Cleanup(waf.Close)

	config := CreateConfig()
	config.ModSecurityUrl = waf.URL
	handler, err := New(context.Background(), http.NotFoundHandler(), config, "test")
	require.NoError(t, err)

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))

	assert.Equal(t, http.StatusForbidden, rw.Code)
	assert.Equal(t, "text/html", rw.Header().Get("Content-Type"))
	assert.Empty(t, rw.Header().Get("Server"))
	assert.Empty(t, rw.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "<h1>403 Forbidden</h1>", rw.Body.String())
}

func TestWafServerErrorIsAnEmptyBadGatewayAndSkipsBackend(t *testing.T) {
	waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("nginx error page"))
	}))
	t.Cleanup(waf.Close)

	var backendCalled bool
	config := CreateConfig()
	config.ModSecurityUrl = waf.URL
	handler, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
	}), config, "test")
	require.NoError(t, err)

	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))

	assert.Equal(t, http.StatusBadGateway, rw.Code)
	assert.NotContains(t, rw.Body.String(), "nginx error page")
	assert.False(t, backendCalled)
}
