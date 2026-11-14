// Package traefik_modsecurity_plugin a modsecurity plugin.
package traefik_modsecurity_plugin

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Config the plugin configuration.
type Config struct {
	TimeoutMillis                  int64  `json:"timeoutMillis,omitempty"`
	ModSecurityUrl                 string `json:"modSecurityUrl,omitempty"`
	MaxBodySize                    int64  `json:"maxBodySize,omitempty"`
	JailEnabled                    bool   `json:"jailEnabled,omitempty"`
	BadRequestsThresholdCount      int    `json:"badRequestsThresholdCount,omitempty"`
	BadRequestsThresholdPeriodSecs int    `json:"badRequestsThresholdPeriodSecs,omitempty"`
	JailTimeDurationSecs           int    `json:"jailTimeDurationSecs,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TimeoutMillis:                  2000,
		JailEnabled:                    false,
		BadRequestsThresholdCount:      25,
		BadRequestsThresholdPeriodSecs: 600,
		JailTimeDurationSecs:           600,
	}
}

// hopHeaders apply to a single connection and must not reach the WAF.
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// Modsecurity a Modsecurity plugin.
type Modsecurity struct {
	next                           http.Handler
	modSecurityUrl                 string
	maxBodySize                    int64
	name                           string
	httpClient                     *http.Client
	logger                         *log.Logger
	jailEnabled                    bool
	badRequestsThresholdCount      int
	badRequestsThresholdPeriodSecs int
	jailTimeDurationSecs           int
	jail                           map[string][]time.Time
	jailRelease                    map[string]time.Time
	jailMutex                      sync.Mutex
}

// New creates a new Modsecurity plugin with the given configuration.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.ModSecurityUrl) == 0 {
		return nil, fmt.Errorf("modSecurityUrl cannot be empty")
	}
	if config.MaxBodySize < 0 {
		return nil, fmt.Errorf("maxBodySize cannot be negative")
	}

	timeout := 2 * time.Second
	if config.TimeoutMillis != 0 {
		timeout = time.Duration(config.TimeoutMillis) * time.Millisecond
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}

	return &Modsecurity{
		modSecurityUrl:                 config.ModSecurityUrl,
		maxBodySize:                    config.MaxBodySize,
		next:                           next,
		name:                           name,
		httpClient:                     &http.Client{Timeout: timeout, Transport: transport},
		logger:                         log.New(os.Stdout, "", log.LstdFlags),
		jailEnabled:                    config.JailEnabled,
		badRequestsThresholdCount:      config.BadRequestsThresholdCount,
		badRequestsThresholdPeriodSecs: config.BadRequestsThresholdPeriodSecs,
		jailTimeDurationSecs:           config.JailTimeDurationSecs,
		jail:                           make(map[string][]time.Time),
		jailRelease:                    make(map[string]time.Time),
	}, nil
}

func (a *Modsecurity) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := remoteIP(req)

	if a.jailEnabled && a.isClientInJail(clientIP) {
		a.logger.Printf("client %s is jailed", clientIP)
		http.Error(rw, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	if a.maxBodySize > 0 && req.ContentLength > a.maxBodySize {
		http.Error(rw, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}

	body, err := a.readBody(req)
	if err != nil {
		a.logger.Printf("fail to read incoming request: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	if a.maxBodySize > 0 && int64(len(body)) > a.maxBodySize {
		http.Error(rw, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	proxyReq, err := http.NewRequestWithContext(req.Context(), req.Method, a.modSecurityUrl+requestURI(req), bytes.NewReader(body))
	if err != nil {
		a.logger.Printf("fail to prepare forwarded request: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	proxyReq.Header = wafHeaders(req, clientIP)
	proxyReq.Host = req.Host

	resp, err := a.httpClient.Do(proxyReq)
	if err != nil {
		a.logger.Printf("fail to send HTTP request to modsec: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		if resp.StatusCode == http.StatusForbidden && a.jailEnabled {
			a.recordOffense(clientIP)
		}
		forwardResponse(resp, rw)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	a.next.ServeHTTP(rw, req)
}

func (a *Modsecurity) readBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	if a.maxBodySize <= 0 {
		return io.ReadAll(req.Body)
	}
	return io.ReadAll(io.LimitReader(req.Body, a.maxBodySize+1))
}

// wafHeaders copies the request headers for the WAF, without hop-by-hop headers,
// so that every request, including a websocket handshake, is inspected as plain HTTP.
func wafHeaders(req *http.Request, clientIP string) http.Header {
	header := req.Header.Clone()
	if header == nil {
		header = make(http.Header)
	}
	for _, field := range header.Values("Connection") {
		for _, name := range strings.Split(field, ",") {
			if name = strings.TrimSpace(name); name != "" {
				header.Del(name)
			}
		}
	}
	for _, name := range hopHeaders {
		header.Del(name)
	}

	if header.Get("X-Forwarded-For") == "" && clientIP != "" {
		header.Set("X-Forwarded-For", clientIP)
	}
	if header.Get("X-Forwarded-Host") == "" && req.Host != "" {
		header.Set("X-Forwarded-Host", req.Host)
	}
	if header.Get("X-Forwarded-Proto") == "" {
		proto := "http"
		if req.TLS != nil {
			proto = "https"
		}
		header.Set("X-Forwarded-Proto", proto)
	}
	return header
}

// requestURI keeps the client's raw encoding, but turns an absolute-form
// target ("GET http://host/path") into a path the WAF URL can be joined with.
func requestURI(req *http.Request) string {
	if strings.HasPrefix(req.RequestURI, "/") {
		return req.RequestURI
	}
	return req.URL.RequestURI()
}

func remoteIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// forwardResponse sends the WAF's block page with its status and content type only;
// headers such as Server or CORS from the WAF's nginx must not reach the client.
func forwardResponse(resp *http.Response, rw http.ResponseWriter) {
	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		rw.Header().Set("Content-Type", contentType)
	}
	rw.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(rw, resp.Body)
}

func (a *Modsecurity) recordOffense(clientIP string) {
	a.jailMutex.Lock()
	defer a.jailMutex.Unlock()

	now := time.Now()
	period := time.Duration(a.badRequestsThresholdPeriodSecs) * time.Second

	var offenses []time.Time
	for _, offense := range a.jail[clientIP] {
		if now.Sub(offense) <= period {
			offenses = append(offenses, offense)
		}
	}
	offenses = append(offenses, now)
	a.jail[clientIP] = offenses

	if len(offenses) >= a.badRequestsThresholdCount {
		a.logger.Printf("client %s reached threshold, putting in jail", clientIP)
		a.jailRelease[clientIP] = now.Add(time.Duration(a.jailTimeDurationSecs) * time.Second)
	}
}

func (a *Modsecurity) isClientInJail(clientIP string) bool {
	a.jailMutex.Lock()
	defer a.jailMutex.Unlock()

	releaseTime, exists := a.jailRelease[clientIP]
	if !exists {
		return false
	}
	if time.Now().Before(releaseTime) {
		return true
	}

	delete(a.jail, clientIP)
	delete(a.jailRelease, clientIP)
	a.logger.Printf("client %s released from jail", clientIP)
	return false
}
