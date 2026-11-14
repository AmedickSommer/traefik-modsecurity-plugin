// Package traefik_modsecurity_plugin a modsecurity plugin.
package traefik_modsecurity_plugin

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
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
	MaxInspectedBodySize           int64  `json:"maxInspectedBodySize,omitempty"`
	StatusHeader                   string `json:"statusHeader,omitempty"`
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

// Values written to the configured status header for the Traefik access log.
const (
	statusOk      = "ok"
	statusBlocked = "blocked"
	statusError   = "error"
)

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
	maxInspectedBodySize           int64
	statusHeader                   string
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
	if config.MaxBodySize < 0 || config.MaxInspectedBodySize < 0 {
		return nil, fmt.Errorf("maxBodySize and maxInspectedBodySize cannot be negative")
	}
	logger := log.New(os.Stdout, "", log.LstdFlags)

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
		maxInspectedBodySize:           config.MaxInspectedBodySize,
		statusHeader:                   http.CanonicalHeaderKey(config.StatusHeader),
		next:                           next,
		name:                           name,
		httpClient:                     &http.Client{Timeout: timeout, Transport: transport},
		logger:                         logger,
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
	if a.statusHeader != "" {
		req.Header.Del(a.statusHeader)
	}

	if a.jailEnabled && a.isClientInJail(clientIP) {
		a.logger.Printf("client %s is jailed", clientIP)
		a.setStatus(req, statusBlocked)
		http.Error(rw, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	if a.maxBodySize > 0 && req.ContentLength > a.maxBodySize {
		a.setStatus(req, statusBlocked)
		http.Error(rw, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}

	inspectBody := a.maxInspectedBodySize <= 0 || req.ContentLength <= a.maxInspectedBodySize
	var body []byte
	if inspectBody {
		var err error
		body, inspectBody, err = a.readBody(req)
		if err == errBodyTooLarge {
			a.setStatus(req, statusBlocked)
			http.Error(rw, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			a.logger.Printf("fail to read incoming request: %s", err.Error())
			a.setStatus(req, statusError)
			http.Error(rw, "", http.StatusBadGateway)
			return
		}
	} else {
		a.limitBody(req)
	}

	var wafBody io.Reader
	if inspectBody {
		wafBody = bytes.NewReader(body)
	}
	proxyReq, err := http.NewRequestWithContext(req.Context(), req.Method, a.modSecurityUrl+requestURI(req), wafBody)
	if err != nil {
		a.logger.Printf("fail to prepare forwarded request: %s", err.Error())
		a.setStatus(req, statusError)
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	proxyReq.Header = wafHeaders(req, clientIP)
	if !inspectBody {
		proxyReq.Header.Del("Content-Type")
		proxyReq.Header.Del("Content-Encoding")
	}
	proxyReq.Host = req.Host

	resp, err := a.httpClient.Do(proxyReq)
	if err != nil {
		a.logger.Printf("fail to send HTTP request to modsec: %s", err.Error())
		a.setStatus(req, statusError)
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		_, _ = io.Copy(io.Discard, resp.Body)
		a.logger.Printf("modsec answered with status %d, rejecting request", resp.StatusCode)
		a.setStatus(req, statusError)
		http.Error(rw, "", http.StatusBadGateway)
		return
	}

	if resp.StatusCode >= 400 {
		if resp.StatusCode == http.StatusForbidden && a.jailEnabled {
			a.recordOffense(clientIP)
		}
		a.setStatus(req, statusBlocked)
		forwardResponse(resp, rw)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)

	a.setStatus(req, statusOk)
	a.next.ServeHTTP(rw, req)
}

func (a *Modsecurity) setStatus(req *http.Request, status string) {
	if a.statusHeader != "" {
		req.Header.Set(a.statusHeader, status)
	}
}

var errBodyTooLarge = errors.New("request body too large")

// readBody buffers the body for the WAF. A body above maxInspectedBodySize is
// streamed to the service instead and reported as not inspected.
func (a *Modsecurity) readBody(req *http.Request) ([]byte, bool, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, true, nil
	}
	limit := smallestLimit(a.maxBodySize, a.maxInspectedBodySize)
	reader := req.Body
	var source io.Reader = reader
	if limit > 0 {
		source = io.LimitReader(reader, limit+1)
	}
	body, err := io.ReadAll(source)
	if err != nil {
		return nil, false, err
	}
	size := int64(len(body))
	if a.maxBodySize > 0 && size > a.maxBodySize {
		return nil, false, errBodyTooLarge
	}
	if a.maxInspectedBodySize > 0 && size > a.maxInspectedBodySize {
		req.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(body), reader), Closer: reader}
		a.limitBody(req)
		return nil, false, nil
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	return body, true, nil
}

// limitBody fails the read of a streamed body once it exceeds maxBodySize.
func (a *Modsecurity) limitBody(req *http.Request) {
	if a.maxBodySize <= 0 || req.Body == nil || req.Body == http.NoBody {
		return
	}
	req.Body = &limitedBody{body: req.Body, remaining: a.maxBodySize}
}

func smallestLimit(limits ...int64) int64 {
	var smallest int64
	for _, limit := range limits {
		if limit > 0 && (smallest == 0 || limit < smallest) {
			smallest = limit
		}
	}
	return smallest
}

type readCloser struct {
	io.Reader
	io.Closer
}

type limitedBody struct {
	body      io.ReadCloser
	remaining int64
}

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.remaining < 0 {
		return 0, errBodyTooLarge
	}
	if int64(len(p)) > l.remaining+1 {
		p = p[:l.remaining+1]
	}
	n, err := l.body.Read(p)
	l.remaining -= int64(n)
	if l.remaining < 0 {
		return n, errBodyTooLarge
	}
	return n, err
}

func (l *limitedBody) Close() error {
	return l.body.Close()
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
