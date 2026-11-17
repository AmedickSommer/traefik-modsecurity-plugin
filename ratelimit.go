package traefik_modsecurity_plugin

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Values of Rule.LimitBy.
const (
	LimitByIP            = "ip"
	LimitByIPFingerprint = "ip-fingerprint"
)

// fingerprintHeaders tell browsers behind one IP apart; a TLS fingerprint
// is not available to a Traefik middleware.
var fingerprintHeaders = []string{
	"User-Agent",
	"Accept",
	"Accept-Language",
	"Accept-Encoding",
	"Sec-Ch-Ua",
	"Sec-Ch-Ua-Mobile",
	"Sec-Ch-Ua-Platform",
}

type rateLimiter struct {
	limit         int
	period        time.Duration
	jailTime      time.Duration
	byFingerprint bool
	now           func() time.Time
	mutex         sync.Mutex
	hits          map[string][]time.Time
	jailed        map[string]time.Time
	nextSweep     time.Time
}

func newRateLimiter(rule Rule) (*rateLimiter, error) {
	if rule.Limit <= 0 || rule.LimitPeriodSecs <= 0 {
		return nil, fmt.Errorf("rate-limit needs limit and limitPeriodSecs above 0")
	}
	if rule.JailSecs < 0 {
		return nil, fmt.Errorf("jailSecs cannot be negative")
	}
	limiter := &rateLimiter{
		limit:    rule.Limit,
		period:   time.Duration(rule.LimitPeriodSecs) * time.Second,
		jailTime: time.Duration(rule.JailSecs) * time.Second,
		now:      time.Now,
		hits:     make(map[string][]time.Time),
		jailed:   make(map[string]time.Time),
	}
	if limiter.jailTime == 0 {
		limiter.jailTime = limiter.period
	}
	switch rule.LimitBy {
	case "", LimitByIP:
	case LimitByIPFingerprint:
		limiter.byFingerprint = true
	default:
		return nil, fmt.Errorf("unknown limitBy %q", rule.LimitBy)
	}
	return limiter, nil
}

func (l *rateLimiter) key(req *http.Request, clientIP string) string {
	if !l.byFingerprint {
		return clientIP
	}
	return clientIP + "/" + fingerprint(req)
}

func fingerprint(req *http.Request) string {
	hash := fnv.New64a()
	for _, name := range fingerprintHeaders {
		_, _ = hash.Write([]byte(strings.Join(req.Header.Values(name), ",")))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (l *rateLimiter) isJailed(key string) bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	release, ok := l.jailed[key]
	if !ok {
		return false
	}
	if l.now().Before(release) {
		return true
	}
	delete(l.jailed, key)
	return false
}

// hit counts a request and reports whether it exceeded the limit; the key is
// then jailed unless jail is false.
func (l *rateLimiter) hit(key string, jail bool) bool {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	now := l.now()
	l.sweep(now)

	recent := l.hits[key][:0]
	for _, hit := range l.hits[key] {
		if now.Sub(hit) < l.period {
			recent = append(recent, hit)
		}
	}
	recent = append(recent, now)
	if len(recent) <= l.limit {
		l.hits[key] = recent
		return false
	}
	if jail {
		delete(l.hits, key)
		l.jailed[key] = now.Add(l.jailTime)
	} else {
		l.hits[key] = recent[1:]
	}
	return true
}

// sweep drops expired entries once per period, so that keys of clients that
// never return do not pile up.
func (l *rateLimiter) sweep(now time.Time) {
	if now.Before(l.nextSweep) {
		return
	}
	l.nextSweep = now.Add(l.period)
	for key, hits := range l.hits {
		if len(hits) == 0 || now.Sub(hits[len(hits)-1]) >= l.period {
			delete(l.hits, key)
		}
	}
	for key, release := range l.jailed {
		if !now.Before(release) {
			delete(l.jailed, key)
		}
	}
}
