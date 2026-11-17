# Traefik ModSecurity Plugin

![Banner](./img/banner.png)

Traefik middleware that checks every request with an
[OWASP ModSecurity CRS](https://hub.docker.com/r/owasp/modsecurity-crs)
container before it reaches the service.

Maintained by AmedickSommer. Forked from
[madebymode/traefik-modsecurity-plugin](https://github.com/madebymode/traefik-modsecurity-plugin)
v1.6.0, which in turn forked
[acouvreur/traefik-modsecurity-plugin](https://github.com/acouvreur/traefik-modsecurity-plugin).

## How it works

1. The plugin reads the request body and sends a copy of the request to the
   WAF container (`modSecurityUrl`).
2. The WAF runs the CRS rules and forwards clean requests to a dummy backend
   that always answers `200`.
3. If the WAF answers with a `4xx` status, its block page goes to the client
   with only the status, `Content-Type` and body. Headers set by the WAF's
   web server, such as `Server` or CORS headers, are dropped.
4. If the WAF answers with `5xx` or cannot be reached in time, the client gets
   an empty `502` and the service is not called.
5. Otherwise the original request continues to the service.

Every request is inspected, including websocket handshakes. Hop-by-hop
headers such as `Upgrade` and `Connection` are removed from the copy, so the
WAF checks a handshake as a plain `GET`; the service still receives the
original upgrade.

The WAF sees the original `Host` header. `X-Forwarded-For`,
`X-Forwarded-Host` and `X-Forwarded-Proto` are passed through, or set from
the request when Traefik has not set them.

## Configuration

| Option                           | Default | Description                                         |
|----------------------------------|---------|-----------------------------------------------------|
| `modSecurityUrl`                 | –       | URL of the WAF container (required)                 |
| `timeoutMillis`                  | `2000`  | Timeout for the call to the WAF                     |
| `maxBodySize`                    | `0`     | Larger request bodies get `413`; `0` is unlimited   |
| `maxInspectedBodySize`           | `0`     | Larger bodies skip WAF inspection; `0` is unlimited |
| `statusHeader`                   | –       | Request header that receives the WAF outcome        |
| `ruleSets`                       | –       | Shipped rule sets to apply, see [Rules](#rules)     |
| `disableRules`                   | –       | Names of shipped rules to switch off                |
| `rules`                          | –       | Project rules, see [Rules](#rules)                  |
| `jailEnabled`                    | `false` | Answer `429` to clients with repeated WAF blocks    |
| `badRequestsThresholdCount`      | `25`    | Number of `403`s that put a client in jail          |
| `badRequestsThresholdPeriodSecs` | `600`   | Period in which the `403`s are counted              |
| `jailTimeDurationSecs`           | `600`   | How long a client stays in jail                     |

Request bodies are held in memory while the WAF checks them, so set
`maxBodySize` on public routers.

A body larger than `maxInspectedBodySize` is not held in memory: the WAF
checks method, URL and headers only, and the body is streamed to the service.
A streamed body that grows beyond `maxBodySize` is cut off with an error,
since the `413` can only be sent before streaming starts.

With `statusHeader` set, the plugin writes `ok`, `blocked`, `error` or
`skipped` into that request header and removes any value the client sent. Traefik's access
log records it with:

```text
--accesslog.fields.headers.names.X-Waf-Status=keep
```

The dummy backend must answer `200` for every path. `traefik/whoami` does
not: it handles `/echo`, `/health` and others itself, so requests to these
paths fail.

## Rules

Rules block requests before they reach the WAF, or take them out of WAF
inspection. Project rules are checked first, then the rules of the selected
sets; the first matching rule decides.

```yaml
ruleSets:
  - typo3                         # includes basic
disableRules:
  - basic/block-user-agents
rules:
  - name: typo3/limit-methods     # replaces the shipped rule of that name
    action: block
    methodNot: [GET, HEAD, POST, PUT]
  - name: powermail-uploads
    action: block
    path: '^/uploads/tx_powermail/'
  - name: monitoring
    action: skip-waf
    path: '^/healthz$'
    clientIp: ['10.0.0.0/8']
```

| Action      | Effect                                                         |
|-------------|----------------------------------------------------------------|
| `block`     | `403` without asking the WAF; status `blocked`                 |
| `skip-body` | The WAF checks method, URL and headers, but not the body       |
| `skip-waf`  | The request goes to the service unchecked; status `skipped`    |
| `rate-limit`| Counts matching requests, jails clients above the limit        |

Set `logOnly: true` on a rule to only log what it would do.

### Rate limits

```yaml
rules:
  - name: donation-flood
    action: rate-limit
    method: [POST]
    path: '^/spenden'
    limit: 9               # requests allowed per period
    limitPeriodSecs: 60
    limitBy: ip-fingerprint
    jailSecs: 600
```

A `rate-limit` rule counts the matching requests per client in a sliding
window. Within the limit the next rules apply as usual. The request above
the limit jails the client: it gets `429` for every request through this
middleware until `jailSecs` have passed (default: `limitPeriodSecs`).

| `limitBy`        | A client is                                          |
|------------------|------------------------------------------------------|
| `ip` (default)   | The client IP                                        |
| `ip-fingerprint` | The client IP plus `User-Agent`, `Accept`,           |
|                  | `Accept-Language`, `Accept-Encoding`, `Sec-Ch-Ua*`   |

`ip-fingerprint` keeps visitors behind one carrier NAT apart, but a bot that
changes its headers gets a new counter each time. Pair it with an IP-only
limit, e.g. Traefik's `rateLimit` middleware with a higher threshold.

Counters and jail live in memory per middleware instance; a change to the
dynamic configuration starts them empty.

| Condition     | Matches                                                      |
|---------------|--------------------------------------------------------------|
| `method`      | One of the listed methods                                    |
| `methodNot`   | None of the listed methods                                   |
| `path`        | Regular expression on the decoded path                       |
| `pathNot`     | Path does not match this regular expression                  |
| `query`       | Regular expression on the raw query string                   |
| `header`      | Header is present; with `headerValue`, a value matches it    |
| `clientIp`    | Client address in one of the listed IPs or CIDR ranges       |

All conditions set on a rule must match. Regular expressions use Go syntax:
no lookarounds, `(?i)` for case-insensitive matching. Repeated slashes in the
path are collapsed before matching.

Shipped sets mirror the security configuration of the AmedickSommer
`php-nginx` base image; see `rules.go` for every rule:

| Set     | Rules                                                                 |
|---------|-----------------------------------------------------------------------|
| `basic` | `basic/dot-files`, `basic/development-files`, `basic/block-user-agents` |
| `typo3` | `basic` plus `typo3/backend-file-upload` (`skip-body`), `typo3/limit-methods` and blocks for scripts in upload folders, flexforms, locallang, static TypoScript, protected files, recycler and temp folders, fileadmin templates, libraries, protected extension folders, the local configuration and distribution files |

A misspelled name in `disableRules` is logged and ignored. Invalid rules or
unknown sets stop the middleware from loading, so Traefik drops the routers
that use it: check the Traefik log after every change.

## Installation

```yaml
command:
  - "--experimental.plugins.traefik-modsecurity-plugin.modulename=github.com/AmedickSommer/traefik-modsecurity-plugin"
  - "--experimental.plugins.traefik-modsecurity-plugin.version=v1.3.0"
```

```yaml
http:
  middlewares:
    waf:
      plugin:
        traefik-modsecurity-plugin:
          modSecurityUrl: http://waf:8080
          timeoutMillis: 30000
          maxBodySize: 768000000
```

See [docker-compose.yml](docker-compose.yml) for a complete example.

## Development

```bash
go test -race ./...
integration/run.sh
```

`integration/run.sh` starts Traefik with the plugin from this checkout, the
CRS WAF and a test service, then checks blocking, the websocket handshake and
the body size limit end to end.

## Licence

Apache License 2.0, see [LICENSE](LICENSE).
