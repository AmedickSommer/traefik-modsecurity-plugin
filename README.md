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

With `statusHeader` set, the plugin writes `ok`, `blocked` or `error`
into that request header and removes any value the client sent. Traefik's access
log records it with:

```text
--accesslog.fields.headers.names.X-Waf-Status=keep
```

The dummy backend must answer `200` for every path. `traefik/whoami` does
not: it handles `/echo`, `/health` and others itself, so requests to these
paths fail.

## Installation

```yaml
command:
  - "--experimental.plugins.traefik-modsecurity-plugin.modulename=github.com/AmedickSommer/traefik-modsecurity-plugin"
  - "--experimental.plugins.traefik-modsecurity-plugin.version=v1.1.0"
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
