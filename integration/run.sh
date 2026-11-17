#!/usr/bin/env bash
# Starts the stack from docker-compose.yml and checks the WAF end to end.
set -uo pipefail
cd "$(dirname "$0")"
base="http://127.0.0.1:18080"
fail=0

docker compose up -d --quiet-pull >/dev/null 2>&1
trap 'docker compose down -v >/dev/null 2>&1' EXIT
for _ in $(seq 1 60); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$base/")" = "200" ] && break
  sleep 1
done

check() {
  local name="$1" want="$2"; shift 2
  local got
  got="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@")"
  if [ "$got" = "$want" ]; then
    printf 'ok    %-45s %s\n' "$name" "$got"
  else
    printf 'FAIL  %-45s got %s, want %s\n' "$name" "$got" "$want"
    fail=1
  fi
}

ws=(-H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==')
traversal='/?f=..%2F..%2F..%2F..%2Fetc%2Fpasswd'

check 'clean request'                        200 "$base/"
check 'attack'                               403 "$base$traversal"
check 'attack + Upgrade: websocket'          403 -H 'Upgrade: websocket' "$base$traversal"
check 'attack + full websocket handshake'    403 "${ws[@]}" "$base/echo$traversal"
check 'clean websocket handshake'            101 "${ws[@]}" "$base/echo"
check 'body within maxBodySize'              200 --data-binary @<(head -c 1000 /dev/zero | tr '\0' a) "$base/"
check 'body above maxBodySize'               413 --data-binary @<(head -c 2000000 /dev/zero | tr '\0' a) "$base/"

check 'rule: dot file'                        403 "$base/.git/config"
check 'rule: .well-known stays reachable'      200 "$base/.well-known/acme-challenge/x"
check 'rule: PUT outside allowed methods'      403 -X PUT "$base/"
check 'rule: project block rule'               403 "$base/uploads/tx_powermail/cv.pdf"
check 'rule: disabled user-agent rule'         200 -A 'libwww-perl/6.0' "$base/"
check 'rule: skip-waf passes attack'           200 "$base/skip$traversal"
check 'skip-body: attack in body passes'       200 --data 'f=../../../../etc/passwd' "$base/typo3/ajax/file/process"
check 'skip-body: attack in URL is blocked'    403 --data 'a=b' "$base/typo3/ajax/file/process$traversal"
check 'small body: attack is blocked'          403 --data 'f=../../../../etc/passwd' "$base/"
check 'large body: not inspected, passes'      200 --data-binary @<(printf 'f=../../../../etc/passwd&p='; head -c 200000 /dev/zero | tr '\0' a) "$base/"
check 'large body: attack in URL is blocked'   403 --data-binary @<(head -c 200000 /dev/zero | tr '\0' a) "$base$traversal"

check 'rate-limit: 1st POST'                  200 -A rate-bot --data a=b "$base/rate/x"
check 'rate-limit: 2nd POST'                  200 -A rate-bot --data a=b "$base/rate/x"
check 'rate-limit: 3rd POST is jailed'        429 -A rate-bot --data a=b "$base/rate/x"
check 'rate-limit: jail covers other paths'   429 -A rate-bot "$base/"
check 'rate-limit: other browser, same IP'    200 -A rate-browser --data a=b "$base/rate/x"

headers="$(curl -s -o /dev/null -D - --max-time 10 "$base$traversal")"
if grep -qiE '^(server|access-control-[a-z-]+):' <<<"$headers"; then
  printf 'FAIL  %-45s %s\n' 'block page without WAF headers' "$(grep -iE '^(server|access-control)' <<<"$headers" | tr -d '\r' | paste -sd' ')"
  fail=1
else
  printf 'ok    %-45s\n' 'block page without WAF headers'
fi

logs="$(docker compose logs --no-log-prefix traefik 2>/dev/null)"
for status in ok blocked skipped; do
  if grep -q "\"request_X-Waf-Status\":\"$status\"" <<<"$logs"; then
    printf 'ok    %-45s\n' "access log shows X-Waf-Status: $status"
  else
    printf 'FAIL  %-45s\n' "access log shows X-Waf-Status: $status"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  docker compose logs traefik | tail -20
fi
exit "$fail"
