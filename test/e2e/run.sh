#!/usr/bin/env bash
# End-to-end test: real CPA host + key-access plugin + two fake OpenAI-compatible upstreams.
# Usage: test/e2e/run.sh <cpa-host-binary> <plugins-dir>
# <plugins-dir> must contain <goos>/<goarch>/key-access.<ext>. All state lives in a fresh temp dir.
set -u
HOST=${1:?host binary}; PLUG=${2:?plugins dir}
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d /tmp/ka-e2e-run.XXXXXX)
PORT=18317; PA=19101; PB=19102; MGMT=e2e-mgmt-secret
BASE=http://127.0.0.1:$PORT
FAILS=0; PIDS=""
trap 'kill $PIDS 2>/dev/null' EXIT

scope() { printf 'cli-proxy-api:caller-scope:v1\0%s' "$1" | shasum -a 256 | cut -d' ' -f1; }
ok() { echo "PASS $1"; }
bad() { echo "FAIL $1"; [ -n "${2:-}" ] && echo "  $2"; FAILS=$((FAILS+1)); }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
chat() { curl -s -m 30 -o "$W/body" -w '%{http_code}' -H "Authorization: Bearer $1" -H 'Content-Type: application/json' -d "{\"model\":\"$2\",\"stream\":$3,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}" "$BASE/v1/chat/completions"; }
served() { grep -o 'served-by:up-[ab]' "$W/body" | head -1; }
six() { out=""; for i in 1 2 3 4 5 6; do c=$(chat "$1" "$2" "$3"); out="$out $c/$(served)"; done; echo "$out"; }
want6() { out=""; for i in 1 2 3 4 5 6; do out="$out $1"; done; echo "$out"; }

SA=$(scope e2e-key-a); SB=$(scope e2e-key-b)
mkdir -p "$W/auths"
cat > "$W/config.yaml" <<EOF
config-version: 8
server:
  host: "127.0.0.1"
  port: $PORT
management:
  allow-remote: false
  secret-key: "$MGMT"
  disable-control-panel: true
access:
  api-keys: ["e2e-key-a", "e2e-key-b", "e2e-key-c"]
oauth:
  auth-dir: "$W/auths"
plugins:
  enabled: true
  dir: "$PLUG"
  configs:
    key-access:
      enabled: true
      priority: 100
      version: 1
      unconfigured_key: allow
      policies:
        - caller_scope: $SA
          name: key-a
          allow_profiles: ["*up-a*"]
        - caller_scope: $SB
          name: key-b
          deny_models: ["m-y"]
          deny_profiles: ["*up-a*"]
api-keys:
  openai-compatibility:
    - name: up-a
      base-url: "http://127.0.0.1:$PA/v1"
      keys:
        - api-key: "fake-a"
      models:
        - {name: m-x, alias: m-x}
        - {name: m-y, alias: m-y}
    - name: up-b
      base-url: "http://127.0.0.1:$PB/v1"
      keys:
        - api-key: "fake-b"
      models:
        - {name: m-x, alias: m-x}
        - {name: m-y, alias: m-y}
EOF

node "$HERE/fake_upstream.js" up-a $PA > "$W/up-a.log" 2>&1 & PIDS="$PIDS $!"
node "$HERE/fake_upstream.js" up-b $PB > "$W/up-b.log" 2>&1 & PIDS="$PIDS $!"
(cd "$W" && exec "$HOST" -config "$W/config.yaml" -local-model) > "$W/host.log" 2>&1 &
PIDS="$PIDS $!"

if ! curl -sf -m 5 --retry 40 --retry-delay 1 --retry-all-errors --retry-connrefused -o "$W/status.json" -H "Authorization: Bearer $MGMT" "$BASE/v0/management/plugins/key-access/status"; then
  echo "FAIL the host never exposed the plugin status route; host log tail:"; tail -40 "$W/host.log"; exit 1
fi
grep -q '"policy_count":2' "$W/status.json" && ok "plugin loaded both policies" || bad "plugin loaded both policies" "$(cat "$W/status.json")"
grep -q '"fail_closed":false' "$W/status.json" && ok "plugin is not failing closed" || bad "plugin is not failing closed" "$(cat "$W/status.json")"
expect "settings page is served" "$(curl -s -o "$W/page" -w '%{http_code}' "$BASE/v0/resource/plugins/key-access/settings")" 200
grep -q 'Key Access' "$W/page" && ok "settings page has its title" || bad "settings page has its title"

expect "key-a non-stream always lands on up-a" "$(six e2e-key-a m-x false)" "$(want6 200/served-by:up-a)"
expect "key-a stream always lands on up-a" "$(six e2e-key-a m-x true)" "$(want6 200/served-by:up-a)"
expect "key-a may use m-y (no model rules)" "$(chat e2e-key-a m-y false)/$(served)" 200/served-by:up-a
expect "key-b non-stream always lands on up-b" "$(six e2e-key-b m-x false)" "$(want6 200/served-by:up-b)"
expect "key-b stream always lands on up-b" "$(six e2e-key-b m-x true)" "$(want6 200/served-by:up-b)"
expect "key-b is denied m-y (non-stream)" "$(chat e2e-key-b m-y false)" 403
grep -q model_access_denied "$W/body" && ok "deny body names model_access_denied" || bad "deny body names model_access_denied" "$(head -c 300 "$W/body")"
expect "key-b is denied m-y (stream)" "$(chat e2e-key-b m-y true)" 403
mix=$(for i in 1 2 3 4 5 6 7 8; do chat e2e-key-c m-x false >/dev/null; served; done | sort -u | tr '\n' ' ')
expect "key-c (no policy) keeps CPA built-in routing across both upstreams" "$mix" "served-by:up-a served-by:up-b "
expect "unknown key is rejected by CPA auth" "$(chat nope m-x false)" 401

. "$HERE/management_checks.sh"

echo "upstream hits: up-a=$(curl -s http://127.0.0.1:$PA/_hits | grep -o '"url"' | wc -l | tr -d ' ') up-b=$(curl -s http://127.0.0.1:$PB/_hits | grep -o '"url"' | wc -l | tr -d ' ')"
echo "logs: $W"
[ "$FAILS" = 0 ] && echo "ALL PASS" || echo "FAILED: $FAILS"
[ "$FAILS" = 0 ]
