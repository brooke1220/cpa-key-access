# Sourced by run.sh after the routing checks: management API, persistence and a host restart.
mg() { curl -s -m 10 -o "$W/mg" -w '%{http_code}' -H "Authorization: Bearer $MGMT" -H 'Content-Type: application/json' "$@"; }
kstatus() { curl -s -m 10 -H "Authorization: Bearer $MGMT" "$BASE/v0/management/plugins/key-access/status"; }
PURL="$BASE/v0/management/plugins/key-access"
SC=$(scope e2e-key-c)
policies_body() { printf '{"version":1,"unconfigured_key":"allow","policies":[{"caller_scope":"%s","name":"key-a","allow_models":[],"deny_models":[],"allow_profiles":["*up-a*"],"deny_profiles":[]},{"caller_scope":"%s","name":"key-b","allow_models":[],"deny_models":["m-y"],"allow_profiles":[],"deny_profiles":["*up-a*"]},{"caller_scope":"%s","name":"key-c","allow_models":[],"deny_models":%s,"allow_profiles":[],"deny_profiles":[]}]}' "$SA" "$SB" "$SC" "$1"; }

echo "-- management API"
etag=$(curl -s -m 10 -D - -o /dev/null -H "Authorization: Bearer $MGMT" "$PURL/policies" | tr -d '\r' | awk -F': ' 'tolower($1)=="etag"{print $2}')
if [ -n "$etag" ]; then ok "GET policies returns an ETag ($etag)"; else bad "GET policies returns an ETag"; fi
expect "key-c may use m-x before any policy change" "$(chat e2e-key-c m-x false)" 200
expect "PUT with a stale ETag is rejected" "$(mg -X PUT -H 'If-Match: "rev-9999"' -d "$(policies_body '["m-x"]')" "$PURL/policies")" 412
expect "PUT with the fresh ETag succeeds" "$(mg -X PUT -H "If-Match: $etag" -d "$(policies_body '["m-x"]')" "$PURL/policies")" 200
expect "a saved model deny takes effect immediately" "$(chat e2e-key-c m-x false)" 403
expect "key-c may still use m-y" "$(chat e2e-key-c m-y false)" 200

echo "-- persistence"
mg "$BASE/v0/management/plugins" > /dev/null
PD=$(sed -n 's/.*"plugins_dir":"\([^"]*\)".*/\1/p' "$W/mg")
if [ -n "$PD" ]; then ok "host reports plugins_dir ($PD)"; else bad "host reports plugins_dir" "$(head -c 200 "$W/mg")"; fi
expect "initialize-storage creates the policy file" "$(mg -X POST -d "$(printf '{"plugins_dir":"%s"}' "$PD")" "$PURL/initialize-storage")" 201
POL="$PD/key-access/policies.yaml"
if [ -f "$POL" ] && grep -q "$SC" "$POL"; then ok "policy file holds the saved key-c policy"; else bad "policy file holds the saved key-c policy" "$POL"; fi
expect "PATCH policy_file through the host" "$(mg -X PATCH -d "$(printf '{"policy_file":"%s"}' "$POL")" "$PURL/config")" 200
for i in $(seq 1 20); do kstatus > "$W/st"; grep -q '"persistent_updates":true' "$W/st" && break; sleep 0.5; done
if grep -q '"persistent_updates":true' "$W/st"; then ok "plugin reloaded from the policy file"; else bad "plugin reloaded from the policy file" "$(cat "$W/st")"; fi
expect "the deny survives the reload" "$(chat e2e-key-c m-x false)" 403
expect "a PUT after persistence succeeds" "$(mg -X PUT -d "$(policies_body '["m-y"]')" "$PURL/policies")" 200
expect "the new deny applies at once (m-y)" "$(chat e2e-key-c m-y false)" 403
expect "and m-x is allowed again" "$(chat e2e-key-c m-x false)" 200

echo "-- restart"
HP=${PIDS##* }
kill "$HP"; wait "$HP" 2>/dev/null
(cd "$W" && exec "$HOST" -config "$W/config.yaml" -local-model) > "$W/host2.log" 2>&1 &
PIDS="$PIDS $!"
if curl -sf -m 5 --retry 40 --retry-delay 1 --retry-all-errors --retry-connrefused -o "$W/st2" -H "Authorization: Bearer $MGMT" "$PURL/status"; then ok "host restarted"; else bad "host restarted" "$(tail -20 "$W/host2.log")"; fi
if grep -q '"persistent_updates":true' "$W/st2"; then ok "restart: still reading the policy file"; else bad "restart: still reading the policy file" "$(cat "$W/st2")"; fi
expect "restart: the saved deny of m-y persisted" "$(chat e2e-key-c m-y false)" 403
expect "restart: key-c may use m-x again" "$(chat e2e-key-c m-x false)" 200
expect "restart: key-a is still pinned to up-a" "$(chat e2e-key-a m-x false)/$(served)" 200/served-by:up-a
