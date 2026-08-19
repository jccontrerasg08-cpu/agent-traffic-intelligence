#!/usr/bin/env bash
# Run a bounded, local-only smoke test against the installed ati-service wheel.
set -euo pipefail

workspace="$(mktemp -d)"
port="${ATI_SMOKE_PORT:-9199}"
token="controlled-smoke-token"
pid=""

cleanup() {
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    kill -TERM "${pid}" || true
    wait "${pid}" || true
  fi
  rm -rf "${workspace}"
}
trap cleanup EXIT

ATI_SERVICE_TOKEN="${token}" \
ATI_HASH_KEY="controlled-smoke-hash-key" \
PORT="${port}" \
ati-service >"${workspace}/service.log" 2>&1 &
pid="$!"

for _attempt in $(seq 1 30); do
  if curl --fail --silent --show-error "http://127.0.0.1:${port}/health" >"${workspace}/health.json"; then
    break
  fi
  sleep 0.1
done

if [[ ! -s "${workspace}/health.json" ]]; then
  cat "${workspace}/service.log" >&2 || true
  echo "error: health endpoint did not become ready" >&2
  exit 1
fi

health_status="$(curl --silent --output "${workspace}/health.json" --write-out '%{http_code}' "http://127.0.0.1:${port}/health")"
if [[ "${health_status}" != "200" ]] || ! grep --quiet '"mode":"observe-only"' "${workspace}/health.json"; then
  echo "error: unexpected health response" >&2
  exit 1
fi

catalog_status="$(curl --silent --output "${workspace}/catalog.json" --write-out '%{http_code}' \
  "http://127.0.0.1:${port}/v1/catalog?probe=must-not-return")"
if [[ "${catalog_status}" != "200" ]] \
  || ! grep --quiet '"catalog_version":"1"' "${workspace}/catalog.json" \
  || grep --quiet 'must-not-return' "${workspace}/catalog.json"; then
  echo "error: public catalog response was invalid or exposed request data" >&2
  exit 1
fi

observation_status="$(curl --silent --output "${workspace}/observation.json" --write-out '%{http_code}' \
  --header 'X-ATI-Client-Class: automation' \
  --header 'Forwarded: for=203.0.113.9' \
  --header 'User-Agent: ControlledSmokeAutomation/1.0' \
  "http://127.0.0.1:${port}/v1/observe?probe=must-not-return")"
if [[ "${observation_status}" != "200" ]] \
  || ! grep --quiet '"declared_client_class":"automation"' "${workspace}/observation.json" \
  || ! grep --quiet '"forwarded_header_state":"present_but_untrusted"' "${workspace}/observation.json" \
  || ! grep --quiet '"dns_resolution":"not_observable_over_http"' "${workspace}/observation.json" \
  || grep --quiet -E '203\.0\.113\.9|ControlledSmokeAutomation|must-not-return' "${workspace}/observation.json"; then
  echo "error: public observation response was invalid or exposed raw declaration values" >&2
  exit 1
fi

unauthorized_status="$(curl --silent --output "${workspace}/unauthorized.json" --write-out '%{http_code}' \
  --request POST \
  --header 'Content-Type: application/x-ndjson' \
  --data-binary $'{"time_iso8601":"2026-08-19T12:00:00+00:00"}\n' \
  "http://127.0.0.1:${port}/v1/analyze")"
if [[ "${unauthorized_status}" != "401" ]]; then
  echo "error: unauthenticated analysis was not rejected" >&2
  exit 1
fi

invalid_type_status="$(curl --silent --output "${workspace}/invalid-type.json" --write-out '%{http_code}' \
  --request POST \
  --header "Authorization: Bearer ${token}" \
  --header 'Content-Type: application/json' \
  --data-binary $'{"time_iso8601":"2026-08-19T12:00:00+00:00"}\n' \
  "http://127.0.0.1:${port}/v1/analyze")"
if [[ "${invalid_type_status}" != "400" ]]; then
  echo "error: invalid content type was not rejected" >&2
  exit 1
fi

authorized_status="$(curl --silent --output "${workspace}/analysis.json" --write-out '%{http_code}' \
  --request POST \
  --header "Authorization: Bearer ${token}" \
  --header 'Content-Type: application/x-ndjson' \
  --data-binary $'{"time_iso8601":"2026-08-19T12:00:00+00:00","remote_addr":"203.0.113.9","request_method":"GET","request_uri":"/docs?token=must-not-return","status":200,"body_bytes_sent":100,"server_protocol":"HTTP/2","http_user_agent":"Mozilla/5.0 compatible; GPTBot/1.0"}\n' \
  "http://127.0.0.1:${port}/v1/analyze")"
if [[ "${authorized_status}" != "200" ]] || grep --quiet -E '203\.0\.113\.9|must-not-return' "${workspace}/analysis.json"; then
  echo "error: authorized analysis response was invalid or exposed raw data" >&2
  exit 1
fi

echo "service smoke passed: health, public catalog, public observation, authentication, content type, and privacy-safe output"
