#!/bin/sh
# Smoke test against a running Guardian: it answers, and it fails closed.
set -eu

URL="${GUARDIAN_URL:-http://guardian:8080}"

echo "health"
curl -fsS "$URL/health" | grep -qx ok

echo "unpaired core denies a valid call"
curl -fsS -X POST -H 'content-type: application/json' \
    -d '{"session":"smoke","tool":"bash","args":{"command":"rm -rf ~/.bash_history"},"cwd":"/work"}' \
    "$URL/decide" | grep -q '"decision":"deny"'

echo "malformed call is denied"
curl -fsS -X POST -H 'content-type: application/json' \
    -d '{not json' "$URL/decide" | grep -q '"decision":"deny"'

echo "smoke test passed"
