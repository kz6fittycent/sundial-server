#!/usr/bin/env bash
# Checks a freshly installed server: it answers, first-run setup works and is
# closed to visitors from outside, and the command line reaches it.
# SERVER and URL can be set to test a build that isn't a snap.
set -euo pipefail

read -ra server <<<"${SERVER:-sudo sundial-server}"
url="${URL:-https://localhost:8461}"
web() { curl -sk --max-time 10 "$@"; }
fail() { echo "FAILED: $*"; exit 1; }

for _ in $(seq 1 30); do web -o /dev/null "$url/" && break; sleep 1; done

to="$(web -o /dev/null -w '%{http_code} %{redirect_url}' "$url/")"
[[ "$to" == "303 $url/setup" ]] || fail "a new server should open setup, got: $to"
page="$(web "$url/setup")"
grep -q "Make a login" <<<"$page" || fail "setup page"
echo "setup page: ok"

page="$(web -H 'X-Forwarded-For: 203.0.113.9' "$url/setup")"
grep -q "home network" <<<"$page" || fail "setup must be closed to outside visitors"
echo "setup closed to outside visitors: ok"

if [[ -n "${SCREENSHOT:-}" ]]; then
  google-chrome --headless=new --no-sandbox --ignore-certificate-errors \
    --hide-scrollbars --window-size=760,640 --screenshot="$SCREENSHOT" "$url/setup" 2>/dev/null
  echo "screenshot: ok"
fi

form=(-H "Origin: $url" -d "user=smoke&password=smoke-test-1&again=smoke-test-1")
to="$(web -o /dev/null -w '%{http_code} %{redirect_url}' "${form[@]}" "$url/setup")"
[[ "$to" == "303 $url/setup/parents" ]] || fail "first login, got: $to"
to="$(web -o /dev/null -w '%{redirect_url}' -H "Origin: $url" -d "user=smoke&password=wrong" "$url/login")"
[[ "$to" == *"Wrong"* ]] || fail "a wrong password should be refused, got: $to"
cookie="$(web -D - -o /dev/null -H "Origin: $url" -d "user=smoke&password=smoke-test-1" "$url/login")"
grep -qi '^set-cookie: sundial_session=' <<<"$cookie" || fail "sign-in"
echo "first login and sign-in: ok"

code="$("${server[@]}" pair)"
[[ "$code" =~ ^[0-9A-Z]{4}(-[0-9A-Z]{4})+$ ]] || fail "pairing code"
"${server[@]}" hosts >/dev/null || fail "hosts"
echo "pairing code and command line: ok"
