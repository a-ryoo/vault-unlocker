#!/bin/sh
set +x
set -eu

VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}
UNSEAL_KEYS_FILE=${UNSEAL_KEYS_FILE:-/vault/unseal/unseal_keys}
CHECK_INTERVAL=${CHECK_INTERVAL:-5}
HTTP_TIMEOUT=${HTTP_TIMEOUT:-5}
VAULT_ADDR=${VAULT_ADDR%/}

case "$VAULT_ADDR" in
  http://?*|https://?*) ;;
  *) echo 'ERROR: VAULT_ADDR must use http or https' >&2; exit 1 ;;
esac
for duration in "$CHECK_INTERVAL" "$HTTP_TIMEOUT"; do
  case "$duration" in
    ''|*[!0-9]*|0*) echo 'ERROR: intervals must be positive integer seconds' >&2; exit 1 ;;
  esac
done

last_message=
log() {
  if [ "$1" != "$last_message" ]; then
    printf '%s\n' "$1"
    last_message=$1
  fi
}

# Do not load curlrc, use a proxy, follow redirects, or print response bodies.
request() {
  method=$1 path=$2
  shift 2
  response=$(curl --disable --silent --fail --noproxy '*' \
    --connect-timeout "$HTTP_TIMEOUT" --max-time "$HTTP_TIMEOUT" \
    --write-out '\n%{http_code}' \
    --request "$method" "$@" "$VAULT_ADDR$path" 2>/dev/null) || return 1
  newline='
'
  case "$response" in
    *"$newline"200) printf '%s' "${response%"$newline"200}" ;;
    *) return 1 ;;
  esac
}

valid_status() {
  jq -se 'length == 1 and (.[0] |
    type == "object" and
    (.initialized | type) == "boolean" and
    (.sealed | type) == "boolean" and
    (.migration | type) == "boolean" and
    (.type | type) == "string" and
    (.t | type) == "number" and .t >= 0 and .t == (.t | floor))
  ' >/dev/null 2>&1
}

read_status() {
  status=$(request GET /v1/sys/seal-status) &&
    printf '%s' "$status" | valid_status
}

unseal() {
  if ! read_status; then
    log 'ERROR: Vault status request failed or returned invalid JSON'
    return
  fi
  if [ "$(printf '%s' "$status" | jq -r .initialized)" != true ]; then
    log 'ERROR: Vault is not initialized; initialization requires an operator'
    return
  fi
  if [ "$(printf '%s' "$status" | jq -r .migration)" != false ] ||
     [ "$(printf '%s' "$status" | jq -r .type)" != shamir ]; then
    log 'ERROR: unseal requires Shamir with no seal migration in progress'
    return
  fi
  if [ "$(printf '%s' "$status" | jq -r .sealed)" = false ]; then
    log 'Vault is unsealed'
    return
  fi

  threshold=$(printf '%s' "$status" | jq -r .t)
  if [ "$threshold" -le 0 ] || [ ! -r "$UNSEAL_KEYS_FILE" ]; then
    log 'ERROR: invalid threshold or unreadable unseal keys file'
    return
  fi
  # Validate the number of distinct shares without passing any share via argv.
  if ! jq -Rse --argjson threshold "$threshold" '
    split("\n") | map(rtrimstr("\r")) | map(select(length > 0)) |
    unique | length >= $threshold
  ' < "$UNSEAL_KEYS_FILE" >/dev/null 2>&1; then
    log 'ERROR: unseal keys file has fewer distinct shares than Vault requires'
    return
  fi

  while IFS= read -r key || [ -n "$key" ]; do
    key=${key%"$(printf '\r')"}
    [ -n "$key" ] || continue
    if ! reply=$(printf '%s' "$key" | jq -Rs '{key: .}' |
      request PUT /v1/sys/unseal --header 'Content-Type: application/json' --data-binary @-); then
      log 'ERROR: unseal request failed; retrying after the next check'
      return
    fi
    if ! printf '%s' "$reply" | valid_status; then
      log 'ERROR: invalid unseal response; retrying after the next check'
      return
    fi
    if ! printf '%s' "$reply" | jq -e '
      .initialized == true and .type == "shamir" and .migration == false
    ' >/dev/null; then
      log 'ERROR: Vault seal state changed during unseal; waiting for the next check'
      return
    fi
    if [ "$(printf '%s' "$reply" | jq -r .sealed)" = false ]; then
      break
    fi
  done < "$UNSEAL_KEYS_FILE"
  unset key reply

  # A successful HTTP request is not proof that unseal completed.
  if read_status && printf '%s' "$status" | jq -e '
    .initialized == true and .sealed == false and
    .type == "shamir" and .migration == false
  ' >/dev/null; then
    log 'Vault is unsealed'
  else
    log 'ERROR: Vault unseal was not confirmed; retrying after the next check'
  fi
}

sleep_pid=
trap '[ -z "$sleep_pid" ] || kill "$sleep_pid" 2>/dev/null; exit 0' TERM INT
while :; do
  unseal
  sleep "$CHECK_INTERVAL" &
  sleep_pid=$!
  wait "$sleep_pid" || true
  sleep_pid=
done
