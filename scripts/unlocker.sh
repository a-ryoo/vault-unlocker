#!/bin/sh
set -eu

VAULT_ADDR="http://localhost:8200"
SECRET_NAME="vault-unseal-keys"
LOCK_NAME="vault-init-lock"
NAMESPACE="${POD_NAMESPACE:-vault}"
KEY_COUNT=5
THRESHOLD=3
MAX_WAIT=60

log() {
  echo "[$(date +%H:%M:%S)] $*"
}

# 1. Check if Vault is initialized
is_initialized=$(curl -s "${VAULT_ADDR}/v1/sys/init" | jq -r .initialized)

if [ "$is_initialized" = "false" ]; then
  log "Vault is not initialized. Trying to acquire init lock..."

  acquire_lock() {
    kubectl create configmap "${LOCK_NAME}" \
      --from-literal=holder="$(hostname)" \
      -n "${NAMESPACE}" >/dev/null 2>&1
  }

  lock_acquired=0
  for i in $(seq 1 30); do
    if acquire_lock; then
      log "Lock acquired. Proceeding with Vault initialization."

      init_json=$(curl -s --request PUT \
        --data "{\"secret_shares\": ${KEY_COUNT}, \"secret_threshold\": ${THRESHOLD}}" \
        "${VAULT_ADDR}/v1/sys/init")

      root_token=$(echo "$init_json" | jq -r .root_token)
      unseal_keys_multiline=$(echo "$init_json" | jq -r '.keys_base64[]')

      b64_keys=$(printf '%s\n' "$unseal_keys_multiline" | base64 | tr -d '\n')
      b64_token=$(printf '%s' "$root_token" | base64 | tr -d '\n')

      secret_yaml=$(cat <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${SECRET_NAME}
  namespace: ${NAMESPACE}
type: Opaque
data:
  unseal_keys: ${b64_keys}
  root_token: ${b64_token}
EOF
)
      log "Creating Kubernetes secret ${SECRET_NAME} in namespace ${NAMESPACE}..."
      echo "$secret_yaml" | kubectl apply -f -
      log "Secret created."

      # Release the lock
      kubectl delete configmap "${LOCK_NAME}" -n "${NAMESPACE}" >/dev/null 2>&1 || true
      lock_acquired=1
      break
    else
      log "Waiting for init lock... (${i}s)"
      sleep 2
    fi
  done

  if [ "$lock_acquired" -ne 1 ]; then
    log "ERROR: Could not acquire lock to initialize Vault. Exiting."
    exit 1
  fi
else
  log "Vault already initialized. Skipping init."
fi

# 2. Wait for unseal keys secret to appear
i=0
while ! kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" >/dev/null 2>&1; do
  [ "$i" -ge "$MAX_WAIT" ] && {
    log "ERROR: Timeout waiting for ${SECRET_NAME} to appear."
    exit 1
  }
  log "Waiting for secret ${SECRET_NAME}... (${i}s)"
  sleep 2
  i=$((i + 2))
done

unseal_keys_multiline=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath="{.data.unseal_keys}" | base64 -d)

# 3. Unseal if needed
is_sealed=$(curl -s "${VAULT_ADDR}/v1/sys/seal-status" | jq -r .sealed)

if [ "$is_sealed" = "true" ]; then
  log "Vault is sealed. Unsealing..."

  i=0
  echo "$unseal_keys_multiline" | while IFS= read -r key; do
    curl -s --request PUT --data "{\"key\": \"${key}\"}" "${VAULT_ADDR}/v1/sys/unseal" > /dev/null
    i=$((i + 1))
    [ "$i" -ge "$THRESHOLD" ] && break
    sleep 1
  done

  log "Vault unsealed."
else
  log "Vault is already unsealed."
fi