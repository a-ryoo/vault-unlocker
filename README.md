# Vault Unlocker

Unseal-only sidecar for an **already initialized Shamir-sealed Vault**. It checks
the local Vault API repeatedly and submits mounted key shares when Vault is
sealed, including after the Vault container restarts independently of the sidecar.

This version intentionally removes automatic initialization, root-token storage,
Kubernetes API access and the ConfigMap initialization lock. It never migrates a
seal or resets another operator's unseal progress. Complete any KMS-to-Shamir
migration before enabling it.

## Configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `VAULT_ADDR` | `http://127.0.0.1:8200` | Local Vault API; HTTPS certificate verification stays enabled |
| `UNSEAL_KEYS_FILE` | `/vault/unseal/unseal_keys` | File containing one unseal share per line |
| `CHECK_INTERVAL` | `5` | Seconds between checks/retries |
| `HTTP_TIMEOUT` | `5` | Maximum seconds for an HTTP request |

The threshold comes from Vault. Provide at least that many distinct valid shares.
The existing Secret's `unseal_keys` key can be mounted directly: Kubernetes
decodes its base64 value into the newline-separated file. Do not put key shares
in Helm values, environment variables or image layers. A root token is not used.

Missing keys, API errors, uninitialized Vault, non-Shamir seals and an active
seal migration must not result in initialization or an apparent successful unseal.
The sidecar retries and reloads the file, allowing projected Secret updates to
take effect without restarting it. Mount the directory, **not `subPath`**.

Continuous unseal also reverses an intentional manual seal. Disable the sidecar
through its deployment owner **before** sealing Vault for maintenance or incident
response. Possession of enough shares grants unseal capability: restrict access
to the Secret and keep an independently recoverable encrypted copy outside Vault.

## Helm integration

`manifests/helm-values.yaml` is a fragment for HashiCorp Vault chart `0.34.1`.
It adds the sidecar and mounts only the `unseal_keys` field of the existing Secret.
Replace the local test image with the published image digest before deployment.
The fragment does not change the Vault server image, seal, storage or replica count.

Use `server.volumes`, rather than `server.extraVolumes`: the latter would also
mount the key material into the main Vault container. Pod `fsGroup: 1000` makes the
0440 Secret volume readable by the sidecar; this matches the current HQ Vault pod.
Keep the Secret in place and backed up before deploying the sidecar.

An empty read-only mount at the standard ServiceAccount token path suppresses
automatic token mounting into the sidecar. The main Vault container retains its
token for service registration. Keep `shareProcessNamespace` disabled; containers
within one Pod are not a strong isolation boundary.

The old `manifests/rbac.yaml` is removed because the unlocker needs no Kubernetes
API permissions. Retire its `vault-secret-access` Role/RoleBinding through their
deployment owner; **retain the Vault server's ServiceAccount and its own RBAC**.
An ESO-sourced Secret must have an independent cold-start recovery path: ESO
cannot read keys or database credentials from the Vault it is trying to start.

## Check and build

Local tests use Python's standard library, a loopback mock Vault API, POSIX `sh`,
`curl` and `jq`. They do not connect to a real Vault or use real key shares.

```sh
sh -n scripts/unlocker.sh
python3 -m unittest discover -s tests -v
docker build --platform linux/amd64 -t vault-unlocker:local .
```

The base image is pinned by digest. APK packages receive fixes from that Alpine
release's repositories; builds are not claimed to be bit-for-bit reproducible.
Publish a release only after tests/build pass, then deploy the resulting GHCR
image **by digest**. CI verifies pushes and pull requests; only a published release
can push an image. The release image currently targets `linux/amd64`.
