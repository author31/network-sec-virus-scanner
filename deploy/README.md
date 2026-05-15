# Deploying the Malshare refresh

Sentinel keeps `data/signatures.json` fresh by pulling the Malshare 24-hour
hash feed once per day. Three deployment shapes are supported. Pick **one**;
running more than one against the same DB at the same time is harmless
(the writer is atomic and the merge is dedupe-by-hash) but wastes quota.

| Option | When to use | File |
|--------|-------------|------|
| System `cron` | Bare-metal / VM with a local cron daemon | [`cron/fetch-malshare.cron`](cron/fetch-malshare.cron) |
| Kubernetes `CronJob` | Running on K8s | [`k8s/fetch-malshare-cronjob.yaml`](k8s/fetch-malshare-cronjob.yaml) |
| `sentinel daemon start` | Long-running container / VM with **no** system cron | binary subcommand |

**Schedule (all three): `17 03 * * *` UTC** — a few minutes after the
Malshare 24h feed window rolls so we don't fetch into an empty window.
Override with `--schedule "<cron>"` or `$SENTINEL_SCHEDULE` where supported.

## API key — rotate before enabling

The Malshare API key was previously pasted in plaintext in issue history.
**Treat it as compromised.** Before enabling any of the options below:

1. Rotate the key on https://malshare.com/.
2. Store the rotated key in your secret backend (systemd `EnvironmentFile`,
   Kubernetes `Secret`, Vault, etc.) — never in a file inside this repo.
3. Inject the value into the process at runtime as `MALSHARE_API_KEY`.

The fetch script reads the key only from the environment and never writes
it to disk or logs.

## Option 1 — system `cron`

```bash
# Install the binary and data dir
sudo install -d -o sentinel -g sentinel /opt/sentinel /var/log/sentinel
sudo rsync -a ./ /opt/sentinel/    # or git clone + uv sync as the service user
sudo -u sentinel uv --project /opt/sentinel sync

# Wire the secret. Mode 0600, owned by the cron user.
sudo install -d -m 0750 -o root -g sentinel /etc/sentinel
sudo install -m 0600 -o sentinel -g sentinel /dev/null /etc/sentinel/env
echo "MALSHARE_API_KEY=<rotated-key>" | sudo tee -a /etc/sentinel/env > /dev/null

# Install the cron file
sudo install -m 0644 deploy/cron/fetch-malshare.cron /etc/cron.d/sentinel-fetch-malshare
```

The cron entry runs as the `sentinel` user, sources `/etc/sentinel/env`,
wraps the fetch in `timeout 300`, and appends stdout/stderr to
`/var/log/sentinel/fetch-malshare.log`. A non-zero exit triggers the
standard cron MAILTO path (`oncall@example.com` — change in the file).

**Manual one-off run:**

```bash
sudo -u sentinel env $(cat /etc/sentinel/env) \
    /opt/sentinel/.venv/bin/python /opt/sentinel/scripts/fetch_malshare.py
```

**Inspect last run:** `tail -n 50 /var/log/sentinel/fetch-malshare.log`.

## Option 2 — Kubernetes `CronJob`

```bash
kubectl create namespace sentinel
kubectl -n sentinel create secret generic sentinel-malshare \
    --from-literal=MALSHARE_API_KEY='<rotated-key>'
kubectl -n sentinel apply -f deploy/k8s/fetch-malshare-cronjob.yaml
```

The manifest:

- pins `schedule: "17 03 * * *"` with `timeZone: Etc/UTC`,
- uses `concurrencyPolicy: Forbid` (no overlapping runs),
- sets `backoffLimit: 0` so a failed `Job` is preserved for inspection,
- sets `activeDeadlineSeconds: 300` (5 min hard cap),
- mounts a `PersistentVolumeClaim` named `sentinel-data` at `/data` for the
  signature DB.

**Manual one-off run** (creates an ad-hoc Job from the CronJob template):

```bash
kubectl -n sentinel create job --from=cronjob/sentinel-fetch-malshare \
    fetch-malshare-manual-$(date +%s)
```

**Inspect last run:**

```bash
kubectl -n sentinel get jobs --selector=app=sentinel,component=signature-refresh
kubectl -n sentinel logs job/<job-name>
```

**Failure alert path:** failed runs leave `kube_job_status_failed` non-zero;
the existing `JobFailed` Prometheus alert pages oncall.

## Option 3 — `sentinel daemon start`

Use this when the deploy target is a long-running container or VM **without**
system cron (e.g. minimal distroless images, `restricted` Kubernetes
`Deployment`s where adding a sidecar `cron` daemon is undesirable). It runs
the cron schedule **in-process**.

```bash
MALSHARE_API_KEY=<rotated-key> sentinel daemon start --run-now
```

Common flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--schedule "<cron>"` | `17 03 * * *` (UTC) | Cron expression; also via `$SENTINEL_SCHEDULE`. |
| `--run-now` | _off_ | Fetch once at startup before the first scheduled tick. |
| `--detach` | _off_ | Daemonise (double-fork). Default is foreground for systemd / container supervisors. |
| `--pidfile PATH` | _none_ | Write the daemon PID to PATH; removed on shutdown. |
| `--output PATH` | `data/signatures.json` | Signature DB path. |
| `--threat-level {low,medium,high,critical}` | `medium` | Label applied to imported entries. |
| `--timeout SECONDS` | `60` | HTTP timeout per fetch. |
| `-v` / `-vv` | _warn_ | Log verbosity. |

**Behaviour:**

- Refuses to start (exit non-zero) when `MALSHARE_API_KEY` is unset.
- Refuses to start (exit non-zero) when `--schedule` / `$SENTINEL_SCHEDULE`
  is not a valid 5-field cron expression.
- Logs to stdout/stderr in the same format as the cronjob path. No key
  material is ever logged.
- On `SIGTERM` / `SIGINT` the daemon lets the in-flight fetch (if any)
  finish, then exits. The fetch writes `data/signatures.json` atomically
  (tempfile + `os.replace`), so an abort can never leave a half-written
  file.
- A scheduled fetch failure is logged and the loop continues — a single
  bad upstream response does not crash the daemon. Persistent failures
  surface through the usual log monitoring path.
- Exit codes: `0` clean shutdown; non-zero (`2`) on config / auth /
  scheduler init failure.

**systemd unit (example):**

```ini
[Unit]
Description=Sentinel Malshare refresh daemon
After=network-online.target

[Service]
Type=simple
User=sentinel
EnvironmentFile=/etc/sentinel/env
ExecStart=/opt/sentinel/.venv/bin/sentinel daemon start --pidfile /run/sentinel/daemon.pid
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

**Manual one-off run** (same as Option 1; the daemon and the script share
a code path):

```bash
MALSHARE_API_KEY=<rotated-key> uv run python scripts/fetch_malshare.py
```

## Failure alerting (all options)

| Option | Where it surfaces | Who gets paged |
|--------|-------------------|----------------|
| System `cron` | Non-zero exit → cron `MAILTO` → log line in `/var/log/sentinel/fetch-malshare.log` | `oncall@example.com` (edit the cron file) |
| Kubernetes `CronJob` | `kube_job_status_failed` non-zero → `JobFailed` Prometheus alert | platform on-call rota |
| `sentinel daemon start` | `level=error` log line; systemd `Restart=on-failure` triggers on config/init exits | service oncall — wire log alert on `level=error scheduled fetch failed` |
