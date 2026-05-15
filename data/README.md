# Signature Database

`signatures.json` is the malware signature database consumed by Sentinel.
Each entry follows the schema enforced by `sentinel.repository.SignatureRepository`.

## Schema

Per entry (see `src/sentinel/repository/signature.py`):

| Field          | Required | Notes                                                       |
|----------------|----------|-------------------------------------------------------------|
| `name`         | yes      | Non-empty string                                            |
| `threat_level` | yes      | One of `low`, `medium`, `high`, `critical`                  |
| `md5`          | one of\* | 32-char hex                                                 |
| `sha256`       | one of\* | 64-char hex                                                 |
| `hex_pattern`  | one of\* | Even-length hex, used by the byte-pattern scan engine       |
| `description`  | no       | Free-text                                                   |

\* At least one of `md5`, `sha256`, or `hex_pattern` must be present.

## Canary

The repo ships with one signature retained by convention: the **EICAR** test
file. It exposes `md5`, `sha256`, and `hex_pattern`, so the scanner self-test
works end-to-end without any network access. Do not remove or rename it.

## Refreshing from Malshare

`scripts/fetch_malshare.py` pulls the 24-hour hash feed from
[Malshare](https://malshare.com/doc.php) and merges new hashes into
`signatures.json` (dedup by `md5`/`sha256`).

### Set the API key

```bash
export MALSHARE_API_KEY=...   # never commit this value
```

The script reads `MALSHARE_API_KEY` from the environment. It is never written
to disk or logs. If the key has previously been pasted in plaintext (issue
history, chat), rotate it on Malshare before use.

### Run a refresh

```bash
uv run python scripts/fetch_malshare.py
```

Useful flags:

- `--output PATH` — write to a different signature DB file
- `--threat-level {low,medium,high,critical}` — label applied to imported
  entries (default `medium`; Malshare's feed does not carry severity)
- `--timeout SECONDS` — HTTP timeout (default 60)
- `--dry-run` — fetch and validate, but do not write
- `--verbose` — debug logs

The script:

1. Calls `GET https://malshare.com/api.php?api_key=$MALSHARE_API_KEY&action=getlist`.
2. Normalizes each record into the signature schema. Imported entries get
   `name = "Malshare-<sha256-prefix>"` and a description noting the import
   date. The Malshare feed does not include a name field.
3. Merges into the existing DB, deduping by `md5` and `sha256`. The EICAR
   canary is preserved.
4. Validates the merged DB through `SignatureRepository.load` before writing.
5. Writes atomically (temp file + rename) on success.

Re-running the script is **idempotent** — only previously-unseen hashes are
added.

### Refresh cadence

Production deployments run the script **once per day at `17 03 * * *` UTC**
(a few minutes after the Malshare 24h feed window rolls over). The schedule
is documented and enforced in three interchangeable deployment shapes:

- System cron: [`deploy/cron/fetch-malshare.cron`](../deploy/cron/fetch-malshare.cron)
- Kubernetes `CronJob`: [`deploy/k8s/fetch-malshare-cronjob.yaml`](../deploy/k8s/fetch-malshare-cronjob.yaml)
- In-process daemon: `sentinel daemon start` (see
  [`deploy/README.md`](../deploy/README.md))

All three are configured to the same `17 03 * * *` UTC schedule. Override
the daemon via `--schedule "<cron>"` or `$SENTINEL_SCHEDULE`.

This module only owns the dataset + script; the deploy artifacts live under
`deploy/`.
