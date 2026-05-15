# Sentinel

Sentinel is a small, educational virus scanner written in Python. It walks a
directory tree and inspects every file with three complementary engines:

- **Hash scan** — MD5 and SHA-256 lookup against a signature database.
- **Byte-pattern scan** — hex-pattern (e.g. EICAR prefix) lookup against the
  same database.
- **Heuristic scan** — configurable regex rules that flag suspicious content
  (PowerShell encoded commands, shell `eval(` markers, long base64 blobs, …).

A scan emits a single log report listing every finding plus a summary block,
and exits non-zero when anything is flagged so it can drive CI gates.

**Scope.** Linux, Python 3.12+. Sentinel is a teaching / demo tool — it is
not a production antivirus, has no realtime protection, no sandbox, and does
not unpack archives. See [Limitations](#limitations).

## Install

Sentinel uses [uv](https://docs.astral.sh/uv/) for environment management.

```bash
git clone https://github.com/author31/network-sec-virus-scanner.git
cd network-sec-virus-scanner
uv sync                         # creates .venv and installs deps
```

A plain `pip` flow also works if you prefer:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .                # exposes the `sentinel` console script
```

Verify the install:

```bash
uv run sentinel scan --help
```

## Usage

```
sentinel scan DIR [--db PATH] [--rules PATH] [--report PATH]
                  [--max-size BYTES] [-v|-vv]
```

| Flag | Default | Purpose |
|------|---------|---------|
| `--db` | `data/signatures.json` | Signature DB JSON path. |
| `--rules` | `data/heuristic_rules.example.json` | Heuristic rules JSON path. |
| `--report` | `./sentinel_report_<UTC>.log` | Report output file. |
| `--max-size` | _(none)_ | Skip files larger than this many bytes. |
| `-v` / `-vv` | _warn_ | Increase log verbosity (info / debug). |

Exit codes: `0` clean, `1` infected or suspicious, `2` error.

### EICAR demo (≈30 seconds)

The repo ships with a tiny demo tree containing a real EICAR test string. It
is the fastest way to confirm everything works.

```bash
uv sync
uv run sentinel scan tests/fixtures/demo_tree --report /tmp/sentinel.log
```

Expected output:

```
Scanned 5 file(s): 2 infected, 1 suspicious, 2 clean. Report: /tmp/sentinel.log
```

> The `eicar.com` fixture contains the canonical EICAR test string. It is
> harmless by design, but some endpoint security products may quarantine it
> on checkout — restore from `git` if that happens.

### More examples

Scan a directory with custom rules and a fixed report path:

```bash
uv run sentinel scan ~/Downloads \
    --db data/signatures.json \
    --rules data/heuristic_rules.example.json \
    --report ./reports/downloads.log -v
```

Skip very large files:

```bash
uv run sentinel scan /var/log --max-size $((50 * 1024 * 1024))
```

## Signature DB format

`data/signatures.json` is a JSON array. Each entry must supply at least one of
`md5`, `sha256`, or `hex_pattern`. Full schema, validation rules, and
refresh-from-Malshare instructions live in
[`data/README.md`](data/README.md).

Minimal entry:

```json
{
  "name": "EICAR-Test-File",
  "threat_level": "low",
  "md5": "44d88612fea8a8f36de82e1278abb02f",
  "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "hex_pattern": "58354f2150254041505b345c505a58353428",
  "description": "EICAR antivirus test string."
}
```

`threat_level` ∈ `{low, medium, high, critical}`.

## Heuristic rule format

`data/heuristic_rules.example.json` is a JSON array of regex rules applied to
each file's textual content (UTF-8, errors replaced). Schema:

| Field | Required | Notes |
|-------|----------|-------|
| `name` | yes | Stable rule identifier shown in reports. |
| `pattern` | yes | Python `re` regex. Use `(?i)` for case-insensitive. |
| `severity` | yes | `low`, `medium`, `high`, or `critical`. |
| `description` | no | Free-text explanation. |

Example:

```json
{
  "name": "powershell-encoded-command",
  "pattern": "(?i)powershell(\\.exe)?\\s+-(?:e|en|enc|encodedcommand)\\b",
  "severity": "high",
  "description": "PowerShell launched with -EncodedCommand obfuscation."
}
```

## Sample report

Every finding is one pipe-delimited line followed by a summary block:

```
<UTC timestamp> | <absolute path> | <detection method> | <signature/rule> | <severity>
```

Real output from the bundled demo:

```
2026-05-15T14:29:05Z | .../demo_tree/top/sub1/deep/eicar.com       | hash:sha256                | EICAR-Test-File     | low
2026-05-15T14:29:05Z | .../demo_tree/top/sub1/deep/eicar.com       | pattern:hex                | EICAR-Test-File     | low
2026-05-15T14:29:05Z | .../demo_tree/top/sub2/suspicious.txt       | heuristic:shell-eval-marker| shell-eval-marker   | medium
2026-05-15T14:29:05Z | .../demo_tree/top/sub2/with_pattern.bin     | pattern:hex                | EICAR-Test-File     | low

=== Scan Summary ===
Started:        2026-05-15T14:29:05Z
Ended:          2026-05-15T14:29:05Z
Duration:       0.001s
Total scanned:  5
Clean:          2
Infected:       2
Suspicious:     1
=====================
```

## Demo fixture: `tests/fixtures/demo_tree/`

```
tests/fixtures/demo_tree/
└── top/
    ├── clean1.txt                  # clean — plain text
    ├── sub1/
    │   ├── clean2.bin              # clean — small binary
    │   └── deep/
    │       └── eicar.com           # infected — full EICAR (hash + hex hits)
    └── sub2/
        ├── with_pattern.bin        # infected — EICAR hex prefix embedded
        └── suspicious.txt          # suspicious — `shell-eval-marker` hit
```

End-to-end smoke test:

```bash
uv run pytest tests/test_demo_tree_smoke.py
```

## Limitations

- **Not a real antivirus.** Signature coverage is intentionally tiny (an
  EICAR canary plus whatever you import via Malshare). Heuristics are simple
  regex rules — easy to fool with light obfuscation.
- **Archive unpacking is optional and container-sandboxed (off by
  default).** Pass `--unpack-archives` to extract zip / tar / gzip / bz2 /
  xz / 7z / rar inside an isolated Docker container and scan their
  contents. See [Archive unpacking](#archive-unpacking) below. Without the
  flag, archives are scanned as opaque blobs (the historical behavior).
- **No realtime / on-access scanning.** Sentinel is a one-shot CLI.
- **Linux-only.** Tested on Linux + CPython 3.12; paths and permissions are
  not validated on other platforms.
- **Whole-file regex.** Heuristic content is read up to a bounded ceiling per
  file; very large files may have content past the ceiling skipped.

Treat findings as hints, not verdicts.

## Archive unpacking

When `--unpack-archives` is set, each archive encountered by the directory
walker is handed off to the *archive scan engine*. The engine launches a
**fresh Docker container per archive layer**:

- Archive mounted read-only at `/in/archive.bin`.
- Extraction target is a `tmpfs` at `/work` with a size cap.
- Signature DB + heuristic rules mounted read-only at `/rules`.
- Container is launched with `--network=none`, a read-only root
  filesystem, `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
  a non-root UID, and pid / memory / cpu caps.
- Container is `--rm`'d unconditionally; the tmpfs disappears with it.

Findings discovered inside an archive are folded into the parent report
with a *provenance path* using `!` as the separator, matching the same
convention as `jar` / `zipinfo` tooling:

```
2026-05-15T15:10:42Z | /var/scan/outer.zip!inner.tar!eicar.com | hash:sha256 | EICAR-Test-File | low
```

Skipped archives (cap exceeded, timeout, unsupported format, missing
unpacker) are visible in the report with detection method
`archive:skipped:<reason>` and severity `low`. They do **not** bump the
infected or suspicious counts and do **not** change the exit code.

Build the sandbox image once with the bundled `Dockerfile.archive-sandbox`:

```bash
docker build -f Dockerfile.archive-sandbox -t sentinel/archive-sandbox:latest .
```

Then opt in at scan time:

```bash
uv run sentinel scan tests/fixtures/archive_tree \
    --unpack-archives \
    --archive-depth 3 \
    --archive-max-extracted-bytes $((512 * 1024 * 1024)) \
    --archive-max-files 10000 \
    --archive-timeout 60 \
    --archive-image sentinel/archive-sandbox:latest
```

If Docker is unavailable and `--unpack-archives` was requested, Sentinel
exits non-zero with a clear message (exit code `2`). For environments
without Docker (test runners, dev loops), set
`SENTINEL_ARCHIVE_BACKEND=local` to run the same extract-and-scan logic
in-process — without sandbox isolation. **Do not enable the local backend
on untrusted input.**

## Roadmap

- **Bloom filter** in front of the hash repository to keep large signature
  DBs cheap to query.
- **Parallel scan** across files (process pool) for big trees.
- **Streaming heuristic engine** so very large files aren't bounded by the
  in-memory read ceiling.

## Shipped

- **Archive unpacking** (zip / tar / gzip / bz2 / xz / 7z / rar) with a
  configurable depth cap and per-archive Docker sandbox.

## Development

```bash
uv sync                  # install dev deps (pytest)
uv run pytest            # run the full suite
uv run pytest tests/test_demo_tree_smoke.py   # just the smoke test
```

See [`CLAUDE.md`](CLAUDE.md) for project conventions (uv only, DDD layout).
