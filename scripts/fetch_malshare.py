"""Fetch Malshare 24h hash list and merge into the signature DB.

Reads ``MALSHARE_API_KEY`` from the environment, calls
``GET https://malshare.com/api.php?api_key=...&action=getlist``, normalizes each
record into the signature schema (see ``sentinel.repository``), and merges into
``data/signatures.json`` deduping by md5/sha256.

The API key is read from the environment only; it is never logged or written
to disk.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

# Make ``src`` importable when this script is invoked directly.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from sentinel.repository import SignatureRepository, SignatureValidationError  # noqa: E402


MALSHARE_URL = "https://malshare.com/api.php"
DEFAULT_OUTPUT = _REPO_ROOT / "data" / "signatures.json"
DEFAULT_THREAT_LEVEL = "medium"
DEFAULT_TIMEOUT_SECONDS = 60
USER_AGENT = "sentinel-fetch-malshare/1.0"

log = logging.getLogger("fetch_malshare")


class FetchError(RuntimeError):
    """Raised when the Malshare API call or response parsing fails."""


@dataclass(frozen=True)
class MergeStats:
    added: int
    skipped_duplicate: int
    skipped_invalid: int
    total: int


def _build_url(api_key: str) -> str:
    qs = urllib.parse.urlencode({"api_key": api_key, "action": "getlist"})
    return f"{MALSHARE_URL}?{qs}"


def fetch_getlist(api_key: str, *, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> list[dict]:
    """Call Malshare ``getlist`` and return the parsed JSON list."""

    if not api_key:
        raise FetchError("MALSHARE_API_KEY is not set")

    request = urllib.request.Request(
        _build_url(api_key),
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310
            status = resp.status
            body = resp.read()
    except urllib.error.HTTPError as exc:
        raise FetchError(f"Malshare HTTP {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise FetchError(f"Malshare network error: {exc.reason}") from exc

    if status != 200:
        raise FetchError(f"Malshare returned HTTP {status}")

    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FetchError(f"Malshare response is not valid JSON: {exc}") from exc

    if not isinstance(decoded, list):
        raise FetchError("Malshare response was not a JSON list")
    return decoded


def _is_hex(value: str, length: int) -> bool:
    if len(value) != length:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def normalize_entry(
    raw: object,
    *,
    fetched_at: str,
    threat_level: str = DEFAULT_THREAT_LEVEL,
) -> Optional[dict]:
    """Normalize a single Malshare record into a signature dict.

    Returns ``None`` if the record carries no usable hash.
    """

    md5: Optional[str] = None
    sha256: Optional[str] = None

    if isinstance(raw, dict):
        for key in ("md5", "MD5"):
            v = raw.get(key)
            if isinstance(v, str) and _is_hex(v, 32):
                md5 = v.lower()
                break
        for key in ("sha256", "SHA256"):
            v = raw.get(key)
            if isinstance(v, str) and _is_hex(v, 64):
                sha256 = v.lower()
                break
    elif isinstance(raw, str):
        if _is_hex(raw, 32):
            md5 = raw.lower()
        elif _is_hex(raw, 64):
            sha256 = raw.lower()

    if md5 is None and sha256 is None:
        return None

    fingerprint = sha256 or md5
    name = f"Malshare-{fingerprint[:12]}"
    entry: dict[str, str] = {
        "name": name,
        "threat_level": threat_level,
        "description": f"Imported from Malshare getlist on {fetched_at}.",
    }
    if md5 is not None:
        entry["md5"] = md5
    if sha256 is not None:
        entry["sha256"] = sha256
    return entry


def _load_existing(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise FetchError(f"existing {path} is not a JSON list")
    return data


def _dedupe_keys(entry: dict) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    if isinstance(entry.get("md5"), str):
        keys.add(("md5", entry["md5"].lower()))
    if isinstance(entry.get("sha256"), str):
        keys.add(("sha256", entry["sha256"].lower()))
    return keys


def merge_entries(
    existing: list[dict], incoming: Iterable[dict]
) -> tuple[list[dict], MergeStats]:
    """Merge ``incoming`` into ``existing``, deduping by md5/sha256."""

    seen: set[tuple[str, str]] = set()
    for entry in existing:
        seen.update(_dedupe_keys(entry))

    merged = list(existing)
    added = 0
    skipped_dup = 0
    for entry in incoming:
        keys = _dedupe_keys(entry)
        if not keys:
            skipped_dup += 1
            continue
        if keys & seen:
            skipped_dup += 1
            continue
        seen.update(keys)
        merged.append(entry)
        added += 1
    return merged, MergeStats(
        added=added,
        skipped_duplicate=skipped_dup,
        skipped_invalid=0,
        total=len(merged),
    )


def _atomic_write_json(path: Path, payload: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=False)
            fh.write("\n")
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def refresh(
    *,
    output: Path,
    api_key: str,
    threat_level: str = DEFAULT_THREAT_LEVEL,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    fetcher=fetch_getlist,
    now: Optional[datetime] = None,
    dry_run: bool = False,
) -> MergeStats:
    """Fetch, normalize, merge, validate, and write the signature DB."""

    fetched_at = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
    raw_records = fetcher(api_key, timeout=timeout)

    invalid = 0
    normalized: list[dict] = []
    for rec in raw_records:
        entry = normalize_entry(rec, fetched_at=fetched_at, threat_level=threat_level)
        if entry is None:
            invalid += 1
            continue
        normalized.append(entry)

    existing = _load_existing(output)
    merged, stats = merge_entries(existing, normalized)
    stats = MergeStats(
        added=stats.added,
        skipped_duplicate=stats.skipped_duplicate,
        skipped_invalid=invalid,
        total=stats.total,
    )

    # Validate the result is loadable by the production loader before persisting.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        json.dump(merged, tmp)
        tmp_path = Path(tmp.name)
    try:
        SignatureRepository.load(tmp_path)
    except SignatureValidationError as exc:
        raise FetchError(f"merged signature DB failed validation: {exc}") from exc
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass

    if not dry_run:
        _atomic_write_json(output, merged)
    return stats


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Refresh signature DB from Malshare getlist."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Path to signature DB JSON (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--threat-level",
        default=DEFAULT_THREAT_LEVEL,
        choices=("low", "medium", "high", "critical"),
        help="Threat level applied to imported Malshare entries.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch + validate without writing the output file.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose logging."
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(list(sys.argv[1:] if argv is None else argv))
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    api_key = os.environ.get("MALSHARE_API_KEY", "")
    try:
        stats = refresh(
            output=args.output,
            api_key=api_key,
            threat_level=args.threat_level,
            timeout=args.timeout,
            dry_run=args.dry_run,
        )
    except FetchError as exc:
        log.error("fetch failed: %s", exc)
        return 1

    log.info(
        "signature DB %s: added=%d, deduped=%d, invalid=%d, total=%d",
        "validated (dry-run)" if args.dry_run else f"updated -> {args.output}",
        stats.added,
        stats.skipped_duplicate,
        stats.skipped_invalid,
        stats.total,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
