from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

MALSHARE_URL = "https://malshare.com/api.php"
USER_AGENT = "sentinel-update/1.0"
DEFAULT_TIMEOUT_SECONDS = 60


class FetchError(RuntimeError):
    """Raised when the Malshare API call or response parsing fails."""


def _build_url(api_key: str) -> str:
    qs = urllib.parse.urlencode({"api_key": api_key, "action": "getlist"})
    return f"{MALSHARE_URL}?{qs}"


def fetch_getlist(
    api_key: str, *, timeout: int = DEFAULT_TIMEOUT_SECONDS
) -> list:
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
