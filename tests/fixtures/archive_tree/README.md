# `archive_tree` — archive-unpacking smoke fixtures

Tiny archives used by `tests/test_archive_tree_smoke.py` to exercise the
`--unpack-archives` code path end-to-end.

| File | Purpose |
|------|---------|
| `flat_eicar.zip` | Single-layer zip wrapping the canonical EICAR string. Should produce a hash-and-pattern hit with provenance `flat_eicar.zip!eicar.com`. |
| `nested_eicar.tar.gz` | `tar.gz` → `inner.zip` → `payload/eicar.com`. Exercises depth-2 recursion. |
| `clean.zip` | Two harmless text files. Should produce zero findings. |
| `zipbomb_small.zip` | A 200 KiB payload of `A` bytes compressed to ~300 B. Used to exercise `--archive-max-extracted-bytes`; with a small cap it is reported as `archive:skipped`. |

The EICAR payload is the public test string; it is harmless by design.

Regenerate with:

```bash
python3 - <<'PY'
import zipfile, tarfile, io
from pathlib import Path
EICAR = (
    b"X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
ROOT = Path("tests/fixtures/archive_tree")
ROOT.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(ROOT / "flat_eicar.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("eicar.com", EICAR)
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as iz:
    iz.writestr("payload/eicar.com", EICAR)
with tarfile.open(ROOT / "nested_eicar.tar.gz", "w:gz") as t:
    info = tarfile.TarInfo("inner.zip"); info.size = len(buf.getvalue())
    t.addfile(info, io.BytesIO(buf.getvalue()))
with zipfile.ZipFile(ROOT / "clean.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("readme.txt", "this is a clean text file\nno malware here\n")
    z.writestr("notes/clean.md", "all good\n")
with zipfile.ZipFile(ROOT / "zipbomb_small.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("blob.bin", b"A" * (200 * 1024))
PY
```
