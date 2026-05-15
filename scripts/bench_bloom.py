"""Benchmark Bloom pre-check vs plain hash-map lookup.

Builds a synthetic signature DB of ``--n`` random md5+sha256 entries,
then runs ``scan_file`` on a clean file many times with the Bloom
filter off and on, reporting wall-clock totals.

Default: 100,000 signatures, 50,000 scan iterations.

Run: ``uv run scripts/bench_bloom.py``
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

from sentinel.application import scan_file
from sentinel.repository import SignatureRepository


def build_db(path: Path, n: int) -> None:
    entries = []
    for i in range(n):
        seed = f"sig-{i}".encode()
        md5 = hashlib.md5(seed).hexdigest()
        sha = hashlib.sha256(seed).hexdigest()
        entries.append(
            {
                "name": f"sig-{i}",
                "threat_level": "low",
                "md5": md5,
                "sha256": sha,
            }
        )
    path.write_text(json.dumps(entries), encoding="utf-8")


def time_scan(repo: SignatureRepository, target: Path, iters: int) -> float:
    start = time.perf_counter()
    for _ in range(iters):
        scan_file(target, repo)
    return time.perf_counter() - start


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=100_000, help="signature count")
    parser.add_argument("--iters", type=int, default=50_000, help="scan iterations")
    parser.add_argument(
        "--fp-rate", type=float, default=0.01, help="bloom target FP rate"
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        db = tmp_path / "signatures.json"
        target = tmp_path / "clean.bin"
        target.write_bytes(os.urandom(4096))

        print(f"Building synthetic DB ({args.n:,} signatures)...")
        build_db(db, args.n)

        print("Loading repo (bloom OFF)...")
        load_off_start = time.perf_counter()
        repo_off = SignatureRepository.load(db)
        load_off = time.perf_counter() - load_off_start

        print("Loading repo (bloom ON)...")
        load_on_start = time.perf_counter()
        repo_on = SignatureRepository.load(
            db, enable_bloom=True, bloom_fp_rate=args.fp_rate
        )
        load_on = time.perf_counter() - load_on_start

        bloom = repo_on.bloom
        assert bloom is not None
        bloom_kib = bloom.bit_size / 8 / 1024

        print(f"Scanning clean file x{args.iters:,} (bloom OFF)...")
        t_off = time_scan(repo_off, target, args.iters)

        print(f"Scanning clean file x{args.iters:,} (bloom ON)...")
        t_on = time_scan(repo_on, target, args.iters)

        miss = [
            hashlib.sha256(f"miss-{i}".encode()).hexdigest()
            for i in range(args.iters)
        ]
        l0 = time.perf_counter()
        for k in miss:
            repo_off.lookup_sha256(k)
        l_off = time.perf_counter() - l0

        l0 = time.perf_counter()
        for k in miss:
            if repo_on.might_contain_hash(k):
                repo_on.lookup_sha256(k)
        l_on = time.perf_counter() - l0

        print()
        print(f"Load OFF: {load_off:.3f}s | Load ON: {load_on:.3f}s")
        print(f"Bloom: m={bloom.bit_size:,} bits ({bloom_kib:.1f} KiB), k={bloom.hash_count}")
        print(f"Scan OFF: {t_off:.3f}s ({t_off / args.iters * 1e6:.2f} us/scan)")
        print(f"Scan ON:  {t_on:.3f}s ({t_on / args.iters * 1e6:.2f} us/scan)")
        if t_on > 0:
            print(f"Scan speedup: {t_off / t_on:.2f}x")
        print()
        print("Lookup-only (no file hashing):")
        print(f"  dict-only:  {l_off:.3f}s ({l_off / args.iters * 1e9:.0f} ns/op)")
        print(f"  bloom+dict: {l_on:.3f}s ({l_on / args.iters * 1e9:.0f} ns/op)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
