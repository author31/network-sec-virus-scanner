from __future__ import annotations

import hashlib
import math

import pytest

from sentinel.infrastructure import BloomFilter


def _md5_keys(n: int, *, salt: str = "in") -> list[str]:
    return [hashlib.md5(f"{salt}-{i}".encode()).hexdigest() for i in range(n)]


def test_constructor_rejects_bad_args() -> None:
    with pytest.raises(ValueError):
        BloomFilter(capacity=-1)
    with pytest.raises(ValueError):
        BloomFilter(capacity=10, fp_rate=0.0)
    with pytest.raises(ValueError):
        BloomFilter(capacity=10, fp_rate=1.0)
    with pytest.raises(ValueError):
        BloomFilter(capacity=10, fp_rate=-0.1)


def test_bit_size_and_hash_count_match_formula() -> None:
    n, p = 1000, 0.01
    bf = BloomFilter(capacity=n, fp_rate=p)
    expected_m = math.ceil(-n * math.log(p) / (math.log(2) ** 2))
    assert bf.bit_size == expected_m
    assert bf.hash_count >= 1


def test_zero_false_negatives_on_inserted_keys() -> None:
    keys = _md5_keys(2_000)
    bf = BloomFilter.from_iterable(keys, fp_rate=0.01)
    assert len(bf) == 2_000
    for k in keys:
        assert k in bf, f"false negative for inserted key {k!r}"


def test_zero_false_negatives_eicar_digests() -> None:
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    bf = BloomFilter.from_iterable([md5, sha])
    assert md5 in bf
    assert sha in bf


def test_membership_for_non_str_is_false() -> None:
    bf = BloomFilter.from_iterable(["abc"])
    assert (123 in bf) is False
    assert (b"abc" in bf) is False
    assert (None in bf) is False


def test_empty_bloom_returns_false() -> None:
    bf = BloomFilter(capacity=0)
    assert "anything" not in bf
    assert len(bf) == 0


def test_false_positive_rate_within_expected_bound() -> None:
    capacity = 5_000
    fp_target = 0.01
    bf = BloomFilter(capacity=capacity, fp_rate=fp_target)
    for k in _md5_keys(capacity, salt="in"):
        bf.add(k)

    trials = 20_000
    miss_keys = _md5_keys(trials, salt="out")
    false_positives = sum(1 for k in miss_keys if k in bf)
    rate = false_positives / trials
    assert rate <= fp_target * 3, (
        f"observed FP rate {rate:.4f} exceeds 3x target {fp_target:.4f}"
    )


def test_add_does_not_corrupt_other_keys() -> None:
    bf = BloomFilter(capacity=100)
    bf.add("alpha")
    bf.add("beta")
    bf.add("gamma")
    assert "alpha" in bf
    assert "beta" in bf
    assert "gamma" in bf
    assert len(bf) == 3
