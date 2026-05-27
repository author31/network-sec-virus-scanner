from __future__ import annotations

import os
from pathlib import Path

import pytest

from sentinel.application.entropy_scan_engine import (
    DEFAULT_ENTROPY_THRESHOLD,
    DETECTION_METHOD_ENTROPY,
    EntropyScanResult,
    compute_entropy,
    scan_file_entropy,
)
from sentinel.repository import ThreatLevel


class TestComputeEntropy:
    def test_empty_bytes(self) -> None:
        assert compute_entropy(b"") == 0.0

    def test_single_byte_value(self) -> None:
        assert compute_entropy(b"\x00" * 100) == 0.0

    def test_two_equal_byte_values(self) -> None:
        data = b"\x00" * 50 + b"\xff" * 50
        entropy = compute_entropy(data)
        assert 0.12 < entropy < 0.13  # 1 bit / 8 = 0.125

    def test_uniform_distribution_max_entropy(self) -> None:
        data = bytes(range(256)) * 100
        entropy = compute_entropy(data)
        assert entropy > 0.99

    def test_returns_float_in_range(self) -> None:
        data = os.urandom(4096)
        entropy = compute_entropy(data)
        assert 0.0 <= entropy <= 1.0


class TestScanFileEntropy:
    def test_high_entropy_flagged(self, tmp_path: Path) -> None:
        f = tmp_path / "random.bin"
        f.write_bytes(os.urandom(8192))
        result = scan_file_entropy(f, threshold=0.75)
        assert result is not None
        assert isinstance(result, EntropyScanResult)
        assert result.entropy >= 0.75
        assert result.detection_method == DETECTION_METHOD_ENTROPY
        assert result.threat_level == ThreatLevel.MEDIUM

    def test_low_entropy_not_flagged(self, tmp_path: Path) -> None:
        f = tmp_path / "zeros.bin"
        f.write_bytes(b"\x00" * 4096)
        result = scan_file_entropy(f, threshold=0.75)
        assert result is None

    def test_empty_file_returns_none(self, tmp_path: Path) -> None:
        f = tmp_path / "empty"
        f.write_bytes(b"")
        result = scan_file_entropy(f, threshold=0.0)
        assert result is None

    def test_custom_threshold(self, tmp_path: Path) -> None:
        f = tmp_path / "text.txt"
        f.write_text("hello world " * 500)
        result_low = scan_file_entropy(f, threshold=0.01)
        result_high = scan_file_entropy(f, threshold=0.99)
        assert result_low is not None
        assert result_high is None

    def test_invalid_threshold_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "x"
        f.write_bytes(b"\x00")
        with pytest.raises(ValueError, match="threshold"):
            scan_file_entropy(f, threshold=1.5)
        with pytest.raises(ValueError, match="threshold"):
            scan_file_entropy(f, threshold=-0.1)

    def test_default_threshold_value(self) -> None:
        assert DEFAULT_ENTROPY_THRESHOLD == 0.75

    def test_result_path_is_absolute(self, tmp_path: Path) -> None:
        f = tmp_path / "rand.bin"
        f.write_bytes(os.urandom(4096))
        result = scan_file_entropy(f, threshold=0.5)
        assert result is not None
        assert result.path.is_absolute()
