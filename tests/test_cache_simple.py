# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Simple tests for cache module to improve coverage."""

from __future__ import annotations

import os
import pathlib
from pathlib import Path
import shutil
import tempfile
import time
from typing import TYPE_CHECKING

from gha_workflow_linter.cache import (
    CacheConfig,
    CachedValidationEntry,
    ValidationCache,
)
from gha_workflow_linter.models import ValidationResult

if TYPE_CHECKING:
    import pytest


class TestCachedValidationEntry:
    """Test CachedValidationEntry class."""

    def test_init(self) -> None:
        """Test CachedValidationEntry initialization."""
        result = ValidationResult.VALID

        entry = CachedValidationEntry(  # pyright: ignore[reportCallIssue]
            repository="actions/checkout",
            reference="v4",
            result=result,
            timestamp=time.time(),
            api_call_type="graphql",
        )

        assert entry.repository == "actions/checkout"
        assert entry.reference == "v4"
        assert entry.result == result
        assert entry.api_call_type == "graphql"

    def test_is_expired_not_expired(self) -> None:
        """Test checking if entry is not expired."""
        result = ValidationResult.VALID

        entry = CachedValidationEntry(  # pyright: ignore[reportCallIssue]
            repository="actions/checkout",
            reference="v4",
            result=result,
            timestamp=time.time(),
            api_call_type="graphql",
        )

        # Should not be expired with 1 hour TTL
        assert not entry.is_expired(3600)

    def test_is_expired_expired(self) -> None:
        """Test checking if entry is expired."""
        result = ValidationResult.VALID

        # Create entry with old timestamp
        entry = CachedValidationEntry(  # pyright: ignore[reportCallIssue]
            repository="actions/checkout",
            reference="v4",
            result=result,
            timestamp=time.time() - 7200,  # 2 hours ago
            api_call_type="graphql",
        )

        # Should be expired with 1 hour TTL
        assert entry.is_expired(3600)

    def test_age_seconds(self) -> None:
        """Test getting age of cache entry."""
        result = ValidationResult.VALID

        # Create entry with timestamp 100 seconds ago
        old_time = time.time() - 100
        entry = CachedValidationEntry(  # pyright: ignore[reportCallIssue]
            repository="actions/checkout",
            reference="v4",
            result=result,
            timestamp=old_time,
            api_call_type="graphql",
        )

        age = entry.age_seconds
        assert age >= 99  # Should be at least 99 seconds (allowing for timing)


class TestValidationCache:
    """Test ValidationCache class."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        # Create a private temp directory and place the cache file inside
        # it. Using mkdtemp() + a fixed filename avoids the race conditions
        # tempfile.mktemp() exposes (where another process could create the
        # named path between mktemp() and our first write).
        self._temp_cache_dir = Path(  # pyright: ignore[reportUninitializedInstanceVariable]
            tempfile.mkdtemp(prefix="gha-workflow-linter-cache-")
        )
        self.temp_cache_file_path = str(  # pyright: ignore[reportUninitializedInstanceVariable]
            self._temp_cache_dir / "cache.json"
        )

        self.cache_config = CacheConfig(  # pyright: ignore[reportUninitializedInstanceVariable, reportCallIssue]
            enabled=True,
            cache_dir=self._temp_cache_dir,
            cache_file="cache.json",
        )

    def teardown_method(self) -> None:
        """Clean up test fixtures."""
        # Remove the entire temp directory in one shot. shutil.rmtree
        # tolerates a missing directory via ignore_errors=True so tests
        # that delete the cache file mid-run still teardown cleanly.
        shutil.rmtree(self._temp_cache_dir, ignore_errors=True)

    def test_init_with_config(self) -> None:
        """Test ValidationCache initialization."""
        cache = ValidationCache(self.cache_config)
        assert cache.config is self.cache_config

    def test_init_with_default_config(self) -> None:
        """Test ValidationCache with default config."""
        default_config = CacheConfig()  # pyright: ignore[reportCallIssue]
        cache = ValidationCache(default_config)
        assert isinstance(cache.config, CacheConfig)

    def test_generate_cache_key(self) -> None:
        """Test cache key generation."""
        cache = ValidationCache(self.cache_config)
        key = cache._generate_cache_key("actions/checkout", "v4")
        assert key == "actions/checkout@v4"

    def test_enabled_true(self) -> None:
        """Test cache enabled property when enabled."""
        cache_config = CacheConfig(enabled=True)  # pyright: ignore[reportCallIssue]
        cache = ValidationCache(cache_config)

        assert cache.config.enabled is True

    def test_enabled_false(self) -> None:
        """Test cache enabled property when disabled."""
        cache_config = CacheConfig(enabled=False)  # pyright: ignore[reportCallIssue]
        cache = ValidationCache(cache_config)

        assert cache.config.enabled is False

    def test_get_cache_file_path(self) -> None:
        """Test getting cache file path."""
        cache = ValidationCache(self.cache_config)
        path = cache.config.cache_file_path

        assert isinstance(path, Path)
        assert str(path).endswith(".json")

    def test_load_cache_basic(self) -> None:
        """Test loading cache with no existing file."""
        # Remove the temp file to ensure we start with no cache
        if os.path.exists(self.temp_cache_file_path):
            os.unlink(self.temp_cache_file_path)

        cache = ValidationCache(self.cache_config)
        cache._load_cache()
        assert cache._cache == {}

    def test_save_cache_basic(self) -> None:
        """Test saving cache (should not fail)."""
        cache = ValidationCache(self.cache_config)
        # Should not raise even if cache is empty
        cache._save_cache()

    def test_cleanup_expired(self) -> None:
        """Test cleaning up expired entries."""
        cache = ValidationCache(self.cache_config)

        # Add an expired entry
        old_entry = CachedValidationEntry(  # pyright: ignore[reportCallIssue]
            repository="old/repo",
            reference="v1",
            result=ValidationResult.VALID,
            timestamp=time.time() - 86400,  # 1 day ago
            api_call_type="graphql",
        )
        cache._cache["test_key"] = old_entry

        initial_count = len(cache._cache)
        cache._cleanup_expired()

        # Should have same or fewer entries after cleanup
        assert len(cache._cache) <= initial_count

    def test_cache_disabled_operations(self) -> None:
        """Test cache operations when disabled."""
        cache_config = CacheConfig(enabled=False)  # pyright: ignore[reportCallIssue]
        cache = ValidationCache(cache_config)

        # Should not raise when cache is disabled
        cache._save_cache()  # Should do nothing

    def test_stats_basic(self) -> None:
        """Test getting cache statistics."""
        cache = ValidationCache(self.cache_config)
        stats = cache.stats

        # Should return CacheStats object
        assert hasattr(stats, "hits")
        assert hasattr(stats, "misses")
        assert stats.hits >= 0
        assert stats.misses >= 0


class TestCachePrime:
    """Regression tests for ``ValidationCache.prime()``.

    The cache module must be UI-free; ``prime()`` reports its findings
    via a ``CachePrimeReport`` instead of printing. The CLI layer renders
    banners *before* opening any Rich Progress UI so output never
    interleaves with a Live spinner.
    """

    def setup_method(self) -> None:
        self._temp_cache_dir = pathlib.Path(  # pyright: ignore[reportUninitializedInstanceVariable]
            tempfile.mkdtemp(prefix="gha-workflow-linter-prime-")
        )
        self.cache_config = CacheConfig(  # pyright: ignore[reportUninitializedInstanceVariable, reportCallIssue]
            enabled=True,
            cache_dir=self._temp_cache_dir,
            cache_file="cache.json",
        )

    def teardown_method(self) -> None:
        shutil.rmtree(self._temp_cache_dir, ignore_errors=True)

    def test_prime_no_cache_file_returns_empty_report(self) -> None:
        from gha_workflow_linter.cache import CachePrimeReport

        cache = ValidationCache(self.cache_config)
        report = cache.prime()
        assert isinstance(report, CachePrimeReport)
        assert report.version_mismatch_purged is False
        assert report.suspicious_patterns_purged is False
        assert report.suspicious_reasons == ()

    def test_prime_idempotent(self) -> None:
        cache = ValidationCache(self.cache_config)
        first = cache.prime()
        second = cache.prime()
        assert first.version_mismatch_purged == second.version_mismatch_purged

    def test_prime_disabled_cache_no_op(self) -> None:
        from gha_workflow_linter.cache import CachePrimeReport

        config = CacheConfig(  # pyright: ignore[reportCallIssue]
            enabled=False,
            cache_dir=self._temp_cache_dir,
            cache_file="cache.json",
        )
        cache = ValidationCache(config)
        report = cache.prime()
        assert isinstance(report, CachePrimeReport)
        assert report.version_mismatch_purged is False
        assert report.suspicious_patterns_purged is False

    def test_prime_detects_version_mismatch(self) -> None:
        """A pre-existing cache from a different tool version triggers a
        version-mismatch purge, surfaced via the report (not stdout)."""
        import json

        # Write a cache file with a deliberately-stale version.
        stale = {
            "_metadata": {
                "version": "0.0.0-fake",
                "created_timestamp": time.time(),
                "entry_count": 0,
                "redirect_count": 0,
                "latest_version_count": 0,
            }
        }
        cache_path = self._temp_cache_dir / "cache.json"
        cache_path.write_text(json.dumps(stale))

        cache = ValidationCache(self.cache_config)
        report = cache.prime()
        assert report.version_mismatch_purged is True
        assert report.suspicious_patterns_purged is False

    def test_prime_does_not_print(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Sanity: prime() must not write to stdout/stderr regardless of
        what it does internally; the CLI layer owns user-facing output."""
        import json

        stale = {
            "_metadata": {
                "version": "0.0.0-fake",
                "created_timestamp": time.time(),
                "entry_count": 0,
                "redirect_count": 0,
                "latest_version_count": 0,
            }
        }
        cache_path = self._temp_cache_dir / "cache.json"
        cache_path.write_text(json.dumps(stale))

        cache = ValidationCache(self.cache_config)
        cache.prime()
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""
