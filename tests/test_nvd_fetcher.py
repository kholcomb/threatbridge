"""Tests for NVD fetcher."""

import json
import time
from pathlib import Path

import pytest
import responses as resp_mock

from cve_intel.fetchers.nvd import NVDFetcher, NVDNotFoundError, NVDRateLimitError


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset the class-level rate limiter state between tests."""
    NVDFetcher._last_request_time = 0.0
    yield
    NVDFetcher._last_request_time = 0.0

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text())


def test_validate_cve_id_valid():
    fetcher = NVDFetcher.__new__(NVDFetcher)
    assert fetcher.validate_cve_id("cve-2024-21762") == "CVE-2024-21762"


def test_validate_cve_id_invalid():
    fetcher = NVDFetcher.__new__(NVDFetcher)
    with pytest.raises(ValueError):
        fetcher.validate_cve_id("not-a-cve")


def test_parse_cve_record(nvd_cve_21762_raw):
    fetcher = NVDFetcher.__new__(NVDFetcher)
    record = fetcher._parse(nvd_cve_21762_raw)

    assert record.cve_id == "CVE-2024-21762"
    assert "CWE-787" in record.weaknesses
    assert len(record.cvss) == 1
    assert record.cvss[0].base_score == 9.8
    assert record.cvss[0].base_severity.value == "CRITICAL"
    assert "fortinet" in record.description_en.lower()
    assert len(record.cpe_matches) == 2


@resp_mock.activate
def test_fetch_success(tmp_path, monkeypatch):
    monkeypatch.setattr("cve_intel.config.settings.cache_dir", tmp_path)

    fixture = _load_fixture("nvd_response_CVE-2024-21762.json")
    resp_mock.add(
        resp_mock.GET,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        json=fixture,
        status=200,
    )

    import diskcache
    fetcher = NVDFetcher.__new__(NVDFetcher)
    fetcher._cache = diskcache.Cache(str(tmp_path / "nvd"))

    import requests
    fetcher._session = requests.Session()

    record = fetcher.fetch("CVE-2024-21762")
    assert record.cve_id == "CVE-2024-21762"


@resp_mock.activate
def test_fetch_404_raises_not_found(tmp_path, monkeypatch):
    monkeypatch.setattr("cve_intel.config.settings.cache_dir", tmp_path)

    resp_mock.add(
        resp_mock.GET,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        json={"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []},
        status=200,
    )

    import diskcache, requests
    fetcher = NVDFetcher.__new__(NVDFetcher)
    fetcher._cache = diskcache.Cache(str(tmp_path / "nvd"))
    fetcher._session = requests.Session()

    with pytest.raises(NVDNotFoundError):
        fetcher.fetch("CVE-9999-99999")


@resp_mock.activate
def test_fetch_403_raises_rate_limit(tmp_path, monkeypatch):
    monkeypatch.setattr("cve_intel.config.settings.cache_dir", tmp_path)

    resp_mock.add(
        resp_mock.GET,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        status=403,
    )

    import diskcache, requests
    fetcher = NVDFetcher.__new__(NVDFetcher)
    fetcher._cache = diskcache.Cache(str(tmp_path / "nvd"))
    fetcher._session = requests.Session()

    with pytest.raises(NVDRateLimitError):
        fetcher.fetch("CVE-2024-21762")


@resp_mock.activate
def test_nvd_fetcher_returns_cached_result_on_second_call(tmp_path):
    """Second fetch for same CVE ID hits cache — HTTP is called only once."""
    fixture = _load_fixture("nvd_response_CVE-2024-21762.json")
    resp_mock.add(
        resp_mock.GET,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        json=fixture,
        status=200,
    )

    import diskcache
    import requests as req_lib

    fetcher = NVDFetcher.__new__(NVDFetcher)
    fetcher._cache = diskcache.Cache(str(tmp_path / "nvd"))
    fetcher._session = req_lib.Session()

    record1 = fetcher.fetch("CVE-2024-21762")
    record2 = fetcher.fetch("CVE-2024-21762")

    assert record1.cve_id == record2.cve_id == "CVE-2024-21762"
    # responses library tracks every call; only one HTTP request should have been made
    assert len(resp_mock.calls) == 1


@resp_mock.activate
def test_nvd_fetcher_refetches_after_cache_expiry(tmp_path):
    """After the cache entry is deleted (simulating expiry), the fetcher re-fetches via HTTP."""
    fixture = _load_fixture("nvd_response_CVE-2024-21762.json")
    resp_mock.add(
        resp_mock.GET,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        json=fixture,
        status=200,
    )
    resp_mock.add(
        resp_mock.GET,
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        json=fixture,
        status=200,
    )

    import diskcache
    import requests as req_lib

    fetcher = NVDFetcher.__new__(NVDFetcher)
    fetcher._cache = diskcache.Cache(str(tmp_path / "nvd"))
    fetcher._session = req_lib.Session()

    # First fetch — populates the cache
    record1 = fetcher.fetch("CVE-2024-21762")
    assert len(resp_mock.calls) == 1

    # Simulate expiry by deleting the cache entry directly
    fetcher._cache.delete("nvd:CVE-2024-21762")

    # Second fetch — cache miss, must go back to HTTP
    record2 = fetcher.fetch("CVE-2024-21762")
    assert len(resp_mock.calls) == 2
    assert record1.cve_id == record2.cve_id == "CVE-2024-21762"


def test_malformed_cvss_severity_logs_warning(caplog):
    """_build_cvss should log a warning when baseSeverity is unrecognized."""
    fetcher = NVDFetcher.__new__(NVDFetcher)

    raw_metrics = {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "baseScore": 9.8,
                    "baseSeverity": "ULTRA",
                }
            }
        ]
    }

    import logging
    with caplog.at_level(logging.WARNING, logger="cve_intel.fetchers.nvd"):
        cvss_list = fetcher._parse_cvss(raw_metrics)

    assert len(cvss_list) == 1
    assert cvss_list[0].base_severity.value == "MEDIUM"
    assert any(
        "ULTRA" in record.message and record.levelname == "WARNING"
        for record in caplog.records
    )


# ---------------------------------------------------------------------------
# Rate limiter tests
# ---------------------------------------------------------------------------

def test_min_interval_without_key(mocker):
    mocker.patch("cve_intel.fetchers.nvd.settings", mocker.MagicMock(has_nvd_key=False))
    assert NVDFetcher._min_interval() == 6.0


def test_min_interval_with_key(mocker):
    mocker.patch("cve_intel.fetchers.nvd.settings", mocker.MagicMock(has_nvd_key=True))
    assert NVDFetcher._min_interval() == 0.6


def test_throttle_sleeps_when_called_too_soon(mocker, monkeypatch):
    """_throttle should sleep for the remaining interval when called back-to-back."""
    mocker.patch.object(NVDFetcher, "_min_interval", return_value=6.0)

    slept: list[float] = []
    monkeypatch.setattr("cve_intel.fetchers.nvd.time.sleep", lambda s: slept.append(s))

    now = time.monotonic()
    NVDFetcher._last_request_time = now - 1.0  # request happened 1s ago, interval is 6s
    monkeypatch.setattr("cve_intel.fetchers.nvd.time.monotonic", lambda: now)

    NVDFetcher._throttle()

    assert len(slept) == 1
    assert abs(slept[0] - 5.0) < 0.1  # ~5s remaining


def test_throttle_no_sleep_when_interval_elapsed(mocker, monkeypatch):
    """_throttle should not sleep when the full interval has already elapsed."""
    mocker.patch.object(NVDFetcher, "_min_interval", return_value=6.0)

    slept: list[float] = []
    monkeypatch.setattr("cve_intel.fetchers.nvd.time.sleep", lambda s: slept.append(s))

    now = time.monotonic()
    NVDFetcher._last_request_time = now - 10.0  # 10s ago, interval is 6s
    monkeypatch.setattr("cve_intel.fetchers.nvd.time.monotonic", lambda: now)

    NVDFetcher._throttle()

    assert slept == []


def test_throttle_shared_across_instances(mocker, monkeypatch):
    """Two separate NVDFetcher instances share the same rate limiter state."""
    mocker.patch.object(NVDFetcher, "_min_interval", return_value=6.0)

    slept: list[float] = []
    monkeypatch.setattr("cve_intel.fetchers.nvd.time.sleep", lambda s: slept.append(s))

    now = time.monotonic()
    NVDFetcher._last_request_time = now - 1.0  # simulates instance A just making a request
    monkeypatch.setattr("cve_intel.fetchers.nvd.time.monotonic", lambda: now)

    NVDFetcher._throttle()  # instance B call — should see instance A's last_request_time

    assert len(slept) == 1
