"""Tests for NVD fetcher."""

import json
from pathlib import Path

import pytest
import responses as resp_mock

from cve_intel.fetchers.nvd import NVDFetcher, NVDNotFoundError, NVDRateLimitError

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
