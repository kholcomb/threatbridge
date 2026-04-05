"""Tests for CISA Vulnrichment fetcher."""

import json
import pytest
from unittest.mock import patch, MagicMock
from io import BytesIO

from cve_intel.fetchers.vulnrichment import (
    fetch_vulnrichment,
    VulnrichmentData,
    SSVCScore,
    _cve_url,
)


def _mock_response(data: dict):
    """Create a mock urllib response returning JSON data."""
    body = json.dumps(data).encode()
    mock = MagicMock()
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    mock.read.return_value = body
    return mock


SAMPLE_CISA_RESPONSE = {
    "containers": {
        "adp": [
            {
                "providerMetadata": {"orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0"},
                "metrics": [
                    {
                        "other": {
                            "type": "ssvc",
                            "content": {
                                "options": [
                                    {"Exploitation": "active"},
                                    {"Automatable": "yes"},
                                    {"Technical Impact": "total"},
                                ]
                            },
                        }
                    },
                    {
                        "other": {
                            "type": "kev",
                            "content": {"dateAdded": "2024-02-09"},
                        }
                    },
                ],
            }
        ]
    }
}


def test_fetch_parses_kev_and_ssvc():
    with patch("urllib.request.urlopen", return_value=_mock_response(SAMPLE_CISA_RESPONSE)):
        result = fetch_vulnrichment("CVE-2024-21762")

    assert result.available is True
    assert result.in_kev is True
    assert result.kev_date_added == "2024-02-09"
    assert result.ssvc.exploitation == "active"
    assert result.ssvc.automatable == "yes"
    assert result.ssvc.technical_impact == "total"
    assert result.is_actively_exploited is True


def test_fetch_suggests_critical_for_kev_active():
    with patch("urllib.request.urlopen", return_value=_mock_response(SAMPLE_CISA_RESPONSE)):
        result = fetch_vulnrichment("CVE-2024-21762")

    assert result.suggested_severity_boost() == "critical"


def test_fetch_returns_unavailable_on_404():
    with patch("urllib.request.urlopen", side_effect=Exception("HTTP Error 404")):
        result = fetch_vulnrichment("CVE-2099-99999")

    assert result.available is False
    assert result.in_kev is False
    assert result.ssvc.exploitation == "none"
    assert result.is_actively_exploited is False
    assert result.suggested_severity_boost() is None


def test_fetch_no_severity_boost_for_no_exploitation():
    no_exploit = {
        "containers": {
            "adp": [
                {
                    "providerMetadata": {"orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0"},
                    "metrics": [
                        {
                            "other": {
                                "type": "ssvc",
                                "content": {
                                    "options": [
                                        {"Exploitation": "none"},
                                        {"Automatable": "no"},
                                        {"Technical Impact": "partial"},
                                    ]
                                },
                            }
                        }
                    ],
                }
            ]
        }
    }
    with patch("urllib.request.urlopen", return_value=_mock_response(no_exploit)):
        result = fetch_vulnrichment("CVE-2024-00001")

    assert result.suggested_severity_boost() is None


def test_cve_url_bucket_calculation():
    assert "21xxx" in _cve_url("CVE-2024-21762")
    assert "0xxx" in _cve_url("CVE-2024-0001")
    assert "1xxx" in _cve_url("CVE-2024-1234")
