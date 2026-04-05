"""Tests for SigmaHQ community rule fetcher and comparator."""

import pytest
from unittest.mock import patch, MagicMock
import json

from cve_intel.fetchers.sigmahq import (
    fetch_community_rules,
    compare_with_community,
    SigmaHQResult,
    CommunityRule,
    _API_BASE,
)


def _mock_urlopen(responses: dict):
    """Context manager that returns different responses by URL."""
    def side_effect(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        for pattern, body in responses.items():
            if pattern in url:
                mock = MagicMock()
                mock.__enter__ = lambda s: s
                mock.__exit__ = MagicMock(return_value=False)
                if isinstance(body, Exception):
                    raise body
                mock.read.return_value = body if isinstance(body, bytes) else body.encode()
                return mock
        raise Exception(f"No mock for URL: {url}")
    return patch("urllib.request.urlopen", side_effect=side_effect)


SAMPLE_RULE = """\
title: Potential CVE-2024-3400 Exploitation
id: bcd95697-e3e7-4c6f-8584-8e3503e6929f
status: test
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename|contains: '/opt/panlogs/'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059
  - cve.2024-3400
"""

DIR_LISTING = json.dumps([
    {
        "name": "exploit_cve_2024_3400.yml",
        "download_url": "https://raw.githubusercontent.com/SigmaHQ/sigma/main/rules-emerging-threats/2024/Exploits/CVE-2024-3400/exploit_cve_2024_3400.yml",
    }
]).encode()


def test_fetch_returns_rules_when_found():
    with _mock_urlopen({
        "contents/rules-emerging-threats": DIR_LISTING,
        "exploit_cve_2024_3400.yml": SAMPLE_RULE,
    }):
        result = fetch_community_rules("CVE-2024-3400")

    assert result.found is True
    assert len(result.rules) == 1
    assert result.rules[0].filename == "exploit_cve_2024_3400.yml"
    assert "CVE-2024-3400" in result.rules[0].rule_text or "3400" in result.rules[0].rule_text


def test_fetch_returns_not_found_on_404():
    with patch("urllib.request.urlopen", side_effect=Exception("HTTP Error 404")):
        result = fetch_community_rules("CVE-2099-99999")

    assert result.found is False
    assert result.rules == []


def test_summary_extracts_logsources_and_tags():
    result = SigmaHQResult(
        cve_id="CVE-2024-3400",
        found=True,
        rules=[CommunityRule(
            filename="test.yml",
            rule_text=SAMPLE_RULE,
            download_url="",
        )],
    )
    summary = result.summary()
    assert summary["found"] is True
    assert summary["rule_count"] == 1
    assert any("file_event" in ls or "linux" in ls for ls in summary["logsources"])
    assert "attack.execution" in summary["attack_tags"]
    assert "cve.2024-3400" in summary["cve_tags"]


def test_compare_detects_logsource_mismatch():
    community = SigmaHQResult(
        cve_id="CVE-2024-3400",
        found=True,
        rules=[CommunityRule(filename="test.yml", rule_text=SAMPLE_RULE, download_url="")],
    )
    generated = (
        "title: Test\nlogsource:\n  category: process_creation\n"
        "detection:\n  selection:\n    Image: test\n  condition: selection\n"
        "tags:\n  - attack.execution\n"
    )
    comparison = compare_with_community(generated, community)

    assert comparison["community_available"] is True
    assert len(comparison["comparisons"]) == 1
    c = comparison["comparisons"][0]
    assert c["logsource_match"] is False
    assert "attack.execution" in c["shared_attack_tags"]


def test_compare_returns_unavailable_when_no_community_rule():
    community = SigmaHQResult(cve_id="CVE-2099-99999", found=False)
    result = compare_with_community("title: Test\n", community)
    assert result["community_available"] is False


def test_compare_detects_missing_tags():
    community = SigmaHQResult(
        cve_id="CVE-2024-3400",
        found=True,
        rules=[CommunityRule(filename="test.yml", rule_text=SAMPLE_RULE, download_url="")],
    )
    # Generated rule is missing attack.t1059
    generated = (
        "title: Test\nlogsource:\n  category: file_event\n  product: linux\n"
        "detection:\n  selection:\n    TargetFilename: test\n  condition: selection\n"
        "tags:\n  - attack.execution\nlevel: high\n"
    )
    comparison = compare_with_community(generated, community)
    c = comparison["comparisons"][0]
    assert "attack.t1059" in c["missing_attack_tags"]
    assert c["level_match"] is True


def test_fetch_logs_warning_on_non_404_http_error(caplog):
    """A non-404 HTTP error on the directory listing (e.g. 503) should log a warning and return found=False."""
    import logging
    import urllib.error

    http_503 = urllib.error.HTTPError(
        url="https://api.github.com", code=503, msg="Service Unavailable", hdrs={}, fp=None
    )
    with patch("urllib.request.urlopen", side_effect=http_503):
        with caplog.at_level(logging.WARNING, logger="cve_intel.fetchers.sigmahq"):
            result = fetch_community_rules("CVE-2024-3400")

    assert result.found is False
    assert any("SigmaHQ directory listing failed" in record.message
               for record in caplog.records)


def test_fetch_retries_directory_listing_on_503():
    """First directory listing returns 503, second returns valid JSON; result must have found=True."""
    import urllib.error

    http_503 = urllib.error.HTTPError(
        url="https://api.github.com", code=503, msg="Service Unavailable", hdrs={}, fp=None
    )
    call_count = 0

    def side_effect(req, timeout=None):
        nonlocal call_count
        call_count += 1
        url = req.full_url if hasattr(req, "full_url") else str(req)
        mock = MagicMock()
        mock.__enter__ = lambda s: s
        mock.__exit__ = MagicMock(return_value=False)
        if "contents/rules-emerging-threats" in url:
            if call_count == 1:
                raise http_503
            mock.read.return_value = DIR_LISTING
            return mock
        # rule file fetch
        mock.read.return_value = SAMPLE_RULE.encode()
        return mock

    with patch("urllib.request.urlopen", side_effect=side_effect):
        with patch("time.sleep"):
            result = fetch_community_rules("CVE-2024-3400")

    assert result.found is True
    assert len(result.rules) == 1
    assert call_count >= 2  # at least one retry of the directory listing
