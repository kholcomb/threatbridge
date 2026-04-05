"""Tests for MCP server tools (all external calls mocked)."""

import json
import pytest
from unittest.mock import MagicMock, patch


def _make_ctx(attack_data):
    """Build a minimal MCP Context mock with lifespan attack_data."""
    ctx = MagicMock()
    ctx.request_context.lifespan_context = {"attack_data": attack_data}
    return ctx


# ---------------------------------------------------------------------------
# fetch_cve
# ---------------------------------------------------------------------------

def test_fetch_cve_returns_cve_dict(mocker, sample_cve_record):
    mocker.patch("cve_intel.mcp_server.NVDFetcher.fetch", return_value=sample_cve_record)
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import fetch_cve
    result = fetch_cve("CVE-2024-21762", ctx)

    assert result["cve_id"] == "CVE-2024-21762"


# ---------------------------------------------------------------------------
# get_attack_techniques
# ---------------------------------------------------------------------------

def test_get_attack_techniques_returns_mapping(mocker, sample_cve_record, mock_attack_data):
    mocker.patch("cve_intel.mcp_server.NVDFetcher.fetch", return_value=sample_cve_record)
    mock_attack_data.all_technique_ids = ["T1190", "T1068", "T1203"]
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import get_attack_techniques
    result = get_attack_techniques("CVE-2024-21762", ctx)

    assert "techniques" in result
    assert "cve_id" in result
    assert result["cve_id"] == "CVE-2024-21762"


# ---------------------------------------------------------------------------
# lookup_technique
# ---------------------------------------------------------------------------

def test_lookup_technique_returns_technique(mock_attack_data):
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import lookup_technique
    result = lookup_technique("T1190", ctx)

    assert result["technique_id"] == "T1190"


def test_lookup_technique_raises_for_unknown(mock_attack_data):
    mock_attack_data.get_technique.return_value = None
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import lookup_technique
    with pytest.raises(ValueError, match="not found"):
        lookup_technique("T9999", ctx)


# ---------------------------------------------------------------------------
# search_techniques
# ---------------------------------------------------------------------------

def test_search_techniques_returns_matches(mock_attack_data):
    mock_attack_data.all_technique_ids = ["T1190", "T1068", "T1203"]
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import search_techniques
    results = search_techniques("exploit", ctx)

    assert isinstance(results, list)
    # All three mock techniques have "Exploit" in their names
    assert len(results) >= 1
    assert all("technique_id" in r for r in results)


def test_search_techniques_returns_empty_for_no_match(mock_attack_data):
    mock_attack_data.all_technique_ids = ["T1190"]
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import search_techniques
    results = search_techniques("zzznomatch", ctx)

    assert results == []


# ---------------------------------------------------------------------------
# get_cve_summary
# ---------------------------------------------------------------------------

def test_get_cve_summary_returns_combined(mocker, sample_cve_record, mock_attack_data):
    mocker.patch("cve_intel.mcp_server.NVDFetcher.fetch", return_value=sample_cve_record)
    mock_attack_data.all_technique_ids = ["T1190", "T1068", "T1203"]
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import get_cve_summary
    result = get_cve_summary("CVE-2024-21762", ctx)

    assert "cve" in result
    assert "attack_mapping" in result
    assert result["attack_mapping"]["cve_id"] == "CVE-2024-21762"


# ---------------------------------------------------------------------------
# get_exploitation_context
# ---------------------------------------------------------------------------

def test_get_exploitation_context_kev_active(mocker):
    from cve_intel.fetchers.vulnrichment import VulnrichmentData, SSVCScore
    mock_data = VulnrichmentData(
        cve_id="CVE-2024-21762",
        available=True,
        in_kev=True,
        kev_date_added="2024-02-09",
        ssvc=SSVCScore(exploitation="active", automatable="yes", technical_impact="total"),
    )
    mocker.patch("cve_intel.mcp_server.fetch_vulnrichment", return_value=mock_data)
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import get_exploitation_context
    result = get_exploitation_context("CVE-2024-21762", ctx)

    assert result["in_kev"] is True
    assert result["ssvc_exploitation"] == "active"
    assert result["is_actively_exploited"] is True
    assert result["suggested_severity"] == "critical"


def test_get_exploitation_context_unavailable(mocker):
    from cve_intel.fetchers.vulnrichment import VulnrichmentData, SSVCScore
    mocker.patch(
        "cve_intel.mcp_server.fetch_vulnrichment",
        return_value=VulnrichmentData(cve_id="CVE-2099-99999"),
    )
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import get_exploitation_context
    result = get_exploitation_context("CVE-2099-99999", ctx)

    assert result["available"] is False
    assert result["suggested_severity"] is None


# ---------------------------------------------------------------------------
# get_community_sigma_rules
# ---------------------------------------------------------------------------

def test_get_community_sigma_rules_found(mocker):
    from cve_intel.fetchers.sigmahq import SigmaHQResult, CommunityRule
    mock_result = SigmaHQResult(
        cve_id="CVE-2024-3400",
        found=True,
        rules=[CommunityRule(
            filename="exploit.yml",
            rule_text="title: Test\nlogsource:\n  category: file_event\n  product: linux\ntags:\n  - attack.execution\n  - cve.2024-3400\n",
            download_url="https://example.com/exploit.yml",
        )],
    )
    mocker.patch("cve_intel.mcp_server.fetch_community_rules", return_value=mock_result)
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import get_community_sigma_rules
    result = get_community_sigma_rules("CVE-2024-3400", ctx)

    assert result["found"] is True
    assert result["rule_count"] == 1
    assert "exploit.yml" in result["filenames"]
    assert "attack.execution" in result["attack_tags"]


def test_get_community_sigma_rules_not_found(mocker):
    from cve_intel.fetchers.sigmahq import SigmaHQResult
    mocker.patch(
        "cve_intel.mcp_server.fetch_community_rules",
        return_value=SigmaHQResult(cve_id="CVE-2099-99999", found=False),
    )
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import get_community_sigma_rules
    result = get_community_sigma_rules("CVE-2099-99999", ctx)

    assert result["found"] is False
    assert result["rule_count"] == 0


# ---------------------------------------------------------------------------
# compare_sigma_rule_with_community
# ---------------------------------------------------------------------------

def test_compare_sigma_rule_detects_mismatch(mocker):
    from cve_intel.fetchers.sigmahq import SigmaHQResult, CommunityRule
    community_rule_text = (
        "title: Community Rule\nlogsource:\n  category: file_event\n  product: linux\n"
        "detection:\n  selection:\n    TargetFilename: /tmp/exploit\n  condition: selection\n"
        "tags:\n  - attack.execution\n  - attack.t1059\nlevel: high\n"
    )
    mock_result = SigmaHQResult(
        cve_id="CVE-2024-3400",
        found=True,
        rules=[CommunityRule(filename="rule.yml", rule_text=community_rule_text, download_url="")],
    )
    mocker.patch("cve_intel.mcp_server.fetch_community_rules", return_value=mock_result)
    ctx = _make_ctx(None)

    generated = (
        "title: Generated Rule\nlogsource:\n  category: process_creation\n"
        "detection:\n  selection:\n    Image: test\n  condition: selection\n"
        "tags:\n  - attack.execution\nlevel: medium\n"
    )

    from cve_intel.mcp_server import compare_sigma_rule_with_community
    result = compare_sigma_rule_with_community("CVE-2024-3400", generated, ctx)

    assert result["community_available"] is True
    c = result["comparisons"][0]
    assert c["logsource_match"] is False
    assert "attack.t1059" in c["missing_attack_tags"]
    assert c["level_match"] is False


def test_compare_sigma_rule_no_community(mocker):
    from cve_intel.fetchers.sigmahq import SigmaHQResult
    mocker.patch(
        "cve_intel.mcp_server.fetch_community_rules",
        return_value=SigmaHQResult(cve_id="CVE-2099-99999", found=False),
    )
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import compare_sigma_rule_with_community
    result = compare_sigma_rule_with_community("CVE-2099-99999", "title: Test\n", ctx)

    assert result["community_available"] is False
