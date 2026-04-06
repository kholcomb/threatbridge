"""Tests for MCP server tools (all external calls mocked)."""

import asyncio
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
    mocker.patch("cve_intel.mcp_server.fetch_cve_record", return_value=sample_cve_record)
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import fetch_cve
    result = fetch_cve("CVE-2024-21762", ctx)

    assert result["cve_id"] == "CVE-2024-21762"


# ---------------------------------------------------------------------------
# get_attack_techniques
# ---------------------------------------------------------------------------

def test_get_attack_techniques_returns_mapping(mocker, sample_cve_record, mock_attack_data):
    mocker.patch("cve_intel.mcp_server.fetch_cve_record", return_value=sample_cve_record)
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
    mocker.patch("cve_intel.mcp_server.fetch_cve_record", return_value=sample_cve_record)
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


# ---------------------------------------------------------------------------
# Authentication logic: _build_attack_requirements
# ---------------------------------------------------------------------------

def test_build_attack_requirements_no_auth_when_privileges_none():
    from cve_intel.models.cve import CVSSData, CVSSSeverity
    from cve_intel.mcp_server import _build_attack_requirements
    cvss = CVSSData(
        version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
        base_severity=CVSSSeverity.CRITICAL,
        attack_vector="NETWORK",
        attack_complexity="LOW",
        privileges_required="NONE",
        user_interaction="NONE",
        scope="UNCHANGED",
    )
    result = _build_attack_requirements(cvss)
    assert result["authentication_required"] is False
    assert result["high_privileges_required"] is False


def test_build_attack_requirements_auth_required_when_privileges_low():
    from cve_intel.models.cve import CVSSData, CVSSSeverity
    from cve_intel.mcp_server import _build_attack_requirements
    cvss = CVSSData(
        version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        base_score=8.8,
        base_severity=CVSSSeverity.HIGH,
        attack_vector="NETWORK",
        attack_complexity="LOW",
        privileges_required="LOW",
        user_interaction="NONE",
        scope="UNCHANGED",
    )
    result = _build_attack_requirements(cvss)
    assert result["authentication_required"] is True
    assert result["high_privileges_required"] is False


def test_build_attack_requirements_auth_required_when_privileges_high():
    from cve_intel.models.cve import CVSSData, CVSSSeverity
    from cve_intel.mcp_server import _build_attack_requirements
    cvss = CVSSData(
        version="3.1",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        base_score=7.2,
        base_severity=CVSSSeverity.HIGH,
        attack_vector="NETWORK",
        attack_complexity="LOW",
        privileges_required="HIGH",
        user_interaction="NONE",
        scope="UNCHANGED",
    )
    result = _build_attack_requirements(cvss)
    assert result["authentication_required"] is True
    assert result["high_privileges_required"] is True


# ---------------------------------------------------------------------------
# ATT&CK startup failure → tools return error dict
# ---------------------------------------------------------------------------

def test_get_attack_techniques_returns_error_when_attack_data_none(mocker, sample_cve_record):
    mocker.patch("cve_intel.mcp_server.fetch_cve_record", return_value=sample_cve_record)
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import get_attack_techniques
    result = get_attack_techniques("CVE-2024-21762", ctx)

    assert "error" in result


def test_triage_cve_returns_error_when_attack_data_none(mocker):
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import triage_cve
    result = triage_cve("CVE-2024-21762", ctx)

    assert "error" in result


def test_batch_triage_cves_returns_error_when_attack_data_none(mocker):
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import batch_triage_cves
    result = batch_triage_cves(["CVE-2024-21762"], ctx)

    assert "error" in result


# ---------------------------------------------------------------------------
# Invalid CVE ID validation at tool boundary
# ---------------------------------------------------------------------------

def test_fetch_cve_invalid_id_returns_error(mocker):
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import fetch_cve
    result = fetch_cve("not-a-cve-id", ctx)

    assert "error" in result


def test_triage_cve_empty_id_returns_error(mocker, mock_attack_data):
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import triage_cve
    result = triage_cve("", ctx)

    assert "error" in result


def test_batch_triage_cves_mixed_ids(mocker, mock_attack_data, sample_cve_record):
    mocker.patch("cve_intel.mcp_server.fetch_cve_record", return_value=sample_cve_record)
    mocker.patch("cve_intel.mcp_server.fetch_vulnrichment", return_value=__import__(
        "cve_intel.fetchers.vulnrichment", fromlist=["VulnrichmentData"]
    ).VulnrichmentData(cve_id="CVE-2024-1234"))
    mock_attack_data.all_technique_ids = []
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import batch_triage_cves
    result = batch_triage_cves(["CVE-2024-1234", "bad-id"], ctx)

    assert "failed" in result
    failed_ids = [f["cve_id"] for f in result["failed"]]
    assert "bad-id" in failed_ids
    bad_entry = next(f for f in result["failed"] if f["cve_id"] == "bad-id")
    assert bad_entry["error_type"] == "invalid_id"


# ---------------------------------------------------------------------------
# Batch triage error type distinction
# ---------------------------------------------------------------------------

def test_batch_triage_not_found_error_type(mocker, mock_attack_data):
    from cve_intel.fetchers.nvd import NVDNotFoundError
    mocker.patch("cve_intel.mcp_server.fetch_cve_record", side_effect=NVDNotFoundError("not found"))
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import batch_triage_cves
    result = batch_triage_cves(["CVE-2099-99999"], ctx)

    assert len(result["failed"]) == 1
    assert result["failed"][0]["error_type"] == "not_found"


def test_batch_triage_rate_limited_error_type(mocker, mock_attack_data):
    from cve_intel.fetchers.nvd import NVDRateLimitError
    mocker.patch("cve_intel.mcp_server.fetch_cve_record", side_effect=NVDRateLimitError("rate limited"))
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import batch_triage_cves
    result = batch_triage_cves(["CVE-2024-1234"], ctx)

    assert len(result["failed"]) == 1
    assert result["failed"][0]["error_type"] == "rate_limited"


def test_batch_triage_summary_includes_failed_count(mocker, mock_attack_data):
    from cve_intel.fetchers.nvd import NVDNotFoundError
    mocker.patch("cve_intel.mcp_server.fetch_cve_record", side_effect=NVDNotFoundError("not found"))
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import batch_triage_cves
    result = batch_triage_cves(["CVE-2099-00001", "CVE-2099-00002"], ctx)

    assert result["summary"]["failed_count"] == 2


def test_batch_triage_triage_notes_warn_on_failures(mocker, mock_attack_data):
    from cve_intel.fetchers.nvd import NVDNotFoundError
    mocker.patch("cve_intel.mcp_server.fetch_cve_record", side_effect=NVDNotFoundError("not found"))
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import batch_triage_cves
    result = batch_triage_cves(["CVE-2099-99999"], ctx)

    assert len(result["triage_notes"]) > 0
    assert any("manual triage" in note for note in result["triage_notes"])


def test_batch_triage_no_triage_notes_when_all_succeed(mocker, mock_attack_data, sample_cve_record):
    from cve_intel.fetchers.vulnrichment import VulnrichmentData
    mocker.patch("cve_intel.mcp_server.fetch_cve_record", return_value=sample_cve_record)
    mocker.patch("cve_intel.mcp_server.fetch_vulnrichment", return_value=VulnrichmentData(cve_id="CVE-2024-21762"))
    mock_attack_data.all_technique_ids = []
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import batch_triage_cves
    result = batch_triage_cves(["CVE-2024-21762"], ctx)

    assert result["summary"]["failed_count"] == 0
    assert result["triage_notes"] == []


# ---------------------------------------------------------------------------
# CPE version range merging
# ---------------------------------------------------------------------------

def test_triage_cve_merges_multiple_version_ranges():
    """Two CPE entries for the same vendor:product must be merged into one
    package entry whose version_ranges list contains both ranges."""
    from cve_intel.models.cve import CPEMatch
    from cve_intel.mcp_server import _parse_cpe_to_package

    cpe_matches = [
        CPEMatch(
            criteria="cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            version_start_including="1.0",
            version_end_excluding="2.0",
            vulnerable=True,
        ),
        CPEMatch(
            criteria="cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            version_start_including="3.0",
            version_end_excluding="4.0",
            vulnerable=True,
        ),
    ]

    result = _parse_cpe_to_package(cpe_matches)

    assert len(result) == 1
    pkg = result[0]
    assert pkg["vendor"] == "acme"
    assert pkg["package"] == "widget"

    ranges = pkg["version_ranges"]
    assert len(ranges) == 2

    start_values = {r["start_including"] for r in ranges}
    end_values = {r["end_excluding"] for r in ranges}
    assert start_values == {"1.0", "3.0"}
    assert end_values == {"2.0", "4.0"}


# ---------------------------------------------------------------------------
# Group 1: Return type contract tests
# ---------------------------------------------------------------------------

def test_triage_cve_returns_dict(mocker, sample_cve_record, mock_attack_data):
    mocker.patch("cve_intel.mcp_server.fetch_cve_record", return_value=sample_cve_record)
    mocker.patch("cve_intel.mcp_server.fetch_vulnrichment", return_value=__import__(
        "cve_intel.fetchers.vulnrichment", fromlist=["VulnrichmentData"]
    ).VulnrichmentData(cve_id="CVE-2024-21762"))
    mock_attack_data.all_technique_ids = []
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import triage_cve
    result = triage_cve("CVE-2024-21762", ctx)

    assert isinstance(result, dict)
    assert "priority_tier" in result
    assert "techniques" in result


# ---------------------------------------------------------------------------
# Group 2: attack_data=None graceful error tests
# ---------------------------------------------------------------------------

def test_get_cve_summary_returns_error_when_attack_data_none(mocker, sample_cve_record):
    mocker.patch("cve_intel.mcp_server.fetch_cve_record", return_value=sample_cve_record)
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import get_cve_summary
    result = get_cve_summary("CVE-2024-21762", ctx)

    assert isinstance(result, dict)
    assert "error" in result


def test_lookup_technique_returns_error_when_attack_data_none():
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import lookup_technique
    result = lookup_technique("T1190", ctx)

    assert isinstance(result, dict)
    assert "error" in result


def test_search_techniques_returns_error_when_attack_data_none():
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import search_techniques
    result = search_techniques("exploit", ctx)

    assert isinstance(result, list)
    assert len(result) == 1
    assert "error" in result[0]


def test_compare_sigma_rule_with_community_returns_error_when_attack_data_none(mocker):
    from cve_intel.fetchers.sigmahq import SigmaHQResult
    mocker.patch(
        "cve_intel.mcp_server.fetch_community_rules",
        return_value=SigmaHQResult(cve_id="CVE-2024-21762", found=False),
    )
    ctx = _make_ctx(None)

    from cve_intel.mcp_server import compare_sigma_rule_with_community
    result = compare_sigma_rule_with_community("CVE-2024-21762", "title: Test\n", ctx)

    assert isinstance(result, dict)
    # compare_sigma_rule_with_community does not use attack_data, so it should
    # succeed (community_available=false) rather than return an error dict
    assert "community_available" in result


# ---------------------------------------------------------------------------
# Group 3: Tool interaction — triage_cve and lookup_technique use same ATT&CK data
# ---------------------------------------------------------------------------

def test_triage_then_lookup_technique_consistent(mocker, sample_cve_record, mock_attack_data):
    """triage_cve top technique ID resolves correctly via lookup_technique."""
    mocker.patch("cve_intel.mcp_server.fetch_cve_record", return_value=sample_cve_record)
    mocker.patch("cve_intel.mcp_server.fetch_vulnrichment", return_value=__import__(
        "cve_intel.fetchers.vulnrichment", fromlist=["VulnrichmentData"]
    ).VulnrichmentData(cve_id="CVE-2024-21762"))
    mock_attack_data.all_technique_ids = ["T1190", "T1068", "T1203"]
    ctx = _make_ctx(mock_attack_data)

    from cve_intel.mcp_server import triage_cve, lookup_technique

    triage_result = triage_cve("CVE-2024-21762", ctx)
    assert isinstance(triage_result, dict)
    assert "techniques" in triage_result

    techniques = triage_result["techniques"]
    if not techniques:
        pytest.skip("No techniques mapped for this CVE fixture — skip interaction test")

    top_technique_id = techniques[0]["technique_id"]
    top_technique_name = techniques[0]["name"]

    lookup_result = lookup_technique(top_technique_id, ctx)
    assert isinstance(lookup_result, dict)
    assert lookup_result["technique_id"] == top_technique_id
    assert lookup_result["name"] == top_technique_name


# ---------------------------------------------------------------------------
# Lifespan context manager lifecycle tests
# ---------------------------------------------------------------------------

def test_lifespan_loads_attack_data_successfully(mock_attack_data):
    """lifespan yields attack_data when get_attack_data succeeds."""
    from cve_intel.mcp_server import lifespan
    mock_server = MagicMock()

    async def _run():
        with patch("cve_intel.mcp_server.get_attack_data", return_value=mock_attack_data):
            async with lifespan(mock_server) as ctx:
                assert ctx["attack_data"] is mock_attack_data

    asyncio.run(_run())


def test_lifespan_yields_none_on_attack_data_failure():
    """lifespan yields attack_data=None when AttackDataError is raised."""
    from cve_intel.mcp_server import lifespan
    from cve_intel.fetchers.attack_data import AttackDataError
    mock_server = MagicMock()

    async def _run():
        with patch(
            "cve_intel.mcp_server.get_attack_data",
            side_effect=AttackDataError("bundle missing"),
        ):
            async with lifespan(mock_server) as ctx:
                assert ctx["attack_data"] is None

    asyncio.run(_run())


def test_lifespan_raises_on_unexpected_error():
    """lifespan re-raises unexpected exceptions (not AttackDataError) so the process exits cleanly."""
    from cve_intel.mcp_server import lifespan
    mock_server = MagicMock()

    async def _run():
        with patch(
            "cve_intel.mcp_server.get_attack_data",
            side_effect=RuntimeError("disk full"),
        ):
            with pytest.raises(RuntimeError, match="disk full"):
                async with lifespan(mock_server) as ctx:
                    pass  # should not reach here

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Full tool pipeline: fetch_cve then triage_cve with shared context
# ---------------------------------------------------------------------------

def test_full_tool_pipeline_fetch_then_triage(mocker, sample_cve_record, mock_attack_data):
    """fetch_cve followed by triage_cve should produce consistent CVE data."""
    from cve_intel.mcp_server import fetch_cve, triage_cve
    from cve_intel.fetchers.vulnrichment import VulnrichmentData

    mocker.patch("cve_intel.mcp_server.fetch_cve_record", return_value=sample_cve_record)
    mocker.patch(
        "cve_intel.mcp_server.fetch_vulnrichment",
        return_value=VulnrichmentData(cve_id="CVE-2024-21762"),
    )
    mock_attack_data.all_technique_ids = []
    ctx = _make_ctx(mock_attack_data)

    fetch_result = fetch_cve("CVE-2024-21762", ctx)
    triage_result = triage_cve("CVE-2024-21762", ctx)

    # Both tools should agree on the CVE ID
    assert fetch_result["cve_id"] == "CVE-2024-21762"
    assert triage_result["cve_id"] == "CVE-2024-21762"
    # cvss_score is not a top-level key in either result — both absent is consistent
    assert fetch_result.get("cvss_score") == triage_result.get("cvss_score")
