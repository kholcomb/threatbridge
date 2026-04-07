"""Tests for SARIF renderer and SarifPolicy."""

import pytest

from cve_intel.output.sarif_renderer import SarifPolicy, _assign_level, render_sarif


# ---------------------------------------------------------------------------
# _assign_level — CVSS baseline
# ---------------------------------------------------------------------------

def test_cvss_error_threshold():
    assert _assign_level(9.0, "CRITICAL", {}, SarifPolicy()) == "error"


def test_cvss_warning_threshold():
    assert _assign_level(7.0, "HIGH", {}, SarifPolicy()) == "warning"


def test_cvss_note_threshold():
    assert _assign_level(4.0, "MEDIUM", {}, SarifPolicy()) == "note"


def test_cvss_none_threshold():
    assert _assign_level(2.0, "LOW", {}, SarifPolicy()) == "none"


def test_cvss_boundary_just_below_error():
    assert _assign_level(8.9, "HIGH", {}, SarifPolicy()) == "warning"


def test_no_score_falls_back_to_severity_string():
    assert _assign_level(None, "critical", {}, SarifPolicy()) == "error"
    assert _assign_level(None, "high", {}, SarifPolicy()) == "warning"
    assert _assign_level(None, "low", {}, SarifPolicy()) == "none"


def test_no_score_no_severity_defaults_to_note():
    assert _assign_level(None, None, {}, SarifPolicy()) == "note"


# ---------------------------------------------------------------------------
# _assign_level — KEV escalation
# ---------------------------------------------------------------------------

def test_kev_escalates_to_error_regardless_of_cvss():
    """A low-CVSS CVE in the KEV catalog should always be error."""
    assert _assign_level(5.0, "MEDIUM", {"in_kev": True}, SarifPolicy()) == "error"


def test_kev_with_no_score_still_error():
    assert _assign_level(None, None, {"in_kev": True}, SarifPolicy()) == "error"


def test_kev_escalation_disabled():
    policy = SarifPolicy(kev_is_error=False)
    assert _assign_level(5.0, "MEDIUM", {"in_kev": True}, policy) == "note"


# ---------------------------------------------------------------------------
# _assign_level — SSVC escalation
# ---------------------------------------------------------------------------

def test_ssvc_active_escalates_to_error():
    assert _assign_level(5.0, "MEDIUM", {"ssvc_exploitation": "active"}, SarifPolicy()) == "error"


def test_ssvc_active_escalation_disabled():
    policy = SarifPolicy(ssvc_active_is_error=False)
    assert _assign_level(5.0, "MEDIUM", {"ssvc_exploitation": "active"}, policy) == "note"


def test_ssvc_poc_bumps_note_to_warning():
    assert _assign_level(4.0, "MEDIUM", {"ssvc_exploitation": "poc"}, SarifPolicy()) == "warning"


def test_ssvc_poc_bumps_none_to_warning():
    assert _assign_level(2.0, "LOW", {"ssvc_exploitation": "poc"}, SarifPolicy()) == "warning"


def test_ssvc_poc_does_not_downgrade_error():
    """A CVSS 9.5 should remain error even with ssvc_poc_is_warning enabled."""
    assert _assign_level(9.5, "CRITICAL", {"ssvc_exploitation": "poc"}, SarifPolicy()) == "error"


def test_ssvc_poc_bump_disabled():
    policy = SarifPolicy(ssvc_poc_is_warning=False)
    assert _assign_level(2.0, "LOW", {"ssvc_exploitation": "poc"}, policy) == "none"


# ---------------------------------------------------------------------------
# _assign_level — custom CVSS thresholds
# ---------------------------------------------------------------------------

def test_custom_cvss_error_threshold():
    policy = SarifPolicy(cvss_error=8.0)
    assert _assign_level(8.0, "HIGH", {}, policy) == "error"
    assert _assign_level(7.9, "HIGH", {}, policy) == "warning"


def test_custom_cvss_warning_threshold():
    policy = SarifPolicy(cvss_warning=5.0)
    assert _assign_level(5.0, "MEDIUM", {}, policy) == "warning"
    assert _assign_level(4.9, "MEDIUM", {}, policy) == "note"


def test_kev_overrides_custom_low_threshold():
    """KEV escalation should fire even when CVSS thresholds are loosened."""
    policy = SarifPolicy(cvss_error=10.0)  # effectively nothing hits error via CVSS
    assert _assign_level(5.0, "MEDIUM", {"in_kev": True}, policy) == "error"


# ---------------------------------------------------------------------------
# render_sarif — integration
# ---------------------------------------------------------------------------

def _make_result(cve_id="CVE-2024-0001", score=9.8, severity="CRITICAL", vuln_meta=None):
    """Build a minimal AnalysisResult-like object for render_sarif."""
    from unittest.mock import MagicMock
    from cve_intel.models.cve import CVSSData, CVSSSeverity

    cvss = MagicMock()
    cvss.base_score = score
    cvss.base_severity = CVSSSeverity(severity.upper()) if severity else None
    cvss.vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    cve = MagicMock()
    cve.description_en = "Test vulnerability description."
    cve.primary_cvss = cvss

    mapping = MagicMock()
    mapping.techniques = []

    result = MagicMock()
    result.cve_id = cve_id
    result.cve_record = cve
    result.attack_mapping = mapping
    result.metadata = {"vulnrichment": vuln_meta or {}}

    return result


def test_render_sarif_default_policy():
    result = _make_result(score=9.8, severity="CRITICAL")
    sarif = render_sarif([result])
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_render_sarif_custom_policy():
    policy = SarifPolicy(cvss_error=10.0)  # nothing hits error via CVSS alone
    result = _make_result(score=9.8, severity="CRITICAL")
    sarif = render_sarif([result], policy=policy)
    assert sarif["runs"][0]["results"][0]["level"] == "warning"


def test_render_sarif_kev_in_properties():
    result = _make_result(score=5.0, severity="MEDIUM", vuln_meta={"in_kev": True})
    sarif = render_sarif([result])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"].get("kev") is True


def test_render_sarif_ssvc_in_properties():
    result = _make_result(score=5.0, severity="MEDIUM", vuln_meta={"ssvc_exploitation": "active"})
    sarif = render_sarif([result])
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"].get("ssvc_exploitation") == "active"


def test_render_sarif_message_includes_kev_tag():
    result = _make_result(score=5.0, severity="MEDIUM", vuln_meta={"in_kev": True})
    sarif = render_sarif([result])
    message = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "[KEV]" in message


def test_render_sarif_empty_results():
    sarif = render_sarif([])
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
