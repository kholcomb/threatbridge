"""Tests for VEX re-ingestion pipeline.

Covers:
- parse_vex / load_vex (scanner_input)
- Suppression filtering in the batch CLI (case-sensitivity included)
- Prior not_affected re-emission in render_vex (vex_renderer)
- Error handling: malformed JSON, missing file
"""

import json
import pytest
from click.testing import CliRunner
from pathlib import Path
from unittest.mock import MagicMock

from cve_intel.fetchers.scanner_input import parse_vex, load_vex, VexDecision
from cve_intel.cli import cli


# ---------------------------------------------------------------------------
# parse_vex / load_vex unit tests
# ---------------------------------------------------------------------------

VALID_VEX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "vulnerabilities": [
        {
            "id": "CVE-2024-1111",
            "analysis": {"state": "not_affected", "justification": "code_not_reachable"},
        },
        {
            "id": "CVE-2024-2222",
            "analysis": {"state": "affected"},
        },
        {
            "id": "CVE-2024-3333",
            # no analysis block — should default to under_investigation
        },
    ],
}


def test_parse_vex_returns_all_decisions():
    decisions = parse_vex(VALID_VEX)
    assert len(decisions) == 3


def test_parse_vex_uppercases_cve_ids():
    data = {
        "vulnerabilities": [
            {"id": "cve-2024-9999", "analysis": {"state": "not_affected"}},
        ]
    }
    decisions = parse_vex(data)
    assert decisions[0].cve_id == "CVE-2024-9999"


def test_parse_vex_state_values():
    decisions = parse_vex(VALID_VEX)
    states = {d.cve_id: d.state for d in decisions}
    assert states["CVE-2024-1111"] == "not_affected"
    assert states["CVE-2024-2222"] == "affected"
    assert states["CVE-2024-3333"] == "under_investigation"


def test_parse_vex_preserves_raw():
    decisions = parse_vex(VALID_VEX)
    assert decisions[0].raw == VALID_VEX["vulnerabilities"][0]


def test_parse_vex_skips_non_cve_ids():
    data = {
        "vulnerabilities": [
            {"id": "GHSA-1234-5678-9012", "analysis": {"state": "not_affected"}},
            {"id": "CVE-2024-0001", "analysis": {"state": "affected"}},
        ]
    }
    decisions = parse_vex(data)
    assert len(decisions) == 1
    assert decisions[0].cve_id == "CVE-2024-0001"


def test_parse_vex_empty_document():
    decisions = parse_vex({})
    assert decisions == []


def test_load_vex_reads_file(tmp_path):
    vex_file = tmp_path / "prior.vex.json"
    vex_file.write_text(json.dumps(VALID_VEX), encoding="utf-8")
    decisions = load_vex(vex_file)
    assert len(decisions) == 3


def test_load_vex_raises_on_bad_json(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        load_vex(bad_file)


# ---------------------------------------------------------------------------
# Batch CLI suppression tests
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_attack(mocker, mock_attack_data):
    mocker.patch("cve_intel.fetchers.attack_data.get_attack_data", return_value=mock_attack_data)


@pytest.fixture
def success_result(sample_cve_record):
    from cve_intel.models.ioc import IOCBundle
    from cve_intel.models.rules import AnalysisResult, RuleBundle
    from cve_intel.models.attack import AttackMapping

    return AnalysisResult(
        cve_id="CVE-2024-2222",
        cve_record=sample_cve_record,
        attack_mapping=AttackMapping(cve_id="CVE-2024-2222", techniques=[]),
        ioc_bundle=IOCBundle(cve_id="CVE-2024-2222"),
        rule_bundle=RuleBundle(cve_id="CVE-2024-2222"),
        enriched=False,
        warnings=[],
        metadata={},
    )


def _make_vex_file(tmp_path: Path, suppressed_ids: list[str]) -> Path:
    vex = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "vulnerabilities": [
            {"id": cve_id, "analysis": {"state": "not_affected"}}
            for cve_id in suppressed_ids
        ],
    }
    p = tmp_path / "prior.vex.json"
    p.write_text(json.dumps(vex), encoding="utf-8")
    return p


def test_batch_suppresses_not_affected_cves(mocker, tmp_path, mock_attack, success_result):
    """CVEs marked not_affected in a prior VEX file are excluded from processing."""
    cve_list = tmp_path / "cves.txt"
    cve_list.write_text("CVE-2024-1111\nCVE-2024-2222\n")
    vex_file = _make_vex_file(tmp_path, ["CVE-2024-1111"])

    analyze_mock = mocker.patch("cve_intel.pipeline.analyze", return_value=success_result)

    runner = CliRunner()
    result = runner.invoke(cli, [
        "batch", str(cve_list),
        "--no-enrich", "--format", "json",
        "--vex-in", str(vex_file),
    ])

    assert result.exit_code == 0
    # Only CVE-2024-2222 should have been analyzed — CVE-2024-1111 was suppressed
    analyzed_ids = [call.kwargs["cve_id"] for call in analyze_mock.call_args_list]
    assert "CVE-2024-2222" in analyzed_ids
    assert "CVE-2024-1111" not in analyzed_ids


def test_batch_suppression_is_case_insensitive(mocker, tmp_path, mock_attack, success_result):
    """Suppression works even when scanner input CVE IDs are lowercase/mixed case."""
    cve_list = tmp_path / "cves.txt"
    # Mixed case from scanner
    cve_list.write_text("cve-2024-1111\nCVE-2024-2222\n")
    vex_file = _make_vex_file(tmp_path, ["CVE-2024-1111"])  # uppercase in VEX

    analyze_mock = mocker.patch("cve_intel.pipeline.analyze", return_value=success_result)

    runner = CliRunner()
    result = runner.invoke(cli, [
        "batch", str(cve_list),
        "--no-enrich", "--format", "json",
        "--vex-in", str(vex_file),
    ])

    assert result.exit_code == 0
    analyzed_ids = [call.kwargs["cve_id"] for call in analyze_mock.call_args_list]
    assert "CVE-2024-1111" not in analyzed_ids


def test_batch_vex_load_failure_exits_cleanly(mocker, tmp_path, mock_attack):
    """A malformed VEX file causes a clean exit with an error message, not a traceback."""
    cve_list = tmp_path / "cves.txt"
    cve_list.write_text("CVE-2024-2222\n")
    bad_vex = tmp_path / "bad.vex.json"
    bad_vex.write_text("not valid json", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, [
        "batch", str(cve_list),
        "--no-enrich", "--format", "json",
        "--vex-in", str(bad_vex),
    ])

    assert result.exit_code != 0
    assert "Cannot load VEX file" in result.output


# ---------------------------------------------------------------------------
# render_vex — prior not_affected re-emission
# ---------------------------------------------------------------------------

def test_render_vex_reemits_prior_not_affected(sample_cve_record):
    """Prior not_affected decisions for CVEs not in the new scan are re-emitted verbatim."""
    from cve_intel.output.vex_renderer import render_vex
    from cve_intel.fetchers.scanner_input import VexDecision
    from cve_intel.models.ioc import IOCBundle
    from cve_intel.models.rules import AnalysisResult, RuleBundle
    from cve_intel.models.attack import AttackMapping

    prior_raw = {"id": "CVE-2024-OLD", "analysis": {"state": "not_affected", "justification": "code_not_reachable"}}
    prior_decision = VexDecision(
        cve_id="CVE-2024-OLD",
        state="not_affected",
        justification="code_not_reachable",
        raw=prior_raw,
    )

    # New scan only has CVE-2024-2222 — CVE-2024-OLD is absent
    result = AnalysisResult(
        cve_id="CVE-2024-2222",
        cve_record=sample_cve_record,
        attack_mapping=AttackMapping(cve_id="CVE-2024-2222", techniques=[]),
        ioc_bundle=IOCBundle(cve_id="CVE-2024-2222"),
        rule_bundle=RuleBundle(cve_id="CVE-2024-2222"),
        enriched=False,
        warnings=[],
        metadata={},
    )

    output = render_vex([result], prior_decisions=[prior_decision])
    vuln_ids = [v.get("id") for v in output["vulnerabilities"]]
    assert "CVE-2024-OLD" in vuln_ids


def test_render_vex_drops_prior_with_no_raw_and_warns(sample_cve_record, caplog):
    """Prior not_affected with raw=None is dropped with a warning log, not silently."""
    import logging
    from cve_intel.output.vex_renderer import render_vex
    from cve_intel.fetchers.scanner_input import VexDecision
    from cve_intel.models.ioc import IOCBundle
    from cve_intel.models.rules import AnalysisResult, RuleBundle
    from cve_intel.models.attack import AttackMapping

    prior_decision = VexDecision(
        cve_id="CVE-2024-OLD",
        state="not_affected",
        raw=None,
    )

    result = AnalysisResult(
        cve_id="CVE-2024-2222",
        cve_record=sample_cve_record,
        attack_mapping=AttackMapping(cve_id="CVE-2024-2222", techniques=[]),
        ioc_bundle=IOCBundle(cve_id="CVE-2024-2222"),
        rule_bundle=RuleBundle(cve_id="CVE-2024-2222"),
        enriched=False,
        warnings=[],
        metadata={},
    )

    with caplog.at_level(logging.WARNING, logger="cve_intel.output.vex_renderer"):
        output = render_vex([result], prior_decisions=[prior_decision])

    vuln_ids = [v.get("id") for v in output["vulnerabilities"]]
    assert "CVE-2024-OLD" not in vuln_ids
    assert "CVE-2024-OLD" in caplog.text
