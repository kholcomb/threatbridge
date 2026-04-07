"""Tests for the SARIF gate — the CI/CD critical-detection path used in security-triage.yml.

Covers the flow: SARIF scanner output → cve-intel batch --format sarif → enriched SARIF
with correct severity levels, and the --fail-on gate that controls CI exit codes.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from cve_intel.cli import cli
from cve_intel.models.cve import CVSSSeverity

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_analysis_result(cve_id="CVE-2024-21762", score=9.8, severity="CRITICAL", vuln_meta=None):
    """Minimal AnalysisResult-like mock for pipeline.analyze."""
    cvss = MagicMock()
    cvss.base_score = score
    cvss.base_severity = CVSSSeverity(severity)
    cvss.vector_string = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    cve = MagicMock()
    cve.description_en = "Test vulnerability."
    cve.primary_cvss = cvss

    mapping = MagicMock()
    mapping.techniques = []

    result = MagicMock()
    result.cve_id = cve_id
    result.cve_record = cve
    result.attack_mapping = mapping
    result.metadata = {"vulnrichment": vuln_meta or {}}
    return result


@pytest.fixture
def scan_sarif(tmp_path):
    """osv-scanner-shaped SARIF fixture with a single CVE finding.

    Copied from scan_results.sarif.fixture (*.sarif is gitignored as generated output)
    into a tmp_path file so the batch CLI receives a path with the right extension.
    """
    src = FIXTURES_DIR / "scan_results.sarif.fixture"
    dst = tmp_path / "scan_results.sarif"
    dst.write_text(src.read_text())
    return dst


@pytest.fixture
def mock_attack(mocker, mock_attack_data):
    mocker.patch("cve_intel.fetchers.attack_data.get_attack_data", return_value=mock_attack_data)


def _run_batch(tmp_path, scan_sarif, extra_args=None):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    runner = CliRunner()
    args = ["batch", str(scan_sarif), "--format", "sarif", "--output", str(out_dir), "--no-enrich"]
    result = runner.invoke(cli, args + (extra_args or []))
    return result, out_dir


# ---------------------------------------------------------------------------
# Level assignment
# ---------------------------------------------------------------------------

def test_critical_cvss_written_as_error(mocker, tmp_path, scan_sarif, mock_attack):
    """CVSS ≥ 9.0 must produce level=error in the enriched SARIF output."""
    mocker.patch("cve_intel.pipeline.analyze", return_value=_make_analysis_result(score=9.8))
    result, out_dir = _run_batch(tmp_path, scan_sarif)

    assert result.exit_code == 0, result.output
    sarif = json.loads((out_dir / "results.sarif.json").read_text())
    levels = [r["level"] for r in sarif["runs"][0]["results"]]
    assert "error" in levels


def test_medium_cvss_not_written_as_error(mocker, tmp_path, scan_sarif, mock_attack):
    """CVSS < 9.0 without KEV/SSVC escalation must not produce level=error."""
    mocker.patch("cve_intel.pipeline.analyze", return_value=_make_analysis_result(score=6.5, severity="MEDIUM"))
    result, out_dir = _run_batch(tmp_path, scan_sarif)

    assert result.exit_code == 0, result.output
    sarif = json.loads((out_dir / "results.sarif.json").read_text())
    levels = [r["level"] for r in sarif["runs"][0]["results"]]
    assert "error" not in levels


def test_kev_listed_escalates_to_error_regardless_of_cvss(mocker, tmp_path, scan_sarif, mock_attack):
    """A KEV-listed CVE must be level=error even with a low CVSS score."""
    mocker.patch(
        "cve_intel.pipeline.analyze",
        return_value=_make_analysis_result(
            score=5.0, severity="MEDIUM", vuln_meta={"in_kev": True, "kev_date_added": "2024-02-09"}
        ),
    )
    result, out_dir = _run_batch(tmp_path, scan_sarif)

    assert result.exit_code == 0, result.output
    sarif = json.loads((out_dir / "results.sarif.json").read_text())
    levels = [r["level"] for r in sarif["runs"][0]["results"]]
    assert "error" in levels


def test_ssvc_active_escalates_to_error(mocker, tmp_path, scan_sarif, mock_attack):
    """SSVC exploitation=active must escalate to level=error regardless of CVSS."""
    mocker.patch(
        "cve_intel.pipeline.analyze",
        return_value=_make_analysis_result(
            score=5.0, severity="MEDIUM", vuln_meta={"ssvc_exploitation": "active"}
        ),
    )
    result, out_dir = _run_batch(tmp_path, scan_sarif)

    assert result.exit_code == 0, result.output
    sarif = json.loads((out_dir / "results.sarif.json").read_text())
    levels = [r["level"] for r in sarif["runs"][0]["results"]]
    assert "error" in levels


# ---------------------------------------------------------------------------
# --fail-on gate (mirrors the Enforce gate step in security-triage.yml)
# ---------------------------------------------------------------------------

def test_fail_on_never_exits_zero_even_with_critical(mocker, tmp_path, scan_sarif, mock_attack):
    """Default --fail-on never: exit 0 even when criticals are present (warn-only mode)."""
    mocker.patch("cve_intel.pipeline.analyze", return_value=_make_analysis_result(score=9.8))
    result, _ = _run_batch(tmp_path, scan_sarif)
    assert result.exit_code == 0


def test_fail_on_error_exits_nonzero_with_critical(mocker, tmp_path, scan_sarif, mock_attack):
    """--fail-on error: non-zero exit when a CVSS ≥ 9.0 finding is present."""
    mocker.patch("cve_intel.pipeline.analyze", return_value=_make_analysis_result(score=9.8))
    result, _ = _run_batch(tmp_path, scan_sarif, extra_args=["--fail-on", "error"])
    assert result.exit_code != 0


def test_fail_on_error_exits_zero_when_no_criticals(mocker, tmp_path, scan_sarif, mock_attack):
    """--fail-on error: exit 0 when no findings reach error level."""
    mocker.patch("cve_intel.pipeline.analyze", return_value=_make_analysis_result(score=6.5, severity="MEDIUM"))
    result, _ = _run_batch(tmp_path, scan_sarif, extra_args=["--fail-on", "error"])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Output file presence
# ---------------------------------------------------------------------------

def test_output_sarif_file_written(mocker, tmp_path, scan_sarif, mock_attack):
    """results.sarif.json must be written to the output directory."""
    mocker.patch("cve_intel.pipeline.analyze", return_value=_make_analysis_result())
    result, out_dir = _run_batch(tmp_path, scan_sarif)

    assert result.exit_code == 0, result.output
    assert (out_dir / "results.sarif.json").exists()


def test_output_sarif_is_valid_sarif(mocker, tmp_path, scan_sarif, mock_attack):
    """Output SARIF must have the expected schema structure."""
    mocker.patch("cve_intel.pipeline.analyze", return_value=_make_analysis_result())
    result, out_dir = _run_batch(tmp_path, scan_sarif)

    sarif = json.loads((out_dir / "results.sarif.json").read_text())
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    assert len(sarif["runs"]) > 0
