"""Tests for batch command retry and error classification."""

import pytest
from click.testing import CliRunner

from cve_intel.cli import cli
from cve_intel.fetchers.nvd import NVDNotFoundError, NVDRateLimitError


@pytest.fixture
def cve_list(tmp_path):
    f = tmp_path / "cves.txt"
    f.write_text("CVE-2024-21762\n")
    return f


@pytest.fixture
def mock_attack(mocker, mock_attack_data):
    mocker.patch("cve_intel.fetchers.attack_data.get_attack_data", return_value=mock_attack_data)


def test_batch_retries_on_rate_limit_then_succeeds(mocker, tmp_path, cve_list, mock_attack, sample_cve_record):
    """pipeline.analyze raises NVDRateLimitError once, then succeeds — batch should succeed."""
    from cve_intel.models.ioc import IOCBundle
    from cve_intel.models.rules import AnalysisResult, RuleBundle
    from cve_intel.models.attack import AttackMapping

    success_result = AnalysisResult(
        cve_id="CVE-2024-21762",
        cve_record=sample_cve_record,
        attack_mapping=AttackMapping(cve_id="CVE-2024-21762", techniques=[]),
        ioc_bundle=IOCBundle(cve_id="CVE-2024-21762"),
        rule_bundle=RuleBundle(cve_id="CVE-2024-21762"),
        enriched=False,
        warnings=[],
        metadata={},
    )

    mocker.patch("cve_intel.cli.time.sleep")
    mocker.patch(
        "cve_intel.pipeline.analyze",
        side_effect=[NVDRateLimitError("rate limited"), success_result],
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["batch", str(cve_list), "--no-enrich", "--format", "json"])

    assert result.exit_code == 0
    assert "CVE-2024-21762" in result.output


def test_batch_does_not_retry_on_not_found(mocker, tmp_path, cve_list, mock_attack):
    """NVDNotFoundError is permanent — should not retry and should appear as skipped."""
    mocker.patch("cve_intel.cli.time.sleep")
    mocker.patch("cve_intel.pipeline.analyze", side_effect=NVDNotFoundError("not found"))

    runner = CliRunner()
    result = runner.invoke(cli, ["batch", str(cve_list), "--no-enrich", "--format", "json"])

    # Should exit cleanly (errors don't raise SystemExit in batch)
    assert result.exit_code == 0
    # analyze should only have been called once — no retries
    import cve_intel.pipeline as p
    assert p.analyze.call_count == 1
    assert "not found in NVD" in result.output


def test_batch_exhausts_retries_on_persistent_rate_limit(mocker, tmp_path, cve_list, mock_attack):
    """If NVDRateLimitError persists across all attempts, CVE ends up in errors."""
    sleep_calls: list[float] = []
    mocker.patch("cve_intel.cli.time.sleep", side_effect=lambda s: sleep_calls.append(s))
    mocker.patch("cve_intel.pipeline.analyze", side_effect=NVDRateLimitError("rate limited"))

    runner = CliRunner()
    result = runner.invoke(cli, ["batch", str(cve_list), "--no-enrich", "--format", "json"])

    assert result.exit_code == 0
    # Should have slept between attempts 1→2 and 2→3 (not after the final failure)
    assert sleep_calls == [5.0, 10.0]
    assert "NVD rate limit" in result.output


def test_batch_not_found_vs_rate_limit_output(mocker, tmp_path, tmp_path_factory, mock_attack, sample_cve_record):
    """Not-found errors print yellow/skipped; rate-limit errors print red with advice."""
    cve_file = tmp_path / "cves.txt"
    cve_file.write_text("CVE-2024-00001\nCVE-2024-00002\n")

    from cve_intel.models.ioc import IOCBundle
    from cve_intel.models.rules import AnalysisResult, RuleBundle
    from cve_intel.models.attack import AttackMapping

    def side_effect(cve_id, **kwargs):
        if cve_id == "CVE-2024-00001":
            raise NVDNotFoundError("not found")
        raise NVDRateLimitError("rate limited")

    mocker.patch("cve_intel.cli.time.sleep")
    mocker.patch("cve_intel.pipeline.analyze", side_effect=side_effect)

    runner = CliRunner()
    result = runner.invoke(cli, ["batch", str(cve_file), "--no-enrich", "--format", "json"])

    assert "not found in NVD" in result.output
    assert "NVD rate limit" in result.output
