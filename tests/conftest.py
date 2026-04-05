"""Shared pytest fixtures."""

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def nvd_cve_21762_raw() -> dict:
    data = json.loads((FIXTURES_DIR / "nvd_response_CVE-2024-21762.json").read_text())
    return data["vulnerabilities"][0]["cve"]


@pytest.fixture
def sample_cve_record(nvd_cve_21762_raw):
    from cve_intel.fetchers.nvd import NVDFetcher
    fetcher = NVDFetcher.__new__(NVDFetcher)
    return fetcher._parse(nvd_cve_21762_raw)


@pytest.fixture
def mock_attack_data(mocker):
    """Minimal mock AttackData with a few techniques."""
    from cve_intel.fetchers.attack_data import AttackData
    from cve_intel.models.attack import AttackTechnique, AttackTactic

    tactic = AttackTactic(tactic_id="TA0001", name="Initial Access", shortname="initial-access")
    tech_t1190 = AttackTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactics=[tactic],
        platforms=["Windows", "Linux"],
        confidence=0.5,
    )
    tech_t1068 = AttackTechnique(
        technique_id="T1068",
        name="Exploitation for Privilege Escalation",
        tactics=[tactic],
        platforms=["Windows", "Linux"],
        confidence=0.5,
    )
    tech_t1203 = AttackTechnique(
        technique_id="T1203",
        name="Exploitation for Client Execution",
        tactics=[tactic],
        platforms=["Windows"],
        confidence=0.5,
    )

    data = mocker.MagicMock(spec=AttackData)
    tech_map = {
        "T1190": tech_t1190,
        "T1068": tech_t1068,
        "T1203": tech_t1203,
    }
    data.get_technique.side_effect = lambda tid: tech_map.get(tid)
    data.get_techniques_by_ids.side_effect = lambda ids: [
        tech_map[i] for i in ids if i in tech_map
    ]
    return data
