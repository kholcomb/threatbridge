"""Tests for Claude enrichment (mocked Claude client)."""

import pytest

from cve_intel.enrichment.attack_enricher import AttackEnricher
from cve_intel.enrichment.ioc_extractor import IOCExtractor
from cve_intel.models.attack import AttackMapping


def _make_mapping(cve_id, mock_attack_data):
    from cve_intel.models.attack import AttackTechnique, AttackTactic
    tactic = AttackTactic(tactic_id="TA0001", name="Initial Access", shortname="initial-access")
    tech = mock_attack_data.get_technique("T1203")
    tech = tech.model_copy(update={"confidence": 0.6, "rationale": "CWE mapping"})
    return AttackMapping(cve_id=cve_id, techniques=[tech], mapping_method="cwe_static")


def test_attack_enricher_confirms_and_adds(mocker, sample_cve_record, mock_attack_data):
    mock_client = mocker.MagicMock()
    mock_client.complete_structured.return_value = {
        "confirmed_techniques": [
            {"technique_id": "T1203", "confidence": 0.9, "rationale": "Out-of-bounds write enables RCE"}
        ],
        "added_techniques": [
            {"technique_id": "T1190", "confidence": 0.8, "rationale": "Network-accessible service"}
        ],
        "removed_technique_ids": [],
        "overall_rationale": "Remote code execution via out-of-bounds write in FortiOS SSL-VPN.",
    }

    mapping = _make_mapping(sample_cve_record.cve_id, mock_attack_data)
    enricher = AttackEnricher(mock_client, mock_attack_data)
    result = enricher.enrich(sample_cve_record, mapping)

    ids = result.technique_ids
    assert "T1203" in ids
    assert "T1190" in ids
    assert result.mapping_method == "claude_enriched"
    assert result.rationale != ""


def test_attack_enricher_removes_technique(mocker, sample_cve_record, mock_attack_data):
    mock_client = mocker.MagicMock()
    mock_client.complete_structured.return_value = {
        "confirmed_techniques": [],
        "added_techniques": [],
        "removed_technique_ids": ["T1203"],
        "overall_rationale": "Test removal.",
    }

    mapping = _make_mapping(sample_cve_record.cve_id, mock_attack_data)
    enricher = AttackEnricher(mock_client, mock_attack_data)
    result = enricher.enrich(sample_cve_record, mapping)

    assert "T1203" not in result.technique_ids


def test_ioc_extractor_parses_claude_output(mocker, sample_cve_record, mock_attack_data):
    mock_client = mocker.MagicMock()
    mock_client.complete_structured.return_value = {
        "network_iocs": [
            {
                "ioc_type": "url",
                "value": "https://target/ssl-vpn/portal.cgi",
                "confidence": "high",
                "context": "Exploit target endpoint for CVE-2024-21762",
            }
        ],
        "file_iocs": [],
        "process_iocs": [
            {
                "ioc_type": "process_name",
                "value": "sslvpnd",
                "confidence": "medium",
                "context": "FortiOS SSL-VPN daemon that processes crafted HTTP requests",
            }
        ],
        "behavioral_iocs": [
            {
                "ioc_type": "behavioral",
                "value": "Specially crafted HTTP request to SSL-VPN portal",
                "confidence": "inferred",
                "context": "Network-level exploit behavior",
            }
        ],
    }

    mapping = AttackMapping(cve_id=sample_cve_record.cve_id, techniques=[])
    extractor = IOCExtractor(mock_client)
    bundle = extractor.extract(sample_cve_record, mapping)

    assert len(bundle.network) >= 1
    assert len(bundle.process) >= 1
    assert len(bundle.behavioral) >= 1
    assert bundle.network[0].value == "https://target/ssl-vpn/portal.cgi"
