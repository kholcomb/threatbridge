"""Integration test for the full pipeline (all external calls mocked)."""

import pytest


def test_pipeline_full_enriched(mocker, sample_cve_record, mock_attack_data):
    """End-to-end pipeline test with mocked NVD, ATT&CK, and Claude."""
    # Mock NVD fetcher
    mocker.patch(
        "cve_intel.pipeline.NVDFetcher.fetch",
        return_value=sample_cve_record,
    )
    # Mock ATT&CK loader
    mocker.patch(
        "cve_intel.pipeline.get_attack_data",
        return_value=mock_attack_data,
    )
    # Mock Claude client constructor and all three enrichment calls
    mock_client = mocker.MagicMock()
    mocker.patch("cve_intel.pipeline.ClaudeClient", return_value=mock_client)

    mock_client.complete_structured.side_effect = [
        # AttackEnricher
        {
            "confirmed_techniques": [
                {"technique_id": "T1203", "confidence": 0.9, "rationale": "OOB write RCE"}
            ],
            "added_techniques": [],
            "removed_technique_ids": [],
            "overall_rationale": "RCE via out-of-bounds write in SSL-VPN.",
        },
        # IOCExtractor
        {
            "network_iocs": [{"ioc_type": "url", "value": "/ssl-vpn/portal.cgi",
                              "confidence": "high", "context": "Exploit endpoint"}],
            "file_iocs": [],
            "process_iocs": [],
            "behavioral_iocs": [],
        },
        # SigmaGenerator
        {
            "rule_text": "title: Test\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    cs-uri: test\n  condition: selection\n",
            "name": "Test Sigma", "description": "Test", "category": "network_detection",
            "severity": "critical", "confidence": "high",
        },
        # YaraGenerator
        {
            "rule_text": 'rule test_rule {\n  strings:\n    $a = "test"\n  condition:\n    $a\n}\n',
            "name": "test_rule", "description": "Test", "category": "file_detection",
            "severity": "critical", "confidence": "medium",
        },
        # SnortGenerator
        {
            "rule_text": 'alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)',
            "name": "Test Snort", "description": "Test",
            "severity": "critical", "confidence": "medium",
        },
        # SuricataGenerator
        {
            "rule_text": 'alert http any any -> any any (msg:"Test Suricata"; http.uri; content:"/test"; sid:2; rev:1;)',
            "name": "Test Suricata", "description": "Test",
            "severity": "critical", "confidence": "medium",
        },
    ]

    from cve_intel.pipeline import analyze
    result = analyze("CVE-2024-21762", enrich=True)

    assert result.cve_id == "CVE-2024-21762"
    assert result.enriched is True
    assert len(result.attack_mapping.techniques) >= 1
    assert len(result.ioc_bundle.network) >= 1
    assert len(result.rule_bundle.sigma_rules) == 1
    assert len(result.rule_bundle.yara_rules) == 1
    assert len(result.rule_bundle.snort_rules) == 1
    assert len(result.rule_bundle.suricata_rules) == 1


def test_pipeline_no_enrich(mocker, sample_cve_record, mock_attack_data):
    """Pipeline without enrichment should skip Claude and produce empty IOC/rules."""
    mocker.patch("cve_intel.pipeline.NVDFetcher.fetch", return_value=sample_cve_record)
    mocker.patch("cve_intel.pipeline.get_attack_data", return_value=mock_attack_data)

    from cve_intel.pipeline import analyze
    result = analyze("CVE-2024-21762", enrich=False)

    assert result.enriched is False
    assert result.ioc_bundle.all_iocs() == []
    assert result.rule_bundle.all_rules() == []
    # Should still have deterministic ATT&CK mapping from CWE-787
    assert len(result.attack_mapping.techniques) >= 1


def test_pipeline_claude_failure_degrades_gracefully(mocker, sample_cve_record, mock_attack_data):
    """If Claude is unavailable, pipeline should continue with deterministic output."""
    mocker.patch("cve_intel.pipeline.NVDFetcher.fetch", return_value=sample_cve_record)
    mocker.patch("cve_intel.pipeline.get_attack_data", return_value=mock_attack_data)

    from cve_intel.enrichment.claude_client import ClaudeError
    mocker.patch("cve_intel.pipeline.ClaudeClient", side_effect=ClaudeError("No API key"))

    from cve_intel.pipeline import analyze
    result = analyze("CVE-2024-21762", enrich=True)

    assert result.enriched is False
    assert result.rule_bundle.all_rules() == []
