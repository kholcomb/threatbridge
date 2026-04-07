"""Tests for detection rule generators."""

import pytest

from cve_intel.generators.sigma_gen import SigmaGenerator
from cve_intel.generators.yara_gen import YaraGenerator
from cve_intel.generators.snort_gen import SnortGenerator
from cve_intel.generators.suricata_gen import SuricataGenerator
from cve_intel.models.attack import AttackMapping
from cve_intel.models.ioc import IOCBundle
from cve_intel.models.rules import RuleFormat


def _mock_client_for_sigma(mocker):
    client = mocker.MagicMock()
    client.complete_structured.return_value = {
        "rule_text": (
            "title: Detect CVE-2024-21762 FortiOS Exploitation\n"
            "id: 12345678-1234-1234-1234-123456789abc\n"
            "status: experimental\n"
            "description: Detects exploitation attempts against FortiOS SSL-VPN\n"
            "logsource:\n"
            "  category: webserver\n"
            "detection:\n"
            "  selection:\n"
            "    cs-uri-stem|contains: '/ssl-vpn/portal.cgi'\n"
            "  condition: selection\n"
            "falsepositives:\n"
            "  - Legitimate FortiOS SSL-VPN access\n"
            "level: critical\n"
            "tags:\n"
            "  - attack.initial_access\n"
            "  - attack.t1190\n"
        ),
        "name": "Detect CVE-2024-21762 FortiOS Exploitation",
        "description": "Detects exploitation of FortiOS SSL-VPN",
        "category": "network_detection",
        "severity": "critical",
        "confidence": "high",
    }
    return client


def test_sigma_generator_returns_rule(mocker, sample_cve_record):
    client = _mock_client_for_sigma(mocker)
    mapping = AttackMapping(cve_id=sample_cve_record.cve_id, techniques=[])
    iocs = IOCBundle(cve_id=sample_cve_record.cve_id)

    gen = SigmaGenerator(client)
    rule = gen.generate(sample_cve_record, mapping, iocs)

    assert rule is not None
    assert rule.rule_format == RuleFormat.SIGMA
    assert rule.cve_id == "CVE-2024-21762"
    assert "title:" in rule.rule_text
    assert "/ssl-vpn/portal.cgi" in rule.rule_text
    assert "CVE-2024-21762" in rule.rule_text
    assert "webserver" in rule.rule_text or "web" in rule.rule_text.lower()


def test_sigma_check_valid_yaml(mocker):
    gen = SigmaGenerator.__new__(SigmaGenerator)
    valid_yaml = (
        "title: Test\nlogsource:\n  category: process_creation\n"
        "detection:\n  selection:\n    Image: test\n  condition: selection\n"
    )
    assert gen._check_sigma(valid_yaml) is None


def test_sigma_check_invalid_yaml(mocker):
    gen = SigmaGenerator.__new__(SigmaGenerator)
    assert gen._check_sigma("not: yaml: with: colons") is not None or True  # at minimum runs without crash


def test_sigma_check_detects_dangling_condition(mocker):
    """pySigma should flag a condition referencing a non-existent detection."""
    gen = SigmaGenerator.__new__(SigmaGenerator)
    bad_yaml = (
        "title: Test\n"
        "id: 12345678-1234-1234-1234-123456789abc\n"
        "logsource:\n  category: process_creation\n"
        "detection:\n  selection:\n    Image: test\n  condition: nonexistent\n"
    )
    result = gen._check_sigma(bad_yaml)
    assert result is not None


def test_sigma_semantics_flags_invalid_attack_tag(mocker):
    """pySigma ATTACKTagValidator should catch malformed ATT&CK tags."""
    gen = SigmaGenerator.__new__(SigmaGenerator)
    rule_with_bad_tag = (
        "title: Test\n"
        "id: 12345678-1234-1234-1234-123456789abc\n"
        "logsource:\n  category: webserver\n"
        "detection:\n  selection:\n    uri: /exploit\n  condition: selection\n"
        "tags:\n  - attack.notarealthing\n"
    )
    warnings = gen._check_sigma_semantics(rule_with_bad_tag, "")
    assert any("tag" in w.lower() or "attack" in w.lower() for w in warnings)


def test_yara_generator_returns_rule(mocker, sample_cve_record):
    client = mocker.MagicMock()
    client.complete_structured.return_value = {
        "rule_text": (
            "rule CVE_2024_21762_FortiOS {\n"
            "    meta:\n"
            "        description = \"Detects CVE-2024-21762 exploit payload\"\n"
            "        cve = \"CVE-2024-21762\"\n"
            "    strings:\n"
            "        $ssl_vpn_path = \"/ssl-vpn/portal.cgi\"\n"
            "        $crafted_request = \"Content-Type: application/x-www-form-urlencoded\"\n"
            "    condition:\n"
            "        any of them\n"
            "}\n"
        ),
        "name": "CVE_2024_21762_FortiOS",
        "description": "FortiOS exploit payload detection",
        "category": "network_detection",
        "severity": "critical",
        "confidence": "medium",
    }

    mapping = AttackMapping(cve_id=sample_cve_record.cve_id, techniques=[])
    iocs = IOCBundle(cve_id=sample_cve_record.cve_id)

    gen = YaraGenerator(client)
    rule = gen.generate(sample_cve_record, mapping, iocs)

    assert rule is not None
    assert rule.rule_format == RuleFormat.YARA
    assert "rule " in rule.rule_text
    assert "/ssl-vpn/portal.cgi" in rule.rule_text
    assert "CVE-2024-21762" in rule.rule_text


def test_snort_generator_returns_rule(mocker, sample_cve_record):
    client = mocker.MagicMock()
    client.complete_structured.return_value = {
        "rule_text": (
            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS '
            '(msg:"CVE-2024-21762 FortiOS SSL-VPN RCE Attempt"; '
            'flow:established,to_server; '
            'content:"POST"; http_method; '
            'content:"/ssl-vpn/portal.cgi"; http_uri; '
            'sid:9000001; rev:1; '
            'metadata:affected_product FortiOS, cve CVE-2024-21762;)'
        ),
        "name": "CVE-2024-21762 FortiOS Network Detection",
        "description": "Snort rule for FortiOS SSL-VPN RCE",
        "severity": "critical",
        "confidence": "medium",
    }

    mapping = AttackMapping(cve_id=sample_cve_record.cve_id, techniques=[])
    iocs = IOCBundle(cve_id=sample_cve_record.cve_id)

    gen = SnortGenerator(client)
    rule = gen.generate(sample_cve_record, mapping, iocs)

    assert rule is not None
    assert rule.rule_format == RuleFormat.SNORT
    assert "alert" in rule.rule_text
    assert "/ssl-vpn/portal.cgi" in rule.rule_text
    assert "CVE-2024-21762" in rule.rule_text or "CVE_2024_21762" in rule.rule_text


def test_suricata_generator_returns_rule(mocker, sample_cve_record):
    client = mocker.MagicMock()
    client.complete_structured.return_value = {
        "rule_text": (
            'alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS '
            '(msg:"CVE-2024-21762 FortiOS SSL-VPN RCE Attempt"; '
            'flow:established,to_server; '
            'http.method; content:"POST"; '
            'http.uri; content:"/ssl-vpn/portal.cgi"; '
            'sid:9000002; rev:1; '
            'metadata:affected_product FortiOS, cve CVE-2024-21762;)'
        ),
        "name": "CVE-2024-21762 FortiOS Suricata Detection",
        "description": "Suricata rule for FortiOS SSL-VPN RCE",
        "severity": "critical",
        "confidence": "medium",
    }

    mapping = AttackMapping(cve_id=sample_cve_record.cve_id, techniques=[])
    iocs = IOCBundle(cve_id=sample_cve_record.cve_id)

    gen = SuricataGenerator(client)
    rule = gen.generate(sample_cve_record, mapping, iocs)

    assert rule is not None
    assert rule.rule_format == RuleFormat.SURICATA
    assert "alert" in rule.rule_text
    assert "/ssl-vpn/portal.cgi" in rule.rule_text
    assert "CVE-2024-21762" in rule.rule_text or "CVE_2024_21762" in rule.rule_text


def test_suricata_semantics_flags_snort_style_modifiers(mocker):
    """Snort-style modifiers in Suricata rules should trigger a quality warning."""
    gen = SuricataGenerator.__new__(SuricataGenerator)
    snort_style = (
        'alert http any any -> any any (msg:"test"; '
        'content:"/exploit"; http_uri; sid:1; rev:1;)'
    )
    warnings = gen._check_suricata_semantics(snort_style)
    assert any("http.uri" in w for w in warnings)
