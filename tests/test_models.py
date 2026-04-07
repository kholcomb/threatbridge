"""Tests for Pydantic data models."""

from datetime import datetime, timezone

import pytest

from cve_intel.models.cve import CVERecord, CVSSData, CVSSSeverity, CPEMatch
from cve_intel.models.attack import AttackMapping, AttackTechnique, AttackTactic
from cve_intel.models.ioc import IOC, IOCBundle, IOCType, IOCConfidence
from cve_intel.models.rules import DetectionRule, RuleBundle, RuleFormat, RuleCategory


def test_cve_record_primary_cvss_prefers_highest_version():
    now = datetime.now(timezone.utc)
    cvss_v2 = CVSSData(version="2.0", vector_string="AV:N/AC:L/Au:N/C:C/I:C/A:C",
                       base_score=10.0, base_severity=CVSSSeverity.HIGH)
    cvss_v31 = CVSSData(version="3.1", vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        base_score=9.8, base_severity=CVSSSeverity.CRITICAL)
    record = CVERecord(
        cve_id="CVE-2024-0001",
        published=now, last_modified=now,
        cvss=[cvss_v2, cvss_v31],
    )
    assert record.primary_cvss.version == "3.1"


def test_cve_record_affected_products():
    now = datetime.now(timezone.utc)
    record = CVERecord(
        cve_id="CVE-2024-0001",
        published=now, last_modified=now,
        cpe_matches=[
            CPEMatch(criteria="cpe:2.3:o:fortinet:fortios:7.4.0:*:*:*:*:*:*:*"),
            CPEMatch(criteria="cpe:2.3:a:fortinet:fortiproxy:7.4.0:*:*:*:*:*:*:*"),
        ],
    )
    products = record.affected_products
    assert "fortinet/fortios" in products
    assert "fortinet/fortiproxy" in products


def test_ioc_bundle_all_iocs():
    bundle = IOCBundle(cve_id="CVE-2024-0001")
    bundle.network.append(IOC(
        ioc_type=IOCType.URL, value="http://evil.example/exploit",
        confidence=IOCConfidence.HIGH, context="Exploit URL",
    ))
    bundle.behavioral.append(IOC(
        ioc_type=IOCType.BEHAVIORAL, value="Unusual HTTP request",
        confidence=IOCConfidence.INFERRED, context="Exploit pattern",
    ))
    assert len(bundle.all_iocs()) == 2


def test_attack_mapping_technique_ids():
    tactic = AttackTactic(tactic_id="TA0001", name="Initial Access", shortname="initial-access")
    tech = AttackTechnique(technique_id="T1190", name="Exploit Public-Facing Application", tactics=[tactic])
    mapping = AttackMapping(cve_id="CVE-2024-0001", techniques=[tech])
    assert "T1190" in mapping.technique_ids


def test_rule_bundle_all_rules():
    from datetime import datetime, timezone
    sigma = DetectionRule(
        cve_id="CVE-2024-0001",
        rule_format=RuleFormat.SIGMA,
        category=RuleCategory.NETWORK_DETECTION,
        name="Test Sigma",
        rule_text="title: Test",
    )
    bundle = RuleBundle(cve_id="CVE-2024-0001", sigma_rules=[sigma])
    assert len(bundle.all_rules()) == 1
