"""CVE analysis pipeline — orchestrates all stages."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Literal

from cve_intel import __version__
from cve_intel.enrichment.attack_enricher import AttackEnricher
from cve_intel.enrichment.claude_client import ClaudeClient, ClaudeError
from cve_intel.enrichment.ioc_extractor import IOCExtractor
from cve_intel.fetchers.attack_data import AttackData, get_attack_data
from cve_intel.fetchers.nvd import NVDFetcher
from cve_intel.fetchers.vulnrichment import fetch_vulnrichment
from cve_intel.generators.sigma_gen import SigmaGenerator
from cve_intel.generators.snort_gen import SnortGenerator
from cve_intel.generators.suricata_gen import SuricataGenerator
from cve_intel.generators.yara_gen import YaraGenerator
from cve_intel.mappers.cvss_to_attack import map_cvss_to_attack
from cve_intel.mappers.cwe_to_attack import map_cwe_to_attack
from cve_intel.models.attack import AttackMapping
from cve_intel.models.ioc import IOCBundle
from cve_intel.models.rules import AnalysisResult, RuleBundle

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

RuleFormats = set[Literal["sigma", "yara", "snort", "suricata"]]


def analyze(
    cve_id: str,
    enrich: bool = True,
    rule_formats: RuleFormats | None = None,
    attack_data: AttackData | None = None,
) -> AnalysisResult:
    """Run the full CVE analysis pipeline.

    Args:
        cve_id: CVE identifier, e.g. "CVE-2024-21762"
        enrich: Whether to use Claude for enrichment and rule generation.
        rule_formats: Which rule formats to generate. Defaults to all four.
        attack_data: Pre-loaded ATT&CK data (avoids re-downloading in batch mode).
    """
    if rule_formats is None:
        rule_formats = {"sigma", "yara", "snort", "suricata"}

    # Stage 1: Validate
    cve_id = cve_id.strip().upper()
    if not CVE_PATTERN.match(cve_id):
        raise ValueError(f"Invalid CVE ID: {cve_id!r}")

    # Stage 2: NVD Fetch
    fetcher = NVDFetcher()
    cve_record = fetcher.fetch(cve_id)

    # Stage 2b: CISA Vulnrichment (non-blocking — failure returns empty data)
    vuln_context = fetch_vulnrichment(cve_id)

    # Stage 3: ATT&CK STIX Load
    if attack_data is None:
        attack_data = get_attack_data()

    # Stage 4: Deterministic Mapping
    mapping = map_cwe_to_attack(cve_id, cve_record.weaknesses, attack_data)

    if cve_record.primary_cvss:
        existing_ids = set(mapping.technique_ids)
        extra = map_cvss_to_attack(cve_id, cve_record.primary_cvss, attack_data, existing_ids)
        if extra:
            all_techs = mapping.techniques + extra
            mapping = mapping.model_copy(update={
                "techniques": all_techs,
                "mapping_method": "cwe_static+cvss_heuristic",
            })

    enriched = False

    if enrich:
        try:
            client = ClaudeClient()

            # Stage 5: Claude ATT&CK Enrichment
            enricher = AttackEnricher(client, attack_data)
            mapping = enricher.enrich(cve_record, mapping)

            # Stage 6: IOC Extraction
            extractor = IOCExtractor(client)
            ioc_bundle = extractor.extract(cve_record, mapping)

            # Stage 7: Rule Generation
            rule_bundle = _generate_rules(
                client, cve_record, mapping, ioc_bundle, rule_formats
            )

            enriched = True

        except ClaudeError as exc:
            # Degrade gracefully
            print(f"[warning] Claude enrichment unavailable: {exc}")
            print("[warning] Continuing with deterministic results only.")
            ioc_bundle = IOCBundle(cve_id=cve_id)
            rule_bundle = RuleBundle(cve_id=cve_id)
    else:
        ioc_bundle = IOCBundle(cve_id=cve_id)
        rule_bundle = RuleBundle(cve_id=cve_id)

    # Apply Vulnrichment severity boost to all generated rules
    severity_boost = vuln_context.suggested_severity_boost()
    if severity_boost:
        rule_bundle = _apply_severity_boost(rule_bundle, severity_boost)

    vuln_meta: dict = {}
    if vuln_context.available:
        vuln_meta = {
            "in_kev": vuln_context.in_kev,
            "kev_date_added": vuln_context.kev_date_added,
            "ssvc_exploitation": vuln_context.ssvc.exploitation,
            "ssvc_automatable": vuln_context.ssvc.automatable,
            "ssvc_technical_impact": vuln_context.ssvc.technical_impact,
            "is_actively_exploited": vuln_context.is_actively_exploited,
        }

    return AnalysisResult(
        cve_id=cve_id,
        cve_record=cve_record,
        attack_mapping=mapping,
        ioc_bundle=ioc_bundle,
        rule_bundle=rule_bundle,
        enriched=enriched,
        metadata={
            "tool_version": __version__,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "enrichment_requested": enrich,
            "rule_formats_requested": sorted(rule_formats),
            "vulnrichment": vuln_meta,
        },
    )


def _generate_rules(
    client: ClaudeClient,
    cve_record,
    mapping: AttackMapping,
    ioc_bundle: IOCBundle,
    rule_formats: RuleFormats,
) -> RuleBundle:
    bundle = RuleBundle(cve_id=cve_record.cve_id)

    if "sigma" in rule_formats:
        gen = SigmaGenerator(client)
        rule = gen.generate(cve_record, mapping, ioc_bundle)
        if rule:
            bundle.sigma_rules.append(rule)

    if "yara" in rule_formats:
        gen = YaraGenerator(client)
        rule = gen.generate(cve_record, mapping, ioc_bundle)
        if rule:
            bundle.yara_rules.append(rule)

    if "snort" in rule_formats:
        gen = SnortGenerator(client)
        rule = gen.generate(cve_record, mapping, ioc_bundle)
        if rule:
            bundle.snort_rules.append(rule)

    if "suricata" in rule_formats:
        gen = SuricataGenerator(client)
        rule = gen.generate(cve_record, mapping, ioc_bundle)
        if rule:
            bundle.suricata_rules.append(rule)

    return bundle


_SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


def _apply_severity_boost(bundle: RuleBundle, minimum: str) -> RuleBundle:
    """Upgrade rule severity to at least `minimum` based on exploitation context."""
    min_idx = _SEVERITY_ORDER.index(minimum) if minimum in _SEVERITY_ORDER else 0

    def boost(rule):
        current = _SEVERITY_ORDER.index(rule.severity) if rule.severity in _SEVERITY_ORDER else 0
        if current < min_idx:
            return rule.model_copy(update={"severity": minimum})
        return rule

    return bundle.model_copy(update={
        "sigma_rules": [boost(r) for r in bundle.sigma_rules],
        "yara_rules": [boost(r) for r in bundle.yara_rules],
        "snort_rules": [boost(r) for r in bundle.snort_rules],
        "suricata_rules": [boost(r) for r in bundle.suricata_rules],
    })
