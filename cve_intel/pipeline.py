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
