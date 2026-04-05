"""CVE analysis pipeline — orchestrates all stages."""

from __future__ import annotations

import concurrent.futures
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

logger = logging.getLogger(__name__)

from cve_intel import __version__
from cve_intel.enrichment.attack_enricher import AttackEnricher
from cve_intel.enrichment.claude_client import ClaudeClient, ClaudeError
from cve_intel.enrichment.ioc_extractor import IOCExtractor
from cve_intel.fetchers.attack_data import AttackData, get_attack_data
from cve_intel.fetchers.nvd import NVDFetcher, CVE_ID_PATTERN
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
from cve_intel.progress import NullProgress

if TYPE_CHECKING:
    from cve_intel.progress import ProgressContext

CVE_PATTERN = CVE_ID_PATTERN  # Re-exported for backward compatibility

RuleFormats = set[Literal["sigma", "yara", "snort", "suricata"]]


def analyze(
    cve_id: str,
    enrich: bool = True,
    rule_formats: RuleFormats | None = None,
    attack_data: AttackData | None = None,
    progress: "ProgressContext | None" = None,
    extract_iocs: bool = True,
    force_refresh: bool = False,
) -> AnalysisResult:
    """Run the full CVE analysis pipeline.

    Args:
        cve_id: CVE identifier, e.g. "CVE-2024-21762"
        enrich: Whether to use Claude for enrichment and rule generation.
        rule_formats: Which rule formats to generate. Defaults to all four.
        attack_data: Pre-loaded ATT&CK data (avoids re-downloading in batch mode).
        progress: Optional progress context for reporting stage status.
        extract_iocs: Whether to run IOC extraction. Set False when only the
            ATT&CK mapping is needed (e.g. the ``map`` command).
    """
    if rule_formats is None:
        rule_formats = {"sigma", "yara", "snort", "suricata"}

    prog = progress if progress is not None else NullProgress()
    warnings: list[str] = []

    # Stage 1: Validate
    prog.advance("Validating CVE ID")
    cve_id = cve_id.strip().upper()
    if not CVE_PATTERN.match(cve_id):
        raise ValueError(f"Invalid CVE ID: {cve_id!r}")

    # Stage 2: NVD Fetch
    prog.advance("Fetching NVD record")
    fetcher = NVDFetcher()
    cve_record = fetcher.fetch(cve_id, force_refresh=force_refresh)

    # Stage 2b: CISA Vulnrichment (non-blocking — failure returns empty data)
    prog.advance("Fetching CISA Vulnrichment data")
    vuln_context = fetch_vulnrichment(cve_id)

    # Stage 3: ATT&CK STIX Load
    prog.advance("Loading ATT&CK data")
    if attack_data is None:
        attack_data = get_attack_data(progress_callback=prog.download_callback())

    # Stage 4: Deterministic Mapping
    prog.advance("Mapping to ATT&CK techniques")
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
            prog.advance("Enriching ATT&CK mapping with Claude")
            prog.set_description("Calling Claude: ATT&CK enrichment…")
            enricher = AttackEnricher(client, attack_data)
            mapping = enricher.enrich(cve_record, mapping)

            # Stage 6: IOC Extraction (skipped when only the mapping is needed)
            if extract_iocs:
                prog.advance("Extracting IOCs")
                prog.set_description("Calling Claude: IOC extraction…")
                extractor = IOCExtractor(client)
                ioc_bundle = extractor.extract(cve_record, mapping)
            else:
                ioc_bundle = IOCBundle(cve_id=cve_id)

            # Stage 7: Rule Generation
            prog.advance("Generating detection rules")
            prog.set_description("Calling Claude: detection rule generation…")
            rule_bundle = _generate_rules(
                client, cve_record, mapping, ioc_bundle, rule_formats
            )

            enriched = True

        except ClaudeError as exc:
            # Degrade gracefully — surface warning through return value
            msg = (
                f"Claude enrichment unavailable: {exc}. "
                "Set ANTHROPIC_API_KEY to enable AI-powered analysis."
            )
            logger.warning(msg)
            warnings.append(msg)
            warnings.append(
                "IOC extraction and detection rule generation were skipped. "
                "Results show deterministic ATT&CK mapping only."
            )
            ioc_bundle = IOCBundle(cve_id=cve_id)
            rule_bundle = RuleBundle(cve_id=cve_id)
    else:
        ioc_bundle = IOCBundle(cve_id=cve_id)
        rule_bundle = RuleBundle(cve_id=cve_id)

    prog.advance("Finalising results")

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
        warnings=warnings,
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
    _GENERATORS = {
        "sigma": (SigmaGenerator, "sigma_rules"),
        "yara": (YaraGenerator, "yara_rules"),
        "snort": (SnortGenerator, "snort_rules"),
        "suricata": (SuricataGenerator, "suricata_rules"),
    }

    active = [(fmt, gen_cls, attr) for fmt, (gen_cls, attr) in _GENERATORS.items() if fmt in rule_formats]

    def _run(gen_cls, attr):
        rule = gen_cls(client).generate(cve_record, mapping, ioc_bundle)
        return attr, rule

    bundle = RuleBundle(cve_id=cve_record.cve_id)
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(active)) as executor:
        futures = {executor.submit(_run, gen_cls, attr): fmt for fmt, gen_cls, attr in active}
        for future in concurrent.futures.as_completed(futures):
            fmt = futures[future]
            try:
                attr, rule = future.result()
            except Exception as exc:
                logger.warning("Rule generation failed for format %r: %s", fmt, exc)
                continue
            if rule:
                getattr(bundle, attr).append(rule)

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
