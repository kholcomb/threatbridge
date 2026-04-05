"""Claude-powered ATT&CK technique enrichment."""

import logging

from cve_intel.enrichment.claude_client import ClaudeClient

logger = logging.getLogger(__name__)
from cve_intel.enrichment.prompts import (
    ATTACK_ENRICHER_SYSTEM,
    ATTACK_ENRICHER_USER,
    ATTACK_ENRICHER_SCHEMA,
)
from cve_intel.fetchers.attack_data import AttackData
from cve_intel.models.attack import AttackMapping, AttackTechnique
from cve_intel.models.cve import CVERecord


class AttackEnricher:
    def __init__(self, client: ClaudeClient, attack_data: AttackData) -> None:
        self._client = client
        self._attack_data = attack_data

    def enrich(self, cve: CVERecord, mapping: AttackMapping) -> AttackMapping:
        cvss = cve.primary_cvss
        candidates_text = "\n".join(
            f"  - {t.technique_id}: {t.name} (current confidence: {t.confidence:.1f})"
            for t in mapping.techniques
        ) or "  (none from static mapping)"

        user_msg = ATTACK_ENRICHER_USER.format(
            cve_id=cve.cve_id,
            description=cve.description_en[:2000],
            cvss_score=cvss.base_score if cvss else "N/A",
            cvss_severity=cvss.base_severity.value if cvss else "N/A",
            cvss_vector=cvss.vector_string if cvss else "N/A",
            products=", ".join(cve.affected_products[:10]) or "N/A",
            cwes=", ".join(cve.weaknesses) or "N/A",
            candidate_techniques=candidates_text,
        )

        result = self._client.complete_structured(
            system=ATTACK_ENRICHER_SYSTEM,
            user=user_msg,
            output_schema=ATTACK_ENRICHER_SCHEMA,
            tool_name="refine_attack_mapping",
        )

        removed_ids = set(result.get("removed_technique_ids", []))
        kept: list[AttackTechnique] = []

        for tech in mapping.techniques:
            if tech.technique_id not in removed_ids:
                # Update confidence/rationale from confirmed list
                for confirmed in result.get("confirmed_techniques", []):
                    if confirmed["technique_id"] == tech.technique_id:
                        tech = tech.model_copy(update={
                            "confidence": confirmed["confidence"],
                            "rationale": confirmed["rationale"],
                        })
                kept.append(tech)

        # Add new techniques identified by Claude
        existing_ids = {t.technique_id for t in kept}
        for added in result.get("added_techniques", []):
            tid = added["technique_id"]
            if tid in existing_ids:
                continue
            tech = self._attack_data.get_technique(tid)
            if tech:
                tech = tech.model_copy(update={
                    "confidence": added["confidence"],
                    "rationale": added["rationale"],
                })
                kept.append(tech)
            else:
                logger.warning("Claude suggested technique %r not found in ATT&CK bundle — skipping", tid)

        return AttackMapping(
            cve_id=cve.cve_id,
            techniques=sorted(kept, key=lambda t: t.confidence, reverse=True),
            mapping_method="claude_enriched",
            rationale=result.get("overall_rationale", ""),
        )
