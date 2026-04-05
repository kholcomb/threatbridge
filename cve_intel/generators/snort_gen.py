"""Snort/Suricata rule generation."""

from cve_intel.enrichment.claude_client import ClaudeClient
from cve_intel.enrichment.prompts import (
    SNORT_GEN_SYSTEM,
    SNORT_GEN_USER,
    SNORT_GEN_SCHEMA,
)
from cve_intel.models.attack import AttackMapping
from cve_intel.models.cve import CVERecord
from cve_intel.models.ioc import IOCBundle, IOCType
from cve_intel.models.rules import DetectionRule, RuleCategory, RuleFormat


class SnortGenerator:
    def __init__(self, client: ClaudeClient) -> None:
        self._client = client

    def generate(
        self, cve: CVERecord, mapping: AttackMapping, iocs: IOCBundle
    ) -> DetectionRule | None:
        techniques_text = "\n".join(
            f"  - {t.technique_id}: {t.name}" for t in mapping.techniques[:6]
        ) or "  N/A"

        network_iocs = iocs.network + [
            ioc for ioc in iocs.behavioral
            if any(kw in ioc.context.lower() for kw in ["http", "request", "network", "tcp", "udp"])
        ]
        ioc_lines = self._format_iocs_for_network(network_iocs)

        user_msg = SNORT_GEN_USER.format(
            cve_id=cve.cve_id,
            description=cve.description_en[:1500],
            products=", ".join(cve.affected_products[:8]) or "N/A",
            techniques=techniques_text,
            iocs=ioc_lines,
        )

        result = self._client.complete_structured(
            system=SNORT_GEN_SYSTEM,
            user=user_msg,
            output_schema=SNORT_GEN_SCHEMA,
            tool_name="generate_snort_rule",
        )

        rule_text = result.get("rule_text", "").strip()
        if not rule_text:
            return None

        confidence = result.get("confidence", "medium")
        description = result.get("description", "")
        warnings = self._check_snort_semantics(rule_text)
        if warnings:
            confidence = "low"
            description = "[QUALITY WARNING] " + "; ".join(warnings) + (" — " + description if description else "")

        return DetectionRule(
            cve_id=cve.cve_id,
            rule_format=RuleFormat.SNORT,
            category=RuleCategory.NETWORK_DETECTION,
            name=result.get("name", f"Detect {cve.cve_id} network exploit"),
            description=description,
            rule_text=rule_text,
            technique_ids=mapping.technique_ids,
            severity=result.get("severity", "medium"),
            confidence=confidence,
            tags=[cve.cve_id] + mapping.technique_ids,
            generation_method="claude_generated",
        )

    def _check_snort_semantics(self, rule_text: str) -> list[str]:
        """Return quality warnings. Empty list means no issues detected."""
        import re
        warnings: list[str] = []
        content_matches = re.findall(r'content:"([^"]+)"', rule_text)
        if not content_matches:
            warnings.append("no content matches — rule will match all traffic on matched port/protocol")
        else:
            GENERIC = {"GET", "POST", "PUT", "DELETE", "HTTP", "HTTP/1.1", "HTTP/1.0", "HEAD", "OPTIONS"}
            specific = [c for c in content_matches if c not in GENERIC and len(c) > 3]
            if not specific:
                warnings.append("content matches are all generic HTTP method/version strings")
        return warnings

    def _format_iocs_for_network(self, iocs) -> str:
        lines: list[str] = []
        for ioc in iocs[:15]:
            lines.append(f"  [{ioc.ioc_type.value}] {ioc.value} ({ioc.confidence.value}) — {ioc.context}")
        return "\n".join(lines) or "  (none — only write rules for traffic patterns explicitly described in the CVE description above)"
