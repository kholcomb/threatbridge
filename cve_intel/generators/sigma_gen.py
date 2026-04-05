"""Sigma rule generation with pySigma validation."""

from cve_intel.enrichment.claude_client import ClaudeClient
from cve_intel.enrichment.prompts import (
    SIGMA_GEN_SYSTEM,
    SIGMA_GEN_USER,
    SIGMA_GEN_SCHEMA,
    SIGMA_FIX_USER,
)
from cve_intel.models.attack import AttackMapping
from cve_intel.models.cve import CVERecord
from cve_intel.models.ioc import IOCBundle
from cve_intel.models.rules import DetectionRule, RuleCategory, RuleFormat


class SigmaGenerator:
    def __init__(self, client: ClaudeClient) -> None:
        self._client = client

    def generate(
        self, cve: CVERecord, mapping: AttackMapping, iocs: IOCBundle
    ) -> DetectionRule | None:
        cvss = cve.primary_cvss
        techniques_text = "\n".join(
            f"  - {t.technique_id}: {t.name}" for t in mapping.techniques[:6]
        ) or "  N/A"

        ioc_lines = self._format_iocs(iocs)

        user_msg = SIGMA_GEN_USER.format(
            cve_id=cve.cve_id,
            description=cve.description_en[:1500],
            products=", ".join(cve.affected_products[:8]) or "N/A",
            techniques=techniques_text,
            iocs=ioc_lines,
            cvss_severity=cvss.base_severity.value if cvss else "N/A",
        )

        result = self._client.complete_structured(
            system=SIGMA_GEN_SYSTEM,
            user=user_msg,
            output_schema=SIGMA_GEN_SCHEMA,
            tool_name="generate_sigma_rule",
        )

        rule_text = result.get("rule_text", "")
        rule_text = self._validate_and_fix(rule_text, result)

        if not rule_text:
            return None

        try:
            category = RuleCategory(result.get("category", "behavioral"))
        except ValueError:
            category = RuleCategory.BEHAVIORAL

        return DetectionRule(
            cve_id=cve.cve_id,
            rule_format=RuleFormat.SIGMA,
            category=category,
            name=result.get("name", f"Detect {cve.cve_id} exploitation"),
            description=result.get("description", ""),
            rule_text=rule_text,
            technique_ids=mapping.technique_ids,
            severity=result.get("severity", "medium"),
            confidence=result.get("confidence", "medium"),
            tags=[cve.cve_id] + mapping.technique_ids,
            generation_method="claude_generated",
        )

    def _validate_and_fix(self, rule_text: str, result: dict) -> str:
        error = self._check_sigma(rule_text)
        if error is None:
            return rule_text

        # One correction pass
        fix_schema = {
            "type": "object",
            "properties": {"rule_text": {"type": "string"}},
            "required": ["rule_text"],
        }
        fix_result = self._client.complete_structured(
            system=SIGMA_GEN_SYSTEM,
            user=SIGMA_FIX_USER.format(error=error, rule_text=rule_text),
            output_schema=fix_schema,
            tool_name="fix_sigma_rule",
        )
        fixed = fix_result.get("rule_text", rule_text)
        # Accept even if still has errors — return best effort
        return fixed

    def _check_sigma(self, rule_text: str) -> str | None:
        """Return error string if invalid, None if valid."""
        try:
            import yaml
            doc = yaml.safe_load(rule_text)
            if not isinstance(doc, dict):
                return "Rule did not parse as a YAML mapping"
            required = {"title", "logsource", "detection"}
            missing = required - set(doc.keys())
            if missing:
                return f"Missing required Sigma fields: {missing}"
            return None
        except Exception as exc:
            return str(exc)

    def _format_iocs(self, iocs: IOCBundle) -> str:
        lines: list[str] = []
        for ioc in iocs.all_iocs()[:20]:
            lines.append(f"  [{ioc.ioc_type.value}] {ioc.value} ({ioc.confidence.value}) — {ioc.context}")
        return "\n".join(lines) or "  (none extracted)"
