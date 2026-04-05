"""YARA rule generation with yara-python validation."""

from cve_intel.enrichment.claude_client import ClaudeClient
from cve_intel.enrichment.prompts import (
    YARA_GEN_SYSTEM,
    YARA_GEN_USER,
    YARA_GEN_SCHEMA,
    YARA_FIX_USER,
)
from cve_intel.models.attack import AttackMapping
from cve_intel.models.cve import CVERecord
from cve_intel.models.ioc import IOCBundle
from cve_intel.models.rules import DetectionRule, RuleCategory, RuleFormat


class YaraGenerator:
    def __init__(self, client: ClaudeClient) -> None:
        self._client = client

    def generate(
        self, cve: CVERecord, mapping: AttackMapping, iocs: IOCBundle
    ) -> DetectionRule | None:
        techniques_text = "\n".join(
            f"  - {t.technique_id}: {t.name}" for t in mapping.techniques[:6]
        ) or "  N/A"

        ioc_lines = self._format_iocs(iocs)

        user_msg = YARA_GEN_USER.format(
            cve_id=cve.cve_id,
            description=cve.description_en[:1500],
            products=", ".join(cve.affected_products[:8]) or "N/A",
            techniques=techniques_text,
            iocs=ioc_lines,
        )

        result = self._client.complete_structured(
            system=YARA_GEN_SYSTEM,
            user=user_msg,
            output_schema=YARA_GEN_SCHEMA,
            tool_name="generate_yara_rule",
        )

        rule_text = result.get("rule_text", "")
        rule_text = self._validate_and_fix(rule_text)

        if not rule_text:
            return None

        try:
            category = RuleCategory(result.get("category", "file_detection"))
        except ValueError:
            category = RuleCategory.FILE_DETECTION

        return DetectionRule(
            cve_id=cve.cve_id,
            rule_format=RuleFormat.YARA,
            category=category,
            name=result.get("name", f"detect_{cve.cve_id.replace('-', '_')}"),
            description=result.get("description", ""),
            rule_text=rule_text,
            technique_ids=mapping.technique_ids,
            severity=result.get("severity", "medium"),
            confidence=result.get("confidence", "medium"),
            tags=[cve.cve_id] + mapping.technique_ids,
            generation_method="claude_generated",
        )

    def _validate_and_fix(self, rule_text: str) -> str:
        error = self._check_yara(rule_text)
        if error is None:
            return rule_text

        fix_schema = {
            "type": "object",
            "properties": {"rule_text": {"type": "string"}},
            "required": ["rule_text"],
        }
        fix_result = self._client.complete_structured(
            system=YARA_GEN_SYSTEM,
            user=YARA_FIX_USER.format(error=error, rule_text=rule_text),
            output_schema=fix_schema,
            tool_name="fix_yara_rule",
        )
        return fix_result.get("rule_text", rule_text)

    def _check_yara(self, rule_text: str) -> str | None:
        try:
            import yara
            yara.compile(source=rule_text)
            return None
        except ImportError:
            # yara-python not available — skip validation
            return None
        except Exception as exc:
            return str(exc)

    def _format_iocs(self, iocs: IOCBundle) -> str:
        lines: list[str] = []
        for ioc in (iocs.file + iocs.network + iocs.behavioral)[:20]:
            lines.append(f"  [{ioc.ioc_type.value}] {ioc.value} ({ioc.confidence.value}) — {ioc.context}")
        return "\n".join(lines) or "  (none extracted)"
