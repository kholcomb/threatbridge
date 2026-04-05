"""Sigma rule generation with pySigma validation."""

import logging

from cve_intel.enrichment.claude_client import ClaudeClient

logger = logging.getLogger(__name__)
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
        cvss_vector = cvss.vector_string if cvss else ""
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

        confidence = result.get("confidence", "medium")
        description = result.get("description", "")
        warnings = self._check_sigma_semantics(rule_text, cvss_vector)
        if warnings:
            confidence = "low"
            description = "[QUALITY WARNING] " + "; ".join(warnings) + (" — " + description if description else "")

        try:
            category = RuleCategory(result.get("category", "behavioral"))
        except ValueError:
            category = RuleCategory.BEHAVIORAL

        return DetectionRule(
            cve_id=cve.cve_id,
            rule_format=RuleFormat.SIGMA,
            category=category,
            name=result.get("name", f"Detect {cve.cve_id} exploitation"),
            description=description,
            rule_text=rule_text,
            technique_ids=mapping.technique_ids,
            severity=result.get("severity", "medium"),
            confidence=confidence,
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
        """Return error string if the rule has structural/parse errors, None if valid.

        Uses pySigma for proper rule parsing and condition validation.
        Falls back to basic YAML checks if pySigma is unavailable.
        """
        try:
            from sigma.collection import SigmaCollection
            from sigma.validation import SigmaValidator
            from sigma.validators.core.condition import (
                DanglingConditionValidator,
                DanglingDetectionValidator,
            )
            from sigma.validators.core.modifiers import InvalidModifierCombinationsValidator
        except ImportError:
            return self._check_sigma_yaml_fallback(rule_text)

        try:
            col = SigmaCollection.from_yaml(rule_text)
        except Exception as exc:
            return str(exc)

        # Check for parse errors attached to rules
        for rule in col:
            if rule.errors:
                return "; ".join(str(e) for e in rule.errors)

        # Run structural validators that warrant a fix attempt
        validator = SigmaValidator([
            DanglingConditionValidator,
            DanglingDetectionValidator,
            InvalidModifierCombinationsValidator,
        ])
        issues = list(validator.validate_rules(col))
        if issues:
            return "; ".join(str(i) for i in issues)

        return None

    def _check_sigma_yaml_fallback(self, rule_text: str) -> str | None:
        """Minimal YAML-based check used when pySigma is unavailable."""
        try:
            import yaml
            doc = yaml.safe_load(rule_text)
            if not isinstance(doc, dict):
                return "Rule did not parse as a YAML mapping"
            missing = {"title", "logsource", "detection"} - set(doc.keys())
            if missing:
                return f"Missing required Sigma fields: {missing}"
            return None
        except Exception as exc:
            return str(exc)

    def _check_sigma_semantics(self, rule_text: str, cvss_vector: str) -> list[str]:
        """Return quality warnings. Empty list means no issues detected.

        Runs pySigma quality validators plus custom specificity checks.
        """
        warnings: list[str] = []

        # pySigma quality validators
        try:
            from sigma.collection import SigmaCollection
            from sigma.validation import SigmaValidator
            from sigma.validators.core.tags import ATTACKTagValidator, DuplicateTagValidator
            from sigma.validators.core.values import (
                DoubleWildcardValidator,
                ControlCharacterValidator,
            )
            from sigma.validators.core.condition import AllOfThemConditionValidator

            col = SigmaCollection.from_yaml(rule_text)
            validator = SigmaValidator([
                ATTACKTagValidator,
                DuplicateTagValidator,
                DoubleWildcardValidator,
                ControlCharacterValidator,
                AllOfThemConditionValidator,
            ])
            for issue in validator.validate_rules(col):
                warnings.append(str(issue))
        except Exception as exc:
            logger.warning("Sigma validation skipped for rule: %s", exc)  # Degrade gracefully; custom checks below still run

        # Custom specificity checks
        try:
            import yaml
            doc = yaml.safe_load(rule_text)
            if not isinstance(doc, dict):
                return warnings
        except Exception:
            return warnings

        detection_strings = _extract_detection_strings(doc.get("detection", {}))
        GENERIC = {".exe", ".dll", "cmd.exe", "powershell", "rundll32",
                   "wscript", "cscript", "mshta", "regsvr32", ".bat", ".ps1"}
        if detection_strings:
            specific = [s for s in detection_strings if s.lower() not in GENERIC and len(s) > 4]
            if not specific:
                warnings.append("detection strings are entirely generic — no CVE-specific indicators found")

        if "AV:N" in cvss_vector:
            logsource = doc.get("logsource", {})
            if isinstance(logsource, dict) and logsource.get("category") == "process_creation":
                warnings.append("logsource is process_creation but CVE has network attack vector (AV:N)")

        return warnings

    def _format_iocs(self, iocs: IOCBundle) -> str:
        lines: list[str] = []
        for ioc in iocs.all_iocs()[:20]:
            lines.append(f"  [{ioc.ioc_type.value}] {ioc.value} ({ioc.confidence.value}) — {ioc.context}")
        return "\n".join(lines) or "  (none extracted)"


def _extract_detection_strings(obj, _key: str = "") -> list[str]:
    """Recursively collect string leaf values from a Sigma detection dict, skipping 'condition'."""
    results: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k != "condition":
                results.extend(_extract_detection_strings(v, k))
    elif isinstance(obj, list):
        for item in obj:
            results.extend(_extract_detection_strings(item, _key))
    elif isinstance(obj, str):
        results.append(obj)
    return results
