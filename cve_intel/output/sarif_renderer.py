"""SARIF 2.1.0 renderer for CVE analysis results.

Produces output compatible with the GitHub Security tab
(upload via actions/upload-sarif).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cve_intel import __version__

if TYPE_CHECKING:
    from cve_intel.models.rules import AnalysisResult

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_CVSS_TO_LEVEL = {
    "critical": "error",
    "high": "warning",
    "medium": "note",
    "low": "none",
}


def _cvss_score_to_level(score: float | None, severity: str | None) -> str:
    if score is not None:
        if score >= 9.0:
            return "error"
        if score >= 7.0:
            return "warning"
        if score >= 4.0:
            return "note"
        return "none"
    if severity:
        return _CVSS_TO_LEVEL.get(severity.lower(), "note")
    return "note"


def render_sarif(results: "list[AnalysisResult]") -> dict:
    """Convert a list of AnalysisResult objects to a SARIF 2.1.0 dict."""
    rules = []
    sarif_results = []

    for result in results:
        cve = result.cve_record
        cve_id = result.cve_id

        # Pick primary CVSS score
        score: float | None = None
        severity: str | None = None
        vector: str | None = None
        description = cve.description_en or ""

        if cve.primary_cvss:
            score = cve.primary_cvss.base_score
            severity = cve.primary_cvss.base_severity
            vector = cve.primary_cvss.vector_string

        level = _cvss_score_to_level(score, severity)

        rule_entry: dict = {
            "id": cve_id,
            "name": "VulnerabilityDetected",
            "shortDescription": {
                "text": f"{cve_id}: {description[:120]}{'…' if len(description) > 120 else ''}"
            },
            "fullDescription": {"text": description},
            "defaultConfiguration": {"level": level},
            "helpUri": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "properties": {},
        }
        if score is not None:
            rule_entry["properties"]["cvss_score"] = score
        if severity:
            rule_entry["properties"]["cvss_severity"] = severity
        if vector:
            rule_entry["properties"]["cvss_vector"] = vector

        # ATT&CK technique IDs as tags
        technique_ids = [t.technique_id for t in result.attack_mapping.techniques]
        if technique_ids:
            rule_entry["properties"]["attack_techniques"] = technique_ids

        rules.append(rule_entry)

        result_entry: dict = {
            "ruleId": cve_id,
            "level": level,
            "message": {
                "text": (
                    f"{cve_id}"
                    + (f" — CVSS {score} ({severity.value if hasattr(severity, 'value') else severity})" if score is not None else "")
                    + f". ATT&CK: {', '.join(technique_ids) if technique_ids else 'none mapped'}."
                    + (f" {description[:256]}" if description else "")
                ).strip()
            },
            "locations": [],
        }
        sarif_results.append(result_entry)

    return {
        "version": "2.1.0",
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cve-intel",
                        "version": __version__,
                        "informationUri": "https://github.com/kholcomb/cve-intel",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
