"""SARIF 2.1.0 renderer for CVE analysis results.

Produces output compatible with the GitHub Security tab
(upload via actions/upload-sarif).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cve_intel import __version__

if TYPE_CHECKING:
    from cve_intel.models.rules import AnalysisResult

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_CVSS_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "warning",
    "medium": "note",
    "low": "none",
}


@dataclass
class SarifPolicy:
    """Controls how CVE risk signals map to SARIF levels.

    CVSS thresholds are the baseline.  KEV and SSVC signals take priority —
    explicit exploitation evidence overrides a numeric score.

    Use SarifPolicy.from_preset() to start from a named preset, then
    override individual fields as needed.
    """

    cvss_error: float = 9.0
    cvss_warning: float = 7.0
    cvss_note: float = 4.0
    kev_is_error: bool = True
    ssvc_active_is_error: bool = True
    ssvc_poc_is_warning: bool = True

    @classmethod
    def from_preset(cls, preset: str) -> "SarifPolicy":
        """Return a SarifPolicy initialised from a named preset.

        Presets align with CVSS severity bands:
          default — Critical=error, High=warning, Medium=note. KEV and SSVC
                    active always escalate to error. PoC bumps to warning.
          strict  — High+Critical=error. Same KEV/SSVC escalation. Zero
                    tolerance for exploitable vulnerabilities.
          lenient — Critical=error via CVSS only. No KEV/SSVC escalation.
                    Pure score-based triage, no exploitation signal override.
        """
        presets: dict[str, dict] = {
            "default": {},  # all dataclass defaults
            "strict": {
                "cvss_error": 7.0,
            },
            "lenient": {
                "kev_is_error": False,
                "ssvc_active_is_error": False,
                "ssvc_poc_is_warning": False,
            },
        }
        if preset not in presets:
            raise ValueError(f"Unknown SARIF policy preset {preset!r}. Choose: {', '.join(presets)}")
        return cls(**presets[preset])


def _assign_level(
    score: float | None,
    severity: str | None,
    vuln_meta: dict,
    policy: SarifPolicy,
) -> str:
    """Assign a SARIF level using policy, KEV/SSVC signals, then CVSS score."""

    # Exploitation evidence takes priority over CVSS score.
    if policy.kev_is_error and vuln_meta.get("in_kev"):
        return "error"
    if policy.ssvc_active_is_error and vuln_meta.get("ssvc_exploitation") == "active":
        return "error"

    # CVSS baseline.
    if score is not None:
        if score >= policy.cvss_error:
            level = "error"
        elif score >= policy.cvss_warning:
            level = "warning"
        elif score >= policy.cvss_note:
            level = "note"
        else:
            level = "none"
    elif severity:
        level = _CVSS_SEVERITY_TO_LEVEL.get(severity.lower(), "note")
    else:
        level = "note"

    # PoC existence bumps low levels up to at least warning.
    if policy.ssvc_poc_is_warning and vuln_meta.get("ssvc_exploitation") == "poc":
        if level in ("note", "none"):
            level = "warning"

    return level


def assign_levels(
    results: "list[AnalysisResult]",
    policy: SarifPolicy | None = None,
) -> dict[str, str]:
    """Return a dict of cve_id → SARIF level for a list of results.

    Used by the VEX renderer to determine analysis state without re-running
    the full SARIF render.
    """
    if policy is None:
        policy = SarifPolicy()
    out: dict[str, str] = {}
    for result in results:
        cve = result.cve_record
        vuln_meta: dict = result.metadata.get("vulnrichment", {})
        score = cve.primary_cvss.base_score if cve.primary_cvss else None
        severity = cve.primary_cvss.base_severity if cve.primary_cvss else None
        out[result.cve_id] = _assign_level(score, severity, vuln_meta, policy)
    return out


def render_sarif(
    results: "list[AnalysisResult]",
    policy: SarifPolicy | None = None,
    findings: "dict[str, Any] | None" = None,
) -> dict:
    """Convert a list of AnalysisResult objects to a SARIF 2.1.0 dict.

    Args:
        results:  AnalysisResult objects from the pipeline.
        policy:   Severity assignment policy (default: SarifPolicy()).
        findings: Optional dict of cve_id → ScannerFinding.  When provided,
                  each result entry gains a populated 'locations' array (package
                  name + installed version) and a 'fixes' array (fixed version).
                  Compatible with GitHub Security tab, GitLab, and Azure DevOps.
    """
    if policy is None:
        policy = SarifPolicy()

    pkgs = findings or {}

    rules = []
    sarif_results = []

    for result in results:
        cve = result.cve_record
        cve_id = result.cve_id
        vuln_meta: dict = result.metadata.get("vulnrichment", {})

        score: float | None = None
        severity: str | None = None
        vector: str | None = None
        description = cve.description_en or ""

        if cve.primary_cvss:
            score = cve.primary_cvss.base_score
            severity = cve.primary_cvss.base_severity
            vector = cve.primary_cvss.vector_string

        level = _assign_level(score, severity, vuln_meta, policy)

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
        if vuln_meta.get("in_kev"):
            rule_entry["properties"]["kev"] = True
        if vuln_meta.get("ssvc_exploitation"):
            rule_entry["properties"]["ssvc_exploitation"] = vuln_meta["ssvc_exploitation"]

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
                    + (f" [KEV]" if vuln_meta.get("in_kev") else "")
                    + (f" [SSVC:{vuln_meta['ssvc_exploitation']}]" if vuln_meta.get("ssvc_exploitation") else "")
                    + f". ATT&CK: {', '.join(technique_ids) if technique_ids else 'none mapped'}."
                    + (f" {description[:256]}" if description else "")
                ).strip()
            },
            "locations": [],
        }

        # Populate package location from scanner input when available.
        # GitHub Code Scanning requires at least one location on every result;
        # fall back to a logical location keyed on the CVE ID when no package
        # context is present.
        finding = pkgs.get(cve_id)
        if finding and finding.package:
            fqn = finding.package
            if finding.installed_version:
                fqn = f"{finding.package}:{finding.installed_version}"
            result_entry["locations"] = [{
                "logicalLocations": [{
                    "name": finding.package,
                    "fullyQualifiedName": fqn,
                    "kind": "package",
                }]
            }]
        else:
            result_entry["locations"] = [{
                "logicalLocations": [{
                    "name": cve_id,
                    "fullyQualifiedName": cve_id,
                    "kind": "module",
                }]
            }]

            # Fix version → SARIF fixes array (shown in GitHub Security tab)
            if finding.fixed_version:
                result_entry["fixes"] = [{
                    "description": {
                        "text": f"Upgrade {finding.package} to {finding.fixed_version}"
                    },
                    "artifactChanges": [{
                        "artifactLocation": {"uri": finding.package},
                        "replacements": [{
                            "deletedRegion": {"startLine": 1, "endLine": 1},
                            "insertedContent": {"text": finding.fixed_version},
                        }]
                    }]
                }]

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
