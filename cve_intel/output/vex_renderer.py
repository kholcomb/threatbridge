"""CycloneDX VEX (Vulnerability Exploitability eXchange) renderer.

Produces a CycloneDX 1.5 JSON document alongside the SARIF output.
VEX documents the triage decisions made by cve-intel so they can be:
  - Carried forward to suppress re-triage on subsequent runs
  - Shared with auditors as a machine-readable applicability record
  - Annotated by teams to add 'not_affected' justifications

VEX analysis states (CycloneDX spec)
-------------------------------------
affected           — vulnerability is exploitable in this deployment
under_investigation — no determination yet (MEDIUM/LOW without exploitation evidence)
not_affected       — present but not exploitable (set manually by the team with justification)
fixed              — resolved in the current version

not_affected justifications (for team annotation)
--------------------------------------------------
code_not_reachable
vulnerable_code_not_in_execute_path     e.g. Spring4Shell: deployed as Boot JAR
inline_mitigations_already_exist        e.g. Log4Shell: egress filtering blocks LDAP
component_not_present                   scanner false positive
requires_configuration                  e.g. feature flag disabled

CI/CD integration
-----------------
Write alongside results.sarif.json when --output is set.
Re-ingest on subsequent runs to carry forward 'not_affected' decisions:
  cve-intel batch scan.sarif --from sarif --vex previous.vex.json
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

from cve_intel import __version__

if TYPE_CHECKING:
    from cve_intel.fetchers.scanner_input import ScannerFinding, VexDecision
    from cve_intel.models.rules import AnalysisResult


# Priority tiers that map to VEX 'affected' state
_AFFECTED_TIERS = {"CRITICAL", "HIGH"}

# SARIF level → VEX state
_LEVEL_TO_STATE = {
    "error":   "affected",
    "warning": "affected",
    "note":    "under_investigation",
    "none":    "under_investigation",
}


def render_vex(
    results: list[AnalysisResult],
    sarif_levels: dict[str, str] | None = None,
    findings: dict[str, ScannerFinding] | None = None,
    prior_decisions: list[VexDecision] | None = None,
) -> dict:
    """Produce a CycloneDX 1.5 VEX document from triage results.

    Args:
        results:         AnalysisResult objects from the pipeline.
        sarif_levels:    Optional dict of cve_id → SARIF level used to determine
                         VEX analysis state. If omitted, all results are marked
                         'under_investigation'.
        findings:        Optional dict of cve_id → ScannerFinding for package context.
        prior_decisions: VexDecision list from a prior run (--vex-in). Entries with
                         state 'not_affected' are written verbatim into the output VEX
                         and are never overridden by fresh triage. This preserves team
                         annotations across runs.
    """
    levels = sarif_levels or {}
    pkgs = findings or {}

    # Index prior not_affected decisions — these are carried forward unchanged.
    # Only humans can change a not_affected decision; the tool never overwrites them.
    prior_not_affected: dict[str, VexDecision] = {
        d.cve_id: d
        for d in (prior_decisions or [])
        if d.state == "not_affected"
    }

    vulnerabilities = []
    for result in results:
        cve_id = result.cve_id
        cve = result.cve_record
        vuln_meta: dict = result.metadata.get("vulnrichment", {})

        level = levels.get(cve_id, "note")
        state = _LEVEL_TO_STATE.get(level, "under_investigation")

        detail = _build_detail(result, vuln_meta)

        vuln_entry: dict = {
            "id": cve_id,
            "source": {"url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "name": "NVD"},
            "analysis": {
                "state": state,
                "detail": detail,
            },
        }

        # CVSS rating
        if cve.primary_cvss:
            cvss = cve.primary_cvss
            severity_str = cvss.base_severity.value.lower() if hasattr(cvss.base_severity, "value") else str(cvss.base_severity).lower()
            vuln_entry["ratings"] = [{
                "source": {"name": "NVD"},
                "score": cvss.base_score,
                "severity": severity_str,
                "method": f"CVSSv{cvss.version}",
                "vector": cvss.vector_string,
            }]

        # ATT&CK technique IDs as cwes/references (CycloneDX uses 'cwes' for weakness IDs,
        # and 'references' for external links — we add technique IDs as advisory references)
        technique_ids = [t.technique_id for t in result.attack_mapping.techniques]
        if technique_ids:
            vuln_entry["references"] = [
                {
                    "id": tid,
                    "source": {
                        "name": "MITRE ATT&CK",
                        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
                    },
                }
                for tid in technique_ids
            ]

        # Package context from scanner input
        finding = pkgs.get(cve_id)
        if finding and finding.package:
            purl = _build_purl(finding)
            affects_entry: dict = {"ref": purl}
            if finding.fixed_version:
                affects_entry["versions"] = [
                    {"version": finding.installed_version, "status": "affected"},
                    {"version": finding.fixed_version, "status": "unaffected"},
                ] if finding.installed_version else [
                    {"version": finding.fixed_version, "status": "unaffected"},
                ]
            vuln_entry["affects"] = [affects_entry]

        vulnerabilities.append(vuln_entry)

    # Append prior not_affected entries verbatim — raw preserves all team annotations.
    # Skip any whose CVE ID was also in the fresh triage results (shouldn't happen
    # since they were filtered before triage, but guard for safety).
    triaged_ids = {r.cve_id for r in results}
    for decision in prior_not_affected.values():
        if decision.cve_id not in triaged_ids:
            if decision.raw:
                vulnerabilities.append(decision.raw)
            else:
                logger.warning(
                    "Prior not_affected decision for %s has no raw data — "
                    "dropping from VEX output",
                    decision.cve_id,
                )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": "urn:uuid:cve-intel-vex",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"name": "cve-intel", "version": __version__}],
        },
        "vulnerabilities": vulnerabilities,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_detail(result: AnalysisResult, vuln_meta: dict) -> str:
    """Build a human-readable analysis detail string for the VEX record."""
    parts: list[str] = []

    if vuln_meta.get("in_kev"):
        parts.append(f"CISA KEV-listed (added {vuln_meta['kev_date_added']})")
    if vuln_meta.get("ssvc_exploitation") == "active":
        parts.append("SSVC: actively exploited in the wild")
    elif vuln_meta.get("ssvc_exploitation") == "poc":
        parts.append("SSVC: proof-of-concept exploit public")

    technique_ids = [t.technique_id for t in result.attack_mapping.techniques]
    if technique_ids:
        parts.append(f"ATT&CK: {', '.join(technique_ids[:3])}")

    if not parts:
        parts.append("Assessed by cve-intel deterministic pipeline")

    return ". ".join(parts) + "."


def _build_purl(finding: ScannerFinding) -> str:
    """Build a best-effort pURL from a ScannerFinding."""
    eco = finding.ecosystem or "generic"
    pkg = finding.package or "unknown"
    ver = f"@{finding.installed_version}" if finding.installed_version else ""
    return f"pkg:{eco}/{pkg}{ver}"
