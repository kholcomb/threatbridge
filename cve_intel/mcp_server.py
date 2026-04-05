"""MCP server for cve-intel — exposes CVE intelligence tools to Claude Code.

All tools are deterministic (no Anthropic API calls). Claude Code acts as the
reasoning layer, interpreting the structured data returned by these tools.

The ATT&CK STIX bundle (~80MB) is loaded once at server startup via the
lifespan context and shared across all tool calls.
"""

import logging
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from mcp.server.fastmcp import FastMCP, Context

from cve_intel.fetchers.attack_data import get_attack_data, AttackData
from cve_intel.fetchers.nvd import NVDFetcher, NVDError, NVDNotFoundError, NVDRateLimitError, CVE_ID_PATTERN
from cve_intel.fetchers.sigmahq import fetch_community_rules, compare_with_community
from cve_intel.fetchers.vulnrichment import fetch_vulnrichment, VulnrichmentData
from cve_intel.mappers.cwe_to_attack import map_cwe_to_attack
from cve_intel.mappers.cvss_to_attack import map_cvss_to_attack
from cve_intel.models.cve import CVSSData, CPEMatch

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[dict]:
    """Load ATT&CK STIX data once at startup and share across all tool calls."""
    try:
        attack_data: AttackData = get_attack_data()
    except Exception as exc:
        logger.error("Failed to load ATT&CK data at startup: %s", exc)
        yield {"attack_data": None}
        return
    yield {"attack_data": attack_data}


mcp = FastMCP("cve-intel", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Internal helpers for triage tools
# ---------------------------------------------------------------------------

_PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Rough ecosystem detection from CPE vendor/product patterns
_PYPI_VENDORS = {"python-", "pypa", "pallets", "psf", "python_"}
_NPM_VENDORS = {"npm", "npmjs", "nodejs", "node.js"}


def _parse_cpe_to_package(cpe_matches: list[CPEMatch]) -> list[dict]:
    """Convert CPE match entries into structured package references.

    CPE format: cpe:2.3:{part}:{vendor}:{product}:{version}:...
    part=a (application), o (os), h (hardware)
    """
    seen: set[str] = set()
    result = []

    for cpe in cpe_matches:
        if not cpe.vulnerable:
            continue
        parts = cpe.criteria.split(":")
        if len(parts) < 6:
            continue

        part = parts[2]      # a / o / h
        vendor = parts[3]
        product = parts[4]

        key = f"{vendor}:{product}"
        if key in seen:
            # Merge version range into existing entry if needed
            continue
        seen.add(key)

        # Ecosystem detection
        vendor_lower = vendor.lower()
        if any(vendor_lower.startswith(p) for p in _PYPI_VENDORS):
            ecosystem = "pypi"
        elif vendor_lower in _NPM_VENDORS or "node" in vendor_lower:
            ecosystem = "npm"
        elif "golang" in vendor_lower or "go." in vendor_lower:
            ecosystem = "go"
        elif part == "o":
            ecosystem = "os"
        else:
            ecosystem = "generic"

        # Version range
        range_parts = []
        if cpe.version_start_including:
            range_parts.append(f">= {cpe.version_start_including}")
        if cpe.version_end_excluding:
            range_parts.append(f"< {cpe.version_end_excluding}")
        elif cpe.version_end_including:
            range_parts.append(f"<= {cpe.version_end_including}")

        result.append({
            "ecosystem": ecosystem,
            "vendor": vendor,
            "package": product,
            "vulnerable_range": ", ".join(range_parts) if range_parts else None,
        })

    return result


def _compute_priority_tier(vuln: VulnrichmentData, cvss: CVSSData | None) -> str:
    """Deterministic priority tier based on exploitation evidence and CVSS score."""
    if vuln.available and (vuln.in_kev or vuln.ssvc.exploitation == "active"):
        return "CRITICAL"
    if vuln.available and vuln.ssvc.exploitation == "poc":
        return "HIGH"
    if cvss and cvss.base_score >= 9.0:
        return "HIGH"
    if vuln.available and vuln.ssvc.automatable == "yes" and cvss and cvss.base_score >= 7.0:
        return "HIGH"
    if vuln.available and vuln.ssvc.technical_impact == "total":
        return "MEDIUM"
    if cvss and cvss.base_score >= 7.0:
        return "MEDIUM"
    return "LOW"


def _build_attack_requirements(cvss: CVSSData | None) -> dict:
    """Structured representation of what an attacker needs to exploit this CVE."""
    if not cvss:
        return {"unknown": True}
    return {
        "network_access_required": cvss.attack_vector == "NETWORK",
        "adjacent_network_only": cvss.attack_vector == "ADJACENT_NETWORK",
        "local_access_only": cvss.attack_vector == "LOCAL",
        "physical_access_required": cvss.attack_vector == "PHYSICAL",
        "authentication_required": cvss.privileges_required != "NONE",
        "high_privileges_required": cvss.privileges_required == "HIGH",
        "user_interaction_required": cvss.user_interaction == "REQUIRED",
        "low_attack_complexity": cvss.attack_complexity == "LOW",
    }


def _build_impact_scope(cvss: CVSSData | None) -> dict:
    """Structured representation of what an attacker can achieve on success."""
    if not cvss:
        return {"unknown": True}
    return {
        "confidentiality": cvss.confidentiality_impact or "UNKNOWN",
        "integrity": cvss.integrity_impact or "UNKNOWN",
        "availability": cvss.availability_impact or "UNKNOWN",
        "scope_changed": cvss.scope == "CHANGED",
        "base_score": cvss.base_score,
        "severity": cvss.base_severity.value,
    }


def _build_triage_notes(
    vuln: VulnrichmentData,
    cvss: CVSSData | None,
    techniques: list[dict],
) -> list[str]:
    """Agent-readable notes explaining why this CVE has its priority tier."""
    notes = []

    if vuln.in_kev:
        notes.append(
            f"CISA KEV: confirmed exploited in the wild (added {vuln.kev_date_added})"
        )
    if vuln.ssvc.exploitation == "active":
        notes.append("SSVC exploitation=active: weaponized exploits are known to exist")
    elif vuln.ssvc.exploitation == "poc":
        notes.append("SSVC exploitation=poc: proof-of-concept code is public")
    if vuln.ssvc.automatable == "yes":
        notes.append("SSVC automatable=yes: can be exploited at scale without human interaction")
    if vuln.ssvc.technical_impact == "total":
        notes.append("SSVC technical_impact=total: full system compromise is possible")

    if cvss:
        if cvss.attack_vector == "NETWORK" and cvss.privileges_required == "NONE":
            notes.append(
                "Unauthenticated network exploit — external exposure alone is sufficient"
            )
        elif cvss.attack_vector == "NETWORK" and cvss.privileges_required in ("LOW", "HIGH"):
            notes.append("Network exploit but requires authentication")
        elif cvss.attack_vector == "LOCAL":
            notes.append("Local access required — not directly exploitable from the network")
        if cvss.scope == "CHANGED":
            notes.append(
                "Scope change: exploitation can impact resources outside the vulnerable component"
            )
        if cvss.user_interaction == "REQUIRED":
            notes.append("User interaction required — social engineering or similar needed")

    tactic_names = {
        tac["shortname"]
        for t in techniques
        for tac in t.get("tactics", [])
    }
    if "initial-access" in tactic_names:
        notes.append(
            "ATT&CK: Initial Access tactic — applicable only to externally exposed services"
        )
    if "lateral-movement" in tactic_names:
        notes.append(
            "ATT&CK: Lateral Movement tactic — applicable post-compromise or from inside the network"
        )

    return notes


def _build_triage_result(cve_id: str, attack_data: AttackData) -> dict:
    """Core triage logic shared by triage_cve and batch_triage_cves."""
    record = NVDFetcher().fetch(cve_id)
    vuln = fetch_vulnrichment(cve_id)
    cvss = record.primary_cvss

    mapping = map_cwe_to_attack(cve_id, record.weaknesses, attack_data)
    if cvss:
        extra = map_cvss_to_attack(
            cve_id, cvss, attack_data, set(mapping.technique_ids)
        )
        if extra:
            mapping = mapping.model_copy(
                update={"techniques": mapping.techniques + extra,
                        "mapping_method": "cwe_static+cvss_heuristic"}
            )

    top_techniques = sorted(
        mapping.techniques, key=lambda t: t.confidence, reverse=True
    )[:5]
    techniques_out = [t.model_dump(mode="json") for t in top_techniques]

    priority = _compute_priority_tier(vuln, cvss)

    return {
        "cve_id": cve_id,
        "priority_tier": priority,
        "exploitation": {
            "available": vuln.available,
            "in_kev": vuln.in_kev,
            "kev_date_added": vuln.kev_date_added,
            "ssvc_exploitation": vuln.ssvc.exploitation,
            "ssvc_automatable": vuln.ssvc.automatable,
            "ssvc_technical_impact": vuln.ssvc.technical_impact,
            "is_actively_exploited": vuln.is_actively_exploited,
        },
        "attack_requirements": _build_attack_requirements(cvss),
        "impact_scope": _build_impact_scope(cvss),
        "affected_packages": _parse_cpe_to_package(record.cpe_matches),
        "techniques": techniques_out,
        "triage_notes": _build_triage_notes(vuln, cvss, techniques_out),
        "description": record.description_en[:500] if record.description_en else "",
    }


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

@mcp.tool()
def fetch_cve(cve_id: str, ctx: Context) -> dict:
    """Fetch a CVE record from the NVD (National Vulnerability Database).

    Returns the full CVE record including English description, CVSS score and
    vector, CWE weakness IDs, affected CPE products, and reference URLs.

    Use this when you need the raw CVE data for a specific CVE ID.
    """
    if not CVE_ID_PATTERN.match(cve_id.strip().upper()):
        return {"error": f"Invalid CVE ID format: {cve_id!r}. Expected format: CVE-YYYY-NNNNN"}
    record = NVDFetcher().fetch(cve_id)
    return record.model_dump(mode="json")


@mcp.tool()
def get_attack_techniques(cve_id: str, ctx: Context) -> dict:
    """Map a CVE to MITRE ATT&CK techniques using CWE weakness types and CVSS heuristics.

    Returns an AttackMapping with technique IDs, names, associated tactics,
    platform coverage, confidence scores (0.0–1.0), and rationale.

    Mapping is deterministic: CWE IDs are looked up in a static map, and CVSS
    vector attributes add low-confidence technique hints.

    For triage, use tactic context to assess architecture fit:
    - Initial Access (TA0001): requires external network exposure
    - Lateral Movement (TA0008): requires attacker already inside the network
    - Privilege Escalation (TA0004): requires attacker already has some access
    - Impact (TA0040): describes what happens after successful exploitation
    """
    attack_data: AttackData = ctx.request_context.lifespan_context["attack_data"]
    if attack_data is None:
        return {"error": "ATT&CK data unavailable — server failed to load bundle at startup"}
    record = NVDFetcher().fetch(cve_id)

    mapping = map_cwe_to_attack(cve_id, record.weaknesses, attack_data)

    if record.primary_cvss:
        extra = map_cvss_to_attack(
            cve_id, record.primary_cvss, attack_data, set(mapping.technique_ids)
        )
        if extra:
            mapping = mapping.model_copy(
                update={"techniques": mapping.techniques + extra,
                        "mapping_method": "cwe_static+cvss_heuristic"}
            )

    return mapping.model_dump(mode="json")


@mcp.tool()
def lookup_technique(technique_id: str, ctx: Context) -> dict:
    """Look up a specific MITRE ATT&CK technique by ID.

    Returns the full technique record: description, associated tactics,
    targeted platforms, data sources, detection notes, and the ATT&CK URL.

    Accepts both technique IDs (T1190) and sub-technique IDs (T1059.001).
    Case-insensitive.
    """
    attack_data: AttackData = ctx.request_context.lifespan_context["attack_data"]
    if attack_data is None:
        return {"error": "ATT&CK data unavailable — server failed to load bundle at startup"}
    tech = attack_data.get_technique(technique_id.upper())
    if tech is None:
        raise ValueError(
            f"Technique '{technique_id}' not found in ATT&CK dataset. "
            f"Check the ID format (e.g. T1190 or T1059.001)."
        )
    return tech.model_dump(mode="json")


@mcp.tool()
def search_techniques(query: str, ctx: Context) -> list[dict]:
    """Search MITRE ATT&CK techniques by name or keyword.

    Returns up to 10 matching techniques with their IDs, names, descriptions,
    and tactic associations. Searches both technique names and descriptions.

    Useful for finding relevant techniques when you know the attack concept
    but not the specific technique ID.
    """
    attack_data: AttackData = ctx.request_context.lifespan_context["attack_data"]
    if attack_data is None:
        return {"error": "ATT&CK data unavailable — server failed to load bundle at startup"}
    q = query.lower()

    matches = []
    for tid in attack_data.all_technique_ids:
        tech = attack_data.get_technique(tid)
        if tech and (q in tech.name.lower() or q in tech.description.lower()):
            matches.append(tech)
        if len(matches) >= 10:
            break

    return [t.model_dump(mode="json") for t in matches]


@mcp.tool()
def get_cve_summary(cve_id: str, ctx: Context) -> dict:
    """Fetch CVE details and ATT&CK technique mapping in a single call.

    Returns a combined dict with:
    - cve: full CVERecord (description, CVSS, CWEs, CPEs, references)
    - attack_mapping: deterministic technique mapping with confidence scores

    For triage workflows, prefer triage_cve — it combines this data with
    exploitation context and produces a structured priority assessment.
    """
    attack_data: AttackData = ctx.request_context.lifespan_context["attack_data"]
    if attack_data is None:
        return {"error": "ATT&CK data unavailable — server failed to load bundle at startup"}
    record = NVDFetcher().fetch(cve_id)

    mapping = map_cwe_to_attack(cve_id, record.weaknesses, attack_data)

    if record.primary_cvss:
        extra = map_cvss_to_attack(
            cve_id, record.primary_cvss, attack_data, set(mapping.technique_ids)
        )
        if extra:
            mapping = mapping.model_copy(
                update={"techniques": mapping.techniques + extra,
                        "mapping_method": "cwe_static+cvss_heuristic"}
            )

    return {
        "cve": record.model_dump(mode="json"),
        "attack_mapping": mapping.model_dump(mode="json"),
    }


@mcp.tool()
def get_exploitation_context(cve_id: str, ctx: Context) -> dict:
    """Fetch CISA Vulnrichment exploitation context for a CVE.

    Returns KEV (Known Exploited Vulnerabilities) status and SSVC scores:
    - in_kev: whether CISA has added this to the KEV catalog
    - kev_date_added: date first added to KEV
    - ssvc_exploitation: "active", "poc", or "none"
    - ssvc_automatable: "yes" or "no"
    - ssvc_technical_impact: "total" or "partial"
    - is_actively_exploited: true if KEV or SSVC exploitation=active
    - suggested_severity: "critical"/"high" if exploitation context warrants it, else null

    Returns available=false if no Vulnrichment entry exists for this CVE.
    """
    data = fetch_vulnrichment(cve_id)
    return {
        "cve_id": data.cve_id,
        "available": data.available,
        "in_kev": data.in_kev,
        "kev_date_added": data.kev_date_added,
        "ssvc_exploitation": data.ssvc.exploitation,
        "ssvc_automatable": data.ssvc.automatable,
        "ssvc_technical_impact": data.ssvc.technical_impact,
        "is_actively_exploited": data.is_actively_exploited,
        "suggested_severity": data.suggested_severity_boost(),
    }


@mcp.tool()
def triage_cve(cve_id: str, ctx: Context) -> dict:
    """Triage a CVE from a dependency scanner finding.

    Returns a structured priority assessment combining all available signals:

    - priority_tier: CRITICAL / HIGH / MEDIUM / LOW
      CRITICAL = actively exploited in the wild (KEV or SSVC exploitation=active)
      HIGH     = PoC exploit exists, or CVSS >= 9.0
      MEDIUM   = CVSS >= 7.0, or total technical impact
      LOW      = everything else

    - exploitation: KEV status + SSVC scores (exploitation level, automatability, impact)
    - attack_requirements: what an attacker needs (network access, auth, user interaction)
    - impact_scope: what they can achieve (C/I/A impacts, scope change, base score)
    - affected_packages: CPE data parsed into structured package references with version ranges
    - techniques: top ATT&CK techniques mapped from CWEs and CVSS vector
    - triage_notes: plain-language reasoning about priority and architecture fit

    Use attack_requirements + triage_notes to cross-reference against deployment architecture:
    - network_access_required=true: only applicable if service is internet-exposed
    - authentication_required=true: attacker needs valid credentials first
    - ATT&CK Initial Access tactic: requires external exposure
    - ATT&CK Lateral Movement tactic: requires attacker already inside the network
    """
    if not CVE_ID_PATTERN.match(cve_id.strip().upper()):
        return {"error": f"Invalid CVE ID format: {cve_id!r}. Expected format: CVE-YYYY-NNNNN"}
    attack_data: AttackData = ctx.request_context.lifespan_context["attack_data"]
    if attack_data is None:
        return {"error": "ATT&CK data unavailable — server failed to load bundle at startup"}
    return _build_triage_result(cve_id, attack_data)


@mcp.tool()
def batch_triage_cves(cve_ids: list[str], ctx: Context) -> dict:
    """Triage multiple CVEs from scanner output in a single call.

    Accepts a list of CVE IDs (e.g. from Snyk, Trivy, Grype, Dependabot output)
    and returns all triage assessments sorted by priority: CRITICAL → HIGH → MEDIUM → LOW.

    CVEs that fail NVD lookup (not found, rate limited) are returned in a separate
    'failed' list so the agent can handle them gracefully.

    Returns:
    - results: list of triage assessments, sorted by priority_tier
    - failed: list of {cve_id, error} for any CVEs that could not be assessed
    - summary: counts per priority tier for quick overview
    """
    attack_data: AttackData = ctx.request_context.lifespan_context["attack_data"]
    if attack_data is None:
        return {"error": "ATT&CK data unavailable — server failed to load bundle at startup"}

    results = []
    failed = []

    for cve_id in cve_ids:
        if not CVE_ID_PATTERN.match(cve_id.strip().upper()):
            failed.append({
                "cve_id": cve_id,
                "error": f"Invalid CVE ID format: {cve_id!r}. Expected format: CVE-YYYY-NNNNN",
                "error_type": "invalid_id",
            })
            continue
        try:
            results.append(_build_triage_result(cve_id, attack_data))
        except NVDNotFoundError as exc:
            failed.append({"cve_id": cve_id, "error": str(exc), "error_type": "not_found"})
        except NVDRateLimitError as exc:
            failed.append({"cve_id": cve_id, "error": str(exc), "error_type": "rate_limited"})
        except NVDError as exc:
            failed.append({"cve_id": cve_id, "error": str(exc), "error_type": "unexpected"})
        except Exception as exc:
            failed.append({"cve_id": cve_id, "error": f"Unexpected error: {exc}", "error_type": "unexpected"})

    results.sort(key=lambda r: _PRIORITY_ORDER.get(r["priority_tier"], 99))

    summary: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        tier = r["priority_tier"]
        summary[tier] = summary.get(tier, 0) + 1

    return {
        "results": results,
        "failed": failed,
        "summary": summary,
    }


@mcp.tool()
def get_community_sigma_rules(cve_id: str, ctx: Context) -> dict:
    """Fetch community Sigma rules for a CVE from the SigmaHQ/sigma repository.

    Returns rules from rules-emerging-threats/{YEAR}/Exploits/{CVE_ID}/ if they exist.
    Includes rule text, logsource details, and ATT&CK tags from the community rules.

    Use the result to:
    - Validate that your generated rule uses the correct logsource
    - Check ATT&CK tag alignment against community consensus
    - Compare detection logic against a vetted baseline
    - Identify coverage gaps (e.g., community has 3 rules, you generated 1)

    Returns found=false if no community rule exists for this CVE.
    """
    result = fetch_community_rules(cve_id)
    return result.summary()


@mcp.tool()
def compare_sigma_rule_with_community(
    cve_id: str, generated_rule_text: str, ctx: Context
) -> dict:
    """Compare a generated Sigma rule against SigmaHQ community rules.

    Fetches community rules for the CVE and returns a structured comparison:
    - logsource_match: whether category/product matches community
    - shared/missing/extra ATT&CK tags
    - level (severity) alignment

    Use this after generating a rule to identify quality gaps before deployment.
    Returns community_available=false if no community rules exist.
    """
    community = fetch_community_rules(cve_id)
    return compare_with_community(generated_rule_text, community)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
