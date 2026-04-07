"""MCP server for cve-intel — exposes CVE intelligence tools to Claude Code.

All tools are deterministic (no Anthropic API calls). Claude Code acts as the
reasoning layer, interpreting the structured data returned by these tools.

The ATT&CK STIX bundle (~80MB) is loaded once at server startup via the
lifespan context and shared across all tool calls.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from pathlib import Path

from mcp.server.fastmcp import FastMCP, Context

from cve_intel.fetchers.attack_data import get_attack_data, AttackData
from cve_intel.fetchers.nvd import NVDError, NVDNotFoundError, NVDRateLimitError, CVE_ID_PATTERN
from cve_intel.fetchers.osv import OSVNotFoundError
from cve_intel.fetchers.resolver import fetch_cve_record
from cve_intel.fetchers.sigmahq import fetch_community_rules, compare_with_community
from cve_intel.fetchers.vulnrichment import fetch_vulnrichment, VulnrichmentData
from cve_intel.mappers.cwe_to_attack import map_cwe_to_attack
from cve_intel.mappers.cvss_signals import extract_signals, rank_techniques, add_structural_techniques
from cve_intel.models.cve import CVSSData, CPEMatch

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[dict]:
    """Load ATT&CK STIX data once at startup and share across all tool calls."""
    from cve_intel.fetchers.attack_data import AttackDataError
    try:
        attack_data: AttackData = get_attack_data()
    except AttackDataError as exc:
        # Network or filesystem failure — log clearly and start degraded so
        # operators can still use non-ATT&CK tools (fetch_cve, triage, etc.).
        logger.error(
            "ATT&CK bundle unavailable at startup (%s: %s). "
            "ATT&CK-dependent tools will return errors until the server is restarted.",
            type(exc).__name__, exc,
        )
        yield {"attack_data": None}
        return
    except Exception as exc:
        # Unexpected error (e.g. corrupt JSON, permission denied on cache dir).
        # Re-raise so the process exits with a clear traceback rather than
        # silently serving broken results.
        logger.critical(
            "Unexpected error loading ATT&CK data (%s: %s) — aborting startup.",
            type(exc).__name__, exc,
        )
        raise
    yield {"attack_data": attack_data}


_INSTRUCTIONS = """\
CVE threat intelligence server. All tools are deterministic — no AI calls inside
the server. You (the agent) provide the reasoning layer on top of the structured
data these tools return.

## Tool groups

- **Raw data**: fetch_cve, get_exploitation_context
- **ATT&CK mapping**: get_attack_techniques, get_cve_summary, lookup_technique, search_techniques, get_related_techniques
- **Triage**: triage_cve, batch_triage_cves
- **Detection**: get_community_sigma_rules, compare_sigma_rule_with_community

## Avoid redundant calls

triage_cve and batch_triage_cves already include full KEV and SSVC data in their
`exploitation` field. Do NOT call get_exploitation_context after triage_cve —
it fetches the same data a second time and returns nothing new.

get_exploitation_context is only useful when you need raw Vulnrichment data
WITHOUT running a full triage (e.g. a quick KEV check with no ATT&CK mapping).

## Primary workflows

**1. Scanner triage** (e.g. Snyk / Trivy / Grype output)
   batch_triage_cves → cross-reference attack_requirements against deployment
   architecture → recommend patches.
   The triage result contains everything needed — do not follow up with
   get_exploitation_context for each CVE.

**2. Single CVE investigation**
   triage_cve → lookup_technique per mapped technique →
   get_related_techniques to expand threat model →
   get_community_sigma_rules → synthesise risk narrative.
   The exploitation field in the triage result already contains KEV/SSVC data.

**3. Detection coverage assessment**
   get_attack_techniques → get_community_sigma_rules →
   lookup_technique (data_sources + detection_notes per technique) → identify gaps.

## Interpreting results

Priority tiers:
  CRITICAL = KEV-listed or SSVC exploitation=active (patch now)
  HIGH     = PoC exists, CVSS ≥ 9.0, or unauthenticated network vector ≥ 7.0
  MEDIUM   = CVSS ≥ 7.0 or total technical impact
  LOW      = everything else

ATT&CK tactic context (use to qualify risk against deployment):
  Initial Access (TA0001)      → only relevant if the service is internet-exposed
  Lateral Movement (TA0008)   → only relevant if an attacker is already inside the network
  Privilege Escalation (TA0004) → only relevant if attacker already has some access
  Impact (TA0040)              → describes what happens after successful exploitation

attack_requirements fields:
  network_access_required=true  → irrelevant if the service is not externally reachable
  authentication_required=true  → attacker needs valid credentials first
  user_interaction_required=true → social engineering or phishing required

Use the `investigate_cve` prompt for a guided single-CVE workflow.
Use the `triage_scanner_output` prompt for batch scanner triage.
Use the `assess_detection_coverage` prompt for detection engineering.
"""

mcp = FastMCP("cve-intel", lifespan=lifespan, instructions=_INSTRUCTIONS)


# ---------------------------------------------------------------------------
# Internal helpers for triage tools
# ---------------------------------------------------------------------------

_PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Rough ecosystem detection from CPE vendor/product patterns
_PYPI_VENDORS = {"python-", "pypa", "pallets", "psf", "python_"}
_NPM_VENDORS = {"npm", "npmjs", "nodejs", "node.js"}


def _parse_cpe_to_package(cpe_matches: list[CPEMatch]) -> list[dict[str, Any]]:
    """Convert CPE match entries into structured package references.

    CPE format: cpe:2.3:{part}:{vendor}:{product}:{version}:...
    part=a (application), o (os), h (hardware)

    Multiple CPE entries for the same vendor:product (e.g. separate version
    ranges) are merged into a single entry with a ``version_ranges`` list so
    that no range information is lost.
    """
    # Ordered dict keyed by "vendor:product" — preserves insertion order and
    # allows in-place mutation for range merging.
    index: dict[str, dict[str, Any]] = {}

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

        # Build the version range dict for this CPE entry (only non-empty keys).
        range_dict: dict[str, str] = {}
        if cpe.version_start_including:
            range_dict["start_including"] = cpe.version_start_including
        if cpe.version_end_excluding:
            range_dict["end_excluding"] = cpe.version_end_excluding
        if cpe.version_end_including:
            range_dict["end_including"] = cpe.version_end_including

        if key in index:
            # Merge: append this range to the existing entry's list.
            if range_dict:
                index[key]["version_ranges"].append(range_dict)
        else:
            # First time we see this vendor:product — create the entry.
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

            index[key] = {
                "ecosystem": ecosystem,
                "vendor": vendor,
                "package": product,
                "version_ranges": [range_dict] if range_dict else [],
            }

    return list(index.values())


def _compute_priority_tier(vuln: VulnrichmentData, cvss: CVSSData | None) -> str:
    """Deterministic priority tier based on exploitation evidence and CVSS score."""
    if vuln.available and (vuln.in_kev or vuln.ssvc.exploitation == "active"):
        return "CRITICAL"
    if vuln.available and vuln.ssvc.exploitation == "poc":
        return "HIGH"
    if cvss and cvss.base_score >= 9.0:
        return "HIGH"
    # Network-reachable with no auth and CVSS >= 7.0 warrants HIGH even without Vulnrichment
    if cvss and cvss.base_score >= 7.0 and cvss.attack_vector == "NETWORK" and cvss.privileges_required == "NONE":
        return "HIGH"
    if vuln.available and vuln.ssvc.automatable == "yes" and cvss and cvss.base_score >= 7.0:
        return "HIGH"
    if vuln.available and vuln.ssvc.technical_impact == "total":
        return "MEDIUM"
    if cvss and cvss.base_score >= 7.0:
        return "MEDIUM"
    return "LOW"


def _build_attack_requirements(cvss: CVSSData | None) -> dict[str, Any]:
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


def _build_impact_scope(cvss: CVSSData | None) -> dict[str, Any]:
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
    techniques: list[dict[str, Any]],
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


def _build_triage_result(cve_id: str, attack_data: AttackData) -> dict[str, Any]:
    """Core triage logic shared by triage_cve and batch_triage_cves."""
    record = fetch_cve_record(cve_id)
    vuln = fetch_vulnrichment(cve_id)
    cvss = record.primary_cvss

    mapping = map_cwe_to_attack(cve_id, record.weaknesses, attack_data)
    if cvss:
        extra = add_structural_techniques(cve_id, cvss, attack_data, set(mapping.technique_ids))
        if extra:
            mapping = mapping.model_copy(update={"techniques": mapping.techniques + extra})

    signals = extract_signals(cvss) if cvss else None
    top_techniques = rank_techniques(mapping.techniques, signals)[:5]
    techniques_out = [t.model_dump(mode="json") for t in top_techniques]

    priority = _compute_priority_tier(vuln, cvss)
    triage_notes = _build_triage_notes(vuln, cvss, techniques_out)

    if mapping.unmapped_cwes:
        triage_notes.append(
            f"ATT&CK mapping incomplete: {', '.join(mapping.unmapped_cwes)} not in static map — "
            "technique list may be partial; run cve-intel analyze with enrichment for full coverage"
        )
    if not techniques_out:
        if not record.weaknesses:
            triage_notes.append(
                "No ATT&CK mapping: no CWE data available for this CVE"
            )

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
        "triage_notes": triage_notes,
        "description": record.description_en[:500] if record.description_en else "",
    }


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

@mcp.tool()
def fetch_cve(cve_id: str, ctx: Context) -> dict[str, Any]:
    """Fetch a CVE record from the NVD (National Vulnerability Database).

    Returns the full CVE record including English description, CVSS score and
    vector, CWE weakness IDs, affected CPE products, and reference URLs.

    Use this when you need the raw CVE data for a specific CVE ID.
    """
    if not CVE_ID_PATTERN.match(cve_id.strip().upper()):
        return {"error": f"Invalid CVE ID format: {cve_id!r}. Expected format: CVE-YYYY-NNNNN"}
    record = fetch_cve_record(cve_id)
    return record.model_dump(mode="json")


@mcp.tool()
def get_attack_techniques(cve_id: str, ctx: Context) -> dict[str, Any]:
    """Map a CVE to MITRE ATT&CK techniques using CWE weakness types and CVSS heuristics.

    Returns an AttackMapping with technique IDs, names, associated tactics,
    platform coverage, mapping_source, and rationale.

    Mapping is deterministic: CWE IDs are looked up in a static map; CVSS
    vector attributes add structurally-implied techniques when no CWE match exists.

    For triage, use tactic context to assess architecture fit:
    - Initial Access (TA0001): requires external network exposure
    - Lateral Movement (TA0008): requires attacker already inside the network
    - Privilege Escalation (TA0004): requires attacker already has some access
    - Impact (TA0040): describes what happens after successful exploitation
    """
    attack_data: AttackData = ctx.request_context.lifespan_context["attack_data"]
    if attack_data is None:
        return {"error": "ATT&CK data unavailable — server failed to load bundle at startup"}
    record = fetch_cve_record(cve_id)

    mapping = map_cwe_to_attack(cve_id, record.weaknesses, attack_data)
    if record.primary_cvss:
        extra = add_structural_techniques(cve_id, record.primary_cvss, attack_data, set(mapping.technique_ids))
        if extra:
            mapping = mapping.model_copy(update={"techniques": mapping.techniques + extra})
    return mapping.model_dump(mode="json")


@mcp.tool()
def lookup_technique(technique_id: str, ctx: Context) -> dict[str, Any]:
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
        return {
            "error": (
                f"Technique '{technique_id}' not found in ATT&CK dataset. "
                f"Check the ID format (e.g. T1190 or T1059.001)."
            )
        }
    return tech.model_dump(mode="json")


@mcp.tool()
def search_techniques(
    query: str,
    ctx: Context,
    tactic: str = "",
    platform: str = "",
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Search MITRE ATT&CK techniques by name or keyword.

    Returns up to `limit` (default 10, max 25) techniques ranked by relevance:
    name matches score higher than tactic-name matches, which score higher than
    description matches. Results from the same parent technique are grouped.

    Optional filters:
    - tactic: ATT&CK tactic shortname to restrict results, e.g. "initial-access",
      "lateral-movement", "privilege-escalation", "defense-evasion", "execution"
    - platform: restrict to techniques targeting a specific platform, e.g.
      "Windows", "Linux", "macOS", "Containers", "Network Devices"

    Each result includes a `relevance_score` (higher = better match) so you
    can judge result quality. Descriptions are trimmed to 200 characters.

    Useful for finding relevant techniques when you know the attack concept
    but not the specific technique ID.
    """
    attack_data: AttackData = ctx.request_context.lifespan_context["attack_data"]
    if attack_data is None:
        return [{"error": "ATT&CK data unavailable — server failed to load bundle at startup"}]

    limit = min(max(1, limit), 25)
    tokens = [t for t in query.lower().split() if t]
    tactic_filter = tactic.lower().strip()
    platform_filter = platform.lower().strip()

    scored: list[tuple[int, Any]] = []

    for tid in attack_data.all_technique_ids:
        tech = attack_data.get_technique(tid)
        if not tech:
            continue

        # Tactic filter
        if tactic_filter:
            tactic_shortnames = [tac.shortname for tac in tech.tactics]
            if tactic_filter not in tactic_shortnames:
                continue

        # Platform filter
        if platform_filter:
            if not any(platform_filter in p.lower() for p in tech.platforms):
                continue

        # Relevance scoring
        name_lower = tech.name.lower()
        desc_lower = tech.description.lower()
        tactic_names_lower = " ".join(tac.name.lower() for tac in tech.tactics)

        score = 0
        for token in tokens:
            if token in name_lower:
                score += 10          # name match: highest weight
            if token in tactic_names_lower:
                score += 4           # tactic name match: medium weight
            if token in desc_lower:
                score += 1           # description match: lowest weight

        if score == 0:
            continue

        scored.append((score, tech))

    # Sort by score descending, stable secondary sort by technique ID
    scored.sort(key=lambda x: (-x[0], x[1].technique_id))

    out = []
    for score, tech in scored[:limit]:
        d = tech.model_dump(mode="json")
        d["description"] = d["description"][:200] + ("…" if len(d["description"]) > 200 else "")
        d["relevance_score"] = score
        out.append(d)

    return out


@mcp.tool()
def get_related_techniques(technique_id: str, ctx: Context) -> dict[str, Any]:
    """Find MITRE ATT&CK techniques related to a given technique ID.

    Returns three relationship groups, each useful for a different purpose:

    - siblings: other sub-techniques of the same parent (e.g. all T1059.xxx when
      given T1059.001). Directly adjacent — same parent tactic and detection surface.

    - same_tactic_and_platform: techniques sharing both a tactic AND at least one
      platform with the input technique. Useful for "what else could an attacker do
      at this stage on this OS?"

    - shared_data_sources: techniques with overlapping data sources. Useful for
      detection engineering — if you already have a log source covering the input
      technique, these are candidates you could detect with the same pipeline.

    Each result includes a `relevance_score` and descriptions trimmed to 200 chars.

    Typical use: after triage_cve returns technique IDs, call this to expand the
    threat model beyond the directly mapped techniques.
    """
    attack_data: AttackData = ctx.request_context.lifespan_context["attack_data"]
    if attack_data is None:
        return {"error": "ATT&CK data unavailable — server failed to load bundle at startup"}

    tid = technique_id.strip().upper()
    anchor = attack_data.get_technique(tid)
    if anchor is None:
        return {"error": f"Technique '{technique_id}' not found. Check the ID format (e.g. T1190 or T1059.001)."}

    anchor_tactic_ids = {tac.tactic_id for tac in anchor.tactics}
    anchor_platforms = {p.lower() for p in anchor.platforms}
    anchor_data_sources = set(anchor.data_sources)

    siblings: list[dict] = []
    same_tactic_platform: list[dict] = []
    shared_data_sources: list[dict] = []

    for other_id in attack_data.all_technique_ids:
        if other_id == tid:
            continue
        other = attack_data.get_technique(other_id)
        if not other:
            continue

        other_tactic_ids = {tac.tactic_id for tac in other.tactics}
        other_platforms = {p.lower() for p in other.platforms}
        other_data_sources = set(other.data_sources)

        # Group 1: siblings — share the same parent technique
        if anchor.is_subtechnique and other.is_subtechnique and anchor.parent_id == other.parent_id:
            d = _technique_summary(other)
            d["relevance_score"] = 10
            siblings.append(d)
            continue

        # Also treat the parent itself as a sibling if we're a sub-technique
        if anchor.is_subtechnique and not other.is_subtechnique and other_id == anchor.parent_id:
            d = _technique_summary(other)
            d["relevance_score"] = 8
            siblings.append(d)
            continue

        # Group 2: same tactic AND at least one platform overlap
        shared_tactics = anchor_tactic_ids & other_tactic_ids
        shared_platforms = anchor_platforms & other_platforms
        if shared_tactics and shared_platforms:
            score = len(shared_tactics) * 3 + len(shared_platforms)
            d = _technique_summary(other)
            d["relevance_score"] = score
            d["shared_tactics"] = [t for t in other.tactics if t.tactic_id in shared_tactics]
            same_tactic_platform.append(d)

        # Group 3: shared data sources (detection overlap)
        shared_ds = anchor_data_sources & other_data_sources
        if len(shared_ds) >= 2:
            d = _technique_summary(other)
            d["relevance_score"] = len(shared_ds)
            d["shared_data_sources"] = sorted(shared_ds)
            shared_data_sources.append(d)

    # Sort each group by relevance descending
    siblings.sort(key=lambda x: -x["relevance_score"])
    same_tactic_platform.sort(key=lambda x: -x["relevance_score"])
    shared_data_sources.sort(key=lambda x: -x["relevance_score"])

    return {
        "anchor": _technique_summary(anchor),
        "siblings": siblings[:10],
        "same_tactic_and_platform": same_tactic_platform[:10],
        "shared_data_sources": shared_data_sources[:10],
    }


def _technique_summary(tech: Any) -> dict[str, Any]:
    """Compact technique dict for relationship results."""
    return {
        "technique_id": tech.technique_id,
        "name": tech.name,
        "description": tech.description[:200] + ("…" if len(tech.description) > 200 else ""),
        "tactics": [t.model_dump(mode="json") for t in tech.tactics],
        "platforms": tech.platforms,
        "data_sources": tech.data_sources,
        "url": tech.url,
    }


@mcp.tool()
def get_cve_summary(cve_id: str, ctx: Context) -> dict[str, Any]:
    """Fetch CVE details and ATT&CK technique mapping in a single call.

    Returns a combined dict with:
    - cve: full CVERecord (description, CVSS, CWEs, CPEs, references)
    - attack_mapping: deterministic technique mapping with mapping_source per technique

    For triage workflows, prefer triage_cve — it combines this data with
    exploitation context and produces a structured priority assessment.
    """
    attack_data: AttackData = ctx.request_context.lifespan_context["attack_data"]
    if attack_data is None:
        return {"error": "ATT&CK data unavailable — server failed to load bundle at startup"}
    record = fetch_cve_record(cve_id)

    mapping = map_cwe_to_attack(cve_id, record.weaknesses, attack_data)
    if record.primary_cvss:
        extra = add_structural_techniques(cve_id, record.primary_cvss, attack_data, set(mapping.technique_ids))
        if extra:
            mapping = mapping.model_copy(update={"techniques": mapping.techniques + extra})
    return {
        "cve": record.model_dump(mode="json"),
        "attack_mapping": mapping.model_dump(mode="json"),
    }


@mcp.tool()
def get_exploitation_context(cve_id: str, ctx: Context) -> dict[str, Any]:
    """Fetch CISA Vulnrichment exploitation context for a CVE.

    NOTE: If you have already called triage_cve or batch_triage_cves, do NOT
    call this tool — the exploitation field in those results already contains
    all KEV and SSVC data. This tool exists for lightweight KEV/SSVC lookups
    when a full triage is not needed.

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
def triage_cve(cve_id: str, ctx: Context) -> dict[str, Any]:
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
def batch_triage_cves(cve_ids: list[str], ctx: Context) -> dict[str, Any]:
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
        except (NVDNotFoundError, OSVNotFoundError) as exc:
            failed.append({"cve_id": cve_id, "error": str(exc), "error_type": "not_found"})
        except NVDRateLimitError as exc:
            failed.append({"cve_id": cve_id, "error": str(exc), "error_type": "rate_limited"})
        except NVDError as exc:
            failed.append({"cve_id": cve_id, "error": str(exc), "error_type": "unexpected"})
        except Exception as exc:
            logger.exception("Unexpected error triaging %s", cve_id)
            failed.append({"cve_id": cve_id, "error": f"Unexpected error: {exc}", "error_type": "unexpected"})

    results.sort(key=lambda r: _PRIORITY_ORDER.get(r["priority_tier"], 99))

    summary: dict[str, Any] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        tier = r["priority_tier"]
        summary[tier] = summary.get(tier, 0) + 1
    summary["failed_count"] = len(failed)

    triage_notes: list[str] = []
    if failed:
        triage_notes.append(
            f"{len(failed)} CVE(s) could not be assessed — review the failed list for manual triage."
        )

    return {
        "results": results,
        "failed": failed,
        "summary": summary,
        "triage_notes": triage_notes,
    }


@mcp.tool()
def get_community_sigma_rules(
    cve_id: str,
    ctx: Context,
    technique_ids: list[str] = [],
) -> dict[str, Any]:
    """Fetch community Sigma rules for a CVE from the SigmaHQ/sigma repository.

    First checks rules-emerging-threats/{YEAR}/Exploits/{CVE_ID}/ for a
    CVE-specific rule.  If none is found and technique_ids are provided,
    falls back to searching SigmaHQ for rules tagged with those ATT&CK
    technique IDs (e.g. attack.t1190).

    Pass technique_ids from a prior triage_cve or get_attack_techniques call
    to enable the fallback — most CVEs lack a dedicated emerging-threats rule
    but will have relevant technique-level rules.

    Use the result to:
    - Validate that your generated rule uses the correct logsource
    - Check ATT&CK tag alignment against community consensus
    - Compare detection logic against a vetted baseline
    - Identify coverage gaps (e.g., community has 3 rules, you generated 1)

    Returns found=false if no rules exist at either the CVE or technique level.
    Check fallback_technique_ids in the result to see whether technique-level
    rules were returned (non-empty) or CVE-specific rules were found (empty).
    """
    result = fetch_community_rules(cve_id, technique_ids=technique_ids or None)
    return result.summary()


@mcp.tool()
def compare_sigma_rule_with_community(
    cve_id: str, generated_rule_text: str, ctx: Context
) -> dict[str, Any]:
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


# ---------------------------------------------------------------------------
# MCP Resources — reference data and workflow documentation
# ---------------------------------------------------------------------------

@mcp.resource("ref://workflows")
def workflow_guide() -> str:
    """Detailed workflow guide for using the cve-intel tools effectively."""
    return """\
# CVE-Intel Workflow Guide

## Workflow 1: Scanner Triage

Use when you have a list of CVE IDs from a dependency scanner (Snyk, Trivy,
Grype, Dependabot) and need to prioritise remediation.

Steps:
1. Call `batch_triage_cves(cve_ids=[...])` with the full list.
   - Results are pre-sorted CRITICAL → HIGH → MEDIUM → LOW.
   - Check `summary` for a count breakdown.
   - Check `failed` for any CVEs that could not be looked up (rate limit,
     not found, invalid ID) and handle them separately.

2. For every CRITICAL or HIGH result, call `get_exploitation_context(cve_id)`
   to confirm KEV status and SSVC scores. This is your strongest signal for
   "patch tonight vs patch this sprint".

3. For each result, read `attack_requirements` and cross-reference against the
   deployment:
   - `network_access_required=true` → is this service exposed to the internet
     or an untrusted network? If not, downgrade urgency.
   - `authentication_required=true` → does an attacker need valid credentials?
     Significantly raises the bar.
   - `user_interaction_required=true` → requires phishing or social engineering.

4. Read `triage_notes` — these are pre-computed plain-language observations
   about the CVE's risk posture (e.g. "Unauthenticated network exploit",
   "ATT&CK: Lateral Movement tactic — applicable post-compromise").

5. Summarise findings: group by priority tier, call out any CVEs where
   deployment architecture reduces the effective risk, and produce a
   prioritised patch list.

---

## Workflow 2: Single CVE Investigation

Use when you need a full risk assessment for one CVE (e.g. a reported
vulnerability in a critical dependency).

Steps:
1. Call `triage_cve(cve_id)` for the complete structured assessment including
   priority tier, exploitation signals, attack requirements, and ATT&CK mapping.

2. Call `get_exploitation_context(cve_id)` for CISA Vulnrichment detail.
   Even if `triage_cve` already includes this data, check `kev_date_added`
   to understand how long it has been actively exploited.

3. For each technique in the `techniques` list, call `lookup_technique(id)` to
   get the full description, targeted platforms, data sources, and detection
   notes. Use `tactics` to understand attacker stage and architecture fit.

4. Call `get_community_sigma_rules(cve_id)` to check whether the security
   community has already published detection rules. If `found=true`, the
   `logsources` and `attack_tags` tell you what log sources are considered
   authoritative.

5. Synthesise: combine priority tier + exploitation evidence + architecture
   fit assessment + detection availability into a risk narrative with
   recommended actions (patch urgency, detection deployment, workarounds).

---

## Workflow 3: Detection Coverage Assessment

Use when you want to understand how well a CVE (or its mapped techniques)
can be detected in your environment.

Steps:
1. Call `get_attack_techniques(cve_id)` to get the deterministic technique
   mapping. Check `mapping_method` — "cwe_static+cvss_heuristic" means both
   CWE-based (higher confidence) and CVSS-based (lower confidence) signals
   were used.

2. Call `get_community_sigma_rules(cve_id)`.
   - `found=true` with rules: review `logsources` to confirm you have those
     log sources in your SIEM. Review `attack_tags` to confirm alignment.
   - `found=false`: no community baseline exists; you are starting from scratch.

3. For each mapped technique, call `lookup_technique(id)`:
   - `data_sources` tells you what telemetry is needed to detect this technique.
   - `detection_notes` provides MITRE's recommended detection approach.
   - `platforms` tells you which OSes/environments are in scope.

4. If you have a generated Sigma rule, call
   `compare_sigma_rule_with_community(cve_id, rule_text)` to check:
   - Whether your logsource matches community consensus.
   - Whether your ATT&CK tags are complete.
   - Whether your severity level is aligned.

5. Report gaps: techniques with no community rules, log sources you do not
   collect, and ATT&CK tags missing from your rule.

---

## ATT&CK Tactic Quick Reference

| Tactic              | ID     | Deployment Relevance                              |
|---------------------|--------|---------------------------------------------------|
| Initial Access      | TA0001 | Only if service is internet-exposed               |
| Execution           | TA0002 | Post-initial-access code execution                |
| Persistence         | TA0003 | Attacker maintaining access after compromise      |
| Privilege Escalation| TA0004 | Attacker already has low-privilege access         |
| Defense Evasion     | TA0005 | Attacker avoiding detection post-compromise       |
| Credential Access   | TA0006 | Stealing credentials from the system              |
| Discovery           | TA0007 | Attacker mapping the environment post-compromise  |
| Lateral Movement    | TA0008 | Only if attacker is already inside the network    |
| Collection          | TA0009 | Data gathering prior to exfiltration              |
| Command and Control | TA0011 | Attacker communicating with compromised system    |
| Exfiltration        | TA0010 | Data leaving the environment                      |
| Impact              | TA0040 | Ransomware, destruction, DoS — end-game actions   |
"""


@mcp.resource("ref://tactic-guide")
def tactic_guide() -> str:
    """ATT&CK tactic definitions and their deployment architecture relevance."""
    return """\
# ATT&CK Tactic Guide — Deployment Architecture Relevance

Use this reference when interpreting `techniques` output from triage_cve or
get_attack_techniques to decide whether a CVE is relevant to a specific deployment.

## Initial Access (TA0001)
Techniques: Exploit Public-Facing Application (T1190), Drive-by Compromise (T1189),
Phishing (T1566), External Remote Services (T1133)

Relevant when: The vulnerable service or application is reachable from an untrusted
network (internet, partner network, or guest VLAN).
Not relevant when: The service is internal-only with no external exposure.
Key question: "Can an unauthenticated external actor reach this service?"

## Execution (TA0002)
Techniques: Command and Scripting Interpreter (T1059), Exploitation for Client
Execution (T1203), User Execution (T1204)

Relevant when: An attacker has already gained some access and is running code.
Context: Usually follows Initial Access. Indicates the vulnerability allows
arbitrary code execution on the target.

## Privilege Escalation (TA0004)
Techniques: Exploitation for Privilege Escalation (T1068), Valid Accounts (T1078),
Sudo and Sudo Caching (T1548.003)

Relevant when: An attacker already has low-privilege access and can escalate to root
or SYSTEM. Only relevant if Initial Access is already assumed.
Key question: "Does an attacker already have a foothold in this environment?"

## Lateral Movement (TA0008)
Techniques: Exploitation of Remote Services (T1210), Remote Services (T1021),
Pass the Hash (T1550.002)

Relevant when: The environment has an attacker already present (post-breach),
and the vulnerable service is reachable from inside the network.
Not relevant when: No breach has occurred and external exposure is the primary concern.
Key question: "Is this on an internal network segment accessible post-compromise?"

## Impact (TA0040)
Techniques: Data Encrypted for Impact (T1486 — ransomware), Service Stop (T1489),
Defacement (T1491), DoS (T1499)

Context: Describes what an attacker achieves after successful exploitation. Use this
to understand blast radius, not to qualify whether the attack is possible.

## Credential Access (TA0006)
Techniques: Brute Force (T1110), OS Credential Dumping (T1003), Unsecured
Credentials (T1552)

Relevant when: The vulnerability exposes credentials directly, or an attacker
already present can use the exploit to harvest credentials for further access.
"""


@mcp.resource("ref://cwe-attack-map")
def cwe_attack_map() -> str:
    """The static CWE-to-ATT&CK technique mapping used by get_attack_techniques."""
    map_path = Path(__file__).parent.parent / "data" / "cwe_attack_map.json"
    try:
        data = json.loads(map_path.read_text(encoding="utf-8"))
        return json.dumps(data, indent=2)
    except Exception as exc:
        return json.dumps({"error": f"Could not load CWE map: {exc}"})


# ---------------------------------------------------------------------------
# MCP Prompts — guided workflow templates
# ---------------------------------------------------------------------------

@mcp.prompt()
def triage_scanner_output(cve_ids: str) -> str:
    """Guided workflow for triaging CVE IDs from scanner output.

    Args:
        cve_ids: Comma-separated CVE IDs from scanner output
                 (e.g. "CVE-2024-21762, CVE-2023-44487, CVE-2021-44228")
    """
    id_list = [c.strip() for c in cve_ids.split(",") if c.strip()]
    formatted = json.dumps(id_list)
    return f"""\
You are triaging CVEs from scanner output. Follow these steps in order:

**CVEs to triage:** {formatted}

## Step 1 — Batch triage
Call `batch_triage_cves` with the list above. Note the `summary` counts and
review `failed` entries — handle rate-limited ones by retrying individually
with `triage_cve`.

## Step 2 — Deepen CRITICAL and HIGH findings
For every CVE in the results with `priority_tier` of CRITICAL or HIGH:
- Call `get_exploitation_context(cve_id)` to confirm KEV status and SSVC scores.
- Note `kev_date_added` if present — this tells you how long it has been
  actively exploited in the wild.

## Step 3 — Apply deployment context
For each result, read `attack_requirements`:
- If `network_access_required=true`: is this service reachable from the internet
  or an untrusted network? If not, reduce urgency.
- If `authentication_required=true`: an attacker needs valid credentials first —
  note this as a mitigating factor.
- If `user_interaction_required=true`: social engineering is required — note this.

Read `triage_notes` for pre-computed risk observations.

Check `techniques[].tactics` for ATT&CK context:
- "initial-access" → only matters if the service is externally exposed.
- "lateral-movement" → only matters if an attacker is already inside the network.

## Step 4 — Summarise
Produce a prioritised remediation list grouped by tier:
- CRITICAL: patch within 24 hours
- HIGH: patch within the current sprint
- MEDIUM: schedule for next release cycle
- LOW: monitor and patch on regular cadence

For each CVE include: priority tier, brief description of the risk, any
deployment-specific factors that raise or lower urgency, and whether active
exploitation is confirmed.
"""


@mcp.prompt()
def investigate_cve(cve_id: str, deployment_context: str = "") -> str:
    """Guided workflow for a full single-CVE investigation.

    Args:
        cve_id: The CVE ID to investigate (e.g. CVE-2024-21762)
        deployment_context: Optional description of your deployment
                            (e.g. "internet-facing Nginx, internal Postgres,
                            no direct user access to the app server")
    """
    context_section = (
        f"\n**Deployment context provided:** {deployment_context}\n"
        if deployment_context
        else "\n**No deployment context provided** — note where assumptions are made.\n"
    )
    return f"""\
You are performing a full investigation of **{cve_id}**.
{context_section}
Follow these steps in order:

## Step 1 — Full triage assessment
Call `triage_cve("{cve_id}")`. This gives you priority tier, exploitation
signals, attack requirements, impact scope, top ATT&CK techniques, and
triage notes in one call.

## Step 2 — Exploitation evidence
Call `get_exploitation_context("{cve_id}")`. Confirm:
- Is this in the CISA KEV catalog? (`in_kev`)
- What is the SSVC exploitation level? (`ssvc_exploitation`: active/poc/none)
- Is exploitation automatable at scale? (`ssvc_automatable`)
- What is the technical impact? (`ssvc_technical_impact`: total/partial)

## Step 3 — ATT&CK technique deep-dive
For each technique in `triage_cve.techniques`, call `lookup_technique(id)`:
- Note `tactics` — use this to qualify risk against the deployment context.
- Note `platforms` — confirm the vulnerable platforms are in use.
- Note `detection_notes` and `data_sources` — record what telemetry is needed
  to detect exploitation attempts.

## Step 4 — Detection coverage
Call `get_community_sigma_rules("{cve_id}")`:
- If `found=true`: the community has published detection rules. Note the
  `logsources` — confirm you collect those log sources.
- If `found=false`: no community baseline. Use `detection_notes` from Step 3
  to understand what to build.

## Step 5 — Risk narrative
Synthesise everything into a structured risk assessment:

1. **What is it?** — One-sentence description of the vulnerability.
2. **How bad is it?** — Priority tier with justification (CVSS score,
   exploitation evidence, technical impact).
3. **Does it apply here?** — Cross-reference attack requirements and ATT&CK
   tactics against the deployment context. Explicitly state what assumptions
   you are making if no deployment context was provided.
4. **What can an attacker achieve?** — Impact scope (confidentiality/
   integrity/availability, scope change).
5. **Is it being exploited?** — KEV status, SSVC exploitation level,
   any `kev_date_added`.
6. **Can we detect it?** — Community rules available? Log sources required?
   Gaps in current detection?
7. **Recommended actions** — Patch urgency, detection rules to deploy,
   workarounds if a patch is not immediately available.
"""


@mcp.prompt()
def assess_detection_coverage(cve_id: str) -> str:
    """Guided workflow for assessing and improving detection coverage for a CVE.

    Args:
        cve_id: The CVE ID to assess detection coverage for
    """
    return f"""\
You are assessing detection coverage for **{cve_id}**.

## Step 1 — Map attack techniques
Call `get_attack_techniques("{cve_id}")` to get the deterministic technique
mapping. Note:
- `techniques[].mapping_source`: "cwe_static" = derived from CWE lookup (reliable);
  "cvss_*_vector" or "cvss_dos_impact" = structurally implied by CVSS vector;
  "claude_enriched" = added or confirmed by Claude enrichment.

## Step 2 — Check community baseline
Call `get_community_sigma_rules("{cve_id}")`:
- `found=true`: review `filenames`, `logsources`, and `attack_tags`.
  The community logsource is your strongest signal for where to look.
- `found=false`: no community baseline — proceed from technique data alone.

## Step 3 — Deep-dive each technique
For each technique from Step 1, call `lookup_technique(technique_id)` and record:
- `data_sources`: what telemetry is needed (process creation, network traffic,
  web logs, etc.)
- `detection_notes`: MITRE's recommended approach
- `platforms`: which OSes/environments are relevant
- `tactics`: attacker stage (shapes which log sources matter)

## Step 4 — Coverage gap analysis
For each technique, assess:
- Do you collect the required `data_sources`?
- Do you have rules covering this technique already?
- Does the community have a rule? If yes, is it deployed in your SIEM?
- Is the technique's platform relevant to your environment?

## Step 5 — Report
Produce a detection coverage report:

| Technique | Tactic | Data Sources Needed | Community Rule? | Gap? |
|-----------|--------|---------------------|-----------------|------|
| (fill in from Steps 1–4) |

Then for each gap:
- Specify the log source needed.
- Summarise the detection logic from `detection_notes`.
- Note whether a community Sigma rule exists or needs to be written.
- Prioritise gaps by mapping_source: "cwe_static" gaps are most reliable; "cvss_*" gaps are structurally implied.
"""


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
