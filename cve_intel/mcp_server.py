"""MCP server for cve-intel — exposes CVE intelligence tools to Claude Code.

All tools are deterministic (no Anthropic API calls). Claude Code acts as the
reasoning layer, interpreting the structured data returned by these tools.

The ATT&CK STIX bundle (~80MB) is loaded once at server startup via the
lifespan context and shared across all tool calls.
"""

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from mcp.server.fastmcp import FastMCP, Context

from cve_intel.fetchers.attack_data import get_attack_data, AttackData
from cve_intel.fetchers.nvd import NVDFetcher
from cve_intel.mappers.cwe_to_attack import map_cwe_to_attack
from cve_intel.mappers.cvss_to_attack import map_cvss_to_attack


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[dict]:
    """Load ATT&CK STIX data once at startup and share across all tool calls."""
    attack_data: AttackData = get_attack_data()
    yield {"attack_data": attack_data}


mcp = FastMCP("cve-intel", lifespan=lifespan)


@mcp.tool()
def fetch_cve(cve_id: str, ctx: Context) -> dict:
    """Fetch a CVE record from the NVD (National Vulnerability Database).

    Returns the full CVE record including English description, CVSS score and
    vector, CWE weakness IDs, affected CPE products, and reference URLs.

    Use this when you need the raw CVE data for a specific CVE ID.
    """
    record = NVDFetcher().fetch(cve_id)
    return record.model_dump(mode="json")


@mcp.tool()
def get_attack_techniques(cve_id: str, ctx: Context) -> dict:
    """Map a CVE to MITRE ATT&CK techniques using CWE weakness types and CVSS heuristics.

    Returns an AttackMapping with technique IDs, names, associated tactics,
    platform coverage, confidence scores (0.0–1.0), and rationale.

    Mapping is deterministic: CWE IDs are looked up in a static map, and CVSS
    vector attributes add low-confidence technique hints. Use this as a starting
    point — you can refine the mapping using your own reasoning over the CVE description.
    """
    attack_data: AttackData = ctx.request_context.lifespan_context["attack_data"]
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

    This is the best starting point for CVE analysis in a Claude Code session.
    After calling this, you have everything needed to reason about the vulnerability,
    suggest IOCs, and generate detection rules.
    """
    attack_data: AttackData = ctx.request_context.lifespan_context["attack_data"]
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


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
