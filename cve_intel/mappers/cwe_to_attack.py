"""Static CWE-ID to ATT&CK technique mapping."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cve_intel.fetchers.attack_data import AttackData
from cve_intel.models.attack import AttackMapping, AttackTechnique

_MAP_PATH = Path(__file__).parent.parent.parent / "data" / "cwe_attack_map.json"
_cwe_map: dict[str, Any] | None = None


def _load_map() -> dict[str, Any]:
    global _cwe_map
    if _cwe_map is None:
        _cwe_map = json.loads(_MAP_PATH.read_text(encoding="utf-8"))
    return _cwe_map


def map_cwe_to_attack(
    cve_id: str,
    cwe_ids: list[str],
    attack_data: AttackData,
) -> AttackMapping:
    cwe_map = _load_map()
    technique_sources: dict[str, list[str]] = {}  # tid → [cwe_id, ...]

    for cwe_id in cwe_ids:
        entry = cwe_map.get(cwe_id)
        if entry:
            for tid in entry["techniques"]:
                technique_sources.setdefault(tid, []).append(cwe_id)

    techniques: list[AttackTechnique] = []
    for tid, sources in technique_sources.items():
        tech = attack_data.get_technique(tid)
        if tech:
            cwe_label = ", ".join(sources)
            rationale = f"{cwe_label} → {tid} (static map)"
            # Use per-entry confidence from the map; fall back to 0.6 if absent.
            # Confidence values align with the Claude enricher's scale:
            #   0.9 = unambiguous, 0.7 = standard class, 0.5 = plausible, 0.3 = speculative
            base_confidence = max(
                cwe_map[src].get("confidence", 0.6) for src in sources if src in cwe_map
            )
            tech = tech.model_copy(update={"confidence": base_confidence, "rationale": rationale})
            techniques.append(tech)

    return AttackMapping(
        cve_id=cve_id,
        techniques=techniques,
        mapping_method="cwe_static",
        rationale=f"Static CWE-to-ATT&CK map for: {', '.join(cwe_ids) or 'none'}",
    )
