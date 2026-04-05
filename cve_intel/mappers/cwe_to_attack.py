"""Static CWE-ID to ATT&CK technique mapping."""

import json
from pathlib import Path
from typing import Optional

from cve_intel.fetchers.attack_data import AttackData
from cve_intel.models.attack import AttackMapping, AttackTechnique

_MAP_PATH = Path(__file__).parent.parent.parent / "data" / "cwe_attack_map.json"
_cwe_map: Optional[dict] = None


def _load_map() -> dict:
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
    technique_ids: dict[str, float] = {}

    for cwe_id in cwe_ids:
        entry = cwe_map.get(cwe_id)
        if entry:
            for tid in entry["techniques"]:
                technique_ids[tid] = max(technique_ids.get(tid, 0.0), 0.6)

    techniques: list[AttackTechnique] = []
    for tid, confidence in technique_ids.items():
        tech = attack_data.get_technique(tid)
        if tech:
            tech = tech.model_copy(update={"confidence": confidence, "rationale": f"Mapped from CWE (static map)"})
            techniques.append(tech)

    return AttackMapping(
        cve_id=cve_id,
        techniques=techniques,
        mapping_method="cwe_static",
        rationale=f"Static CWE-to-ATT&CK map for: {', '.join(cwe_ids) or 'none'}",
    )
