"""CVSS vector attribute heuristics for ATT&CK technique hints."""

from cve_intel.fetchers.attack_data import AttackData
from cve_intel.models.attack import AttackMapping, AttackTechnique
from cve_intel.models.cve import CVSSData


# (attack_vector, attack_complexity, privileges_required, scope_changed) -> [(tech_id, confidence)]
_HEURISTICS: list[tuple[dict, list[tuple[str, float]]]] = [
    # Network-facing, low complexity — likely public-facing exploit
    ({"attack_vector": "NETWORK", "attack_complexity": "LOW"}, [("T1190", 0.5)]),
    # Network-facing, adjacent — lateral movement or network service exploit
    ({"attack_vector": "ADJACENT_NETWORK"}, [("T1210", 0.4)]),
    # Scope change — privilege escalation is likely
    ({"scope": "CHANGED"}, [("T1068", 0.4)]),
    # Physical access required
    ({"attack_vector": "PHYSICAL"}, [("T1200", 0.5)]),
    # High integrity/confidentiality impact, no privileges — likely credential access
    ({"privileges_required": "NONE", "confidentiality_impact": "HIGH"}, [("T1552", 0.3)]),
    # Availability impact only — DoS
    ({"availability_impact": "HIGH", "confidentiality_impact": "NONE", "integrity_impact": "NONE"},
     [("T1499", 0.5)]),
]


def map_cvss_to_attack(
    cve_id: str,
    cvss: CVSSData,
    attack_data: AttackData,
    existing_ids: set[str],
) -> list[AttackTechnique]:
    """Return additional low-confidence technique hints based on CVSS attributes."""
    hints: dict[str, float] = {}

    for conditions, mappings in _HEURISTICS:
        if _matches(cvss, conditions):
            for tid, conf in mappings:
                if tid not in existing_ids:
                    hints[tid] = max(hints.get(tid, 0.0), conf)

    techniques: list[AttackTechnique] = []
    for tid, confidence in hints.items():
        tech = attack_data.get_technique(tid)
        if tech:
            tech = tech.model_copy(update={
                "confidence": confidence,
                "rationale": "CVSS vector heuristic (low confidence)",
            })
            techniques.append(tech)

    return techniques


def _matches(cvss: CVSSData, conditions: dict) -> bool:
    for attr, expected in conditions.items():
        actual = getattr(cvss, attr, None)
        if actual is None:
            return False
        if isinstance(expected, str) and actual.upper() != expected.upper():
            return False
    return True
