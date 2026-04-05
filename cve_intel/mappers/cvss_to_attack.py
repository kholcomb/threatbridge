"""CVSS vector attribute heuristics for ATT&CK technique hints."""

from cve_intel.fetchers.attack_data import AttackData
from cve_intel.models.attack import AttackMapping, AttackTechnique
from cve_intel.models.cve import CVSSData


# (label, conditions) -> [(tech_id, confidence)]
_HEURISTICS: list[tuple[str, dict, list[tuple[str, float]]]] = [
    ("NETWORK + LOW complexity", {"attack_vector": "NETWORK", "attack_complexity": "LOW"}, [("T1190", 0.5)]),
    ("ADJACENT_NETWORK vector", {"attack_vector": "ADJACENT_NETWORK"}, [("T1210", 0.4)]),
    ("scope CHANGED", {"scope": "CHANGED"}, [("T1068", 0.4)]),
    ("PHYSICAL access", {"attack_vector": "PHYSICAL"}, [("T1200", 0.5)]),
    ("no privileges + HIGH confidentiality", {"privileges_required": "NONE", "confidentiality_impact": "HIGH"}, [("T1552", 0.3)]),
    ("HIGH availability, no C/I impact", {"availability_impact": "HIGH", "confidentiality_impact": "NONE", "integrity_impact": "NONE"}, [("T1499", 0.5)]),
]


def map_cvss_to_attack(
    cve_id: str,
    cvss: CVSSData,
    attack_data: AttackData,
    existing_ids: set[str],
) -> list[AttackTechnique]:
    """Return additional low-confidence technique hints based on CVSS attributes."""
    hints: dict[str, tuple[float, str]] = {}  # tid → (confidence, label)

    for label, conditions, mappings in _HEURISTICS:
        if _matches(cvss, conditions):
            for tid, conf in mappings:
                if tid not in existing_ids:
                    if conf > hints.get(tid, (0.0, ""))[0]:
                        hints[tid] = (conf, label)

    techniques: list[AttackTechnique] = []
    for tid, (confidence, label) in hints.items():
        tech = attack_data.get_technique(tid)
        if tech:
            tech = tech.model_copy(update={
                "confidence": confidence,
                "rationale": f"CVSS heuristic: {label} → {tid}",
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
