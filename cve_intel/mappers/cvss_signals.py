"""CVSS version-normalised signals for ATT&CK technique re-ranking.

All signals are expressed in CVSS v4.0 semantics regardless of the source
vector version.  Older vector formats are mapped as follows:

  v3.1 / v3.0
    AC:H          → attack_requirements = "P"   (high complexity implies prereq)
    AC:L          → attack_requirements = "N"
    UI:N          → user_interaction    = "N"
    UI:R          → user_interaction    = "P"   (can't distinguish Active/Passive)
    S:U           → subsequent_impact  = False
    S:C           → subsequent_impact  = True

  v2.0
    Au:N          → privileges_required = "N"
    Au:S / Au:M   → privileges_required = "L"   (conservative upper-bound)
    AC:L          → attack_requirements = "N"
    AC:M / AC:H   → attack_requirements = "P"
    (no UI field) → user_interaction    = "N"
    (no scope)    → subsequent_impact  = False
"""

from __future__ import annotations

from dataclasses import dataclass

from cve_intel.models.attack import AttackTechnique
from cve_intel.models.cve import CVSSData

# ATT&CK tactic IDs referenced in scoring
_INITIAL_ACCESS    = "TA0001"
_EXECUTION         = "TA0002"
_PERSISTENCE       = "TA0003"
_PRIV_ESC          = "TA0004"
_CREDENTIAL_ACCESS = "TA0006"
_LATERAL_MOVEMENT  = "TA0008"


@dataclass(frozen=True)
class CVSSSignals:
    """Version-normalised CVSS signals expressed in v4.0 semantics."""

    attack_vector: str        # "N" | "A" | "L" | "P"
    attack_requirements: str  # "N" | "P"
    privileges_required: str  # "N" | "L" | "H"
    user_interaction: str     # "N" | "P" | "A"
    subsequent_impact: bool   # True when exploit can affect beyond vulnerable component
    cvss_version: str         # "2.0" | "3.0" | "3.1" | "4.0"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_signals(cvss: CVSSData) -> CVSSSignals:
    """Normalise a CVSSData record into CVSSSignals using v4.0 semantics."""
    fields = _parse_vector(cvss.vector_string)
    version = cvss.version

    if version == "4.0":
        return _from_v4(fields)
    if version in ("3.0", "3.1"):
        return _from_v3(fields, version)
    return _from_v2(fields)


def rank_techniques(
    techniques: list[AttackTechnique],
    signals: CVSSSignals | None,
) -> list[AttackTechnique]:
    """Sort techniques by (tactic_fit_score DESC, confidence DESC).

    When signals is None (no CVSS data) falls back to confidence-only sort,
    preserving existing behaviour.
    """
    if signals is None:
        return sorted(techniques, key=lambda t: t.confidence, reverse=True)

    return sorted(
        techniques,
        key=lambda t: (_tactic_fit_score(t, signals), t.confidence),
        reverse=True,
    )


# ---------------------------------------------------------------------------
# Version normalisers
# ---------------------------------------------------------------------------

def _parse_vector(vector: str) -> dict[str, str]:
    """Parse any CVSS vector string into an upper-cased key→value dict."""
    result: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            result[k.upper()] = v.upper()
    return result


def _from_v4(f: dict[str, str]) -> CVSSSignals:
    subsequent = any(
        f.get(k, "N") not in ("N", "X")
        for k in ("SC", "SI", "SA")
    )
    return CVSSSignals(
        attack_vector=f.get("AV", "N"),
        attack_requirements=f.get("AT", "N"),
        privileges_required=f.get("PR", "N"),
        user_interaction=f.get("UI", "N"),
        subsequent_impact=subsequent,
        cvss_version="4.0",
    )


def _from_v3(f: dict[str, str], version: str) -> CVSSSignals:
    return CVSSSignals(
        attack_vector=f.get("AV", "N"),
        attack_requirements="P" if f.get("AC", "L") == "H" else "N",
        privileges_required=f.get("PR", "N"),
        user_interaction="N" if f.get("UI", "N") == "N" else "P",
        subsequent_impact=f.get("S", "U") == "C",
        cvss_version=version,
    )


def _from_v2(f: dict[str, str]) -> CVSSSignals:
    au = f.get("AU", "N")
    ac = f.get("AC", "L")
    return CVSSSignals(
        attack_vector=f.get("AV", "N"),
        attack_requirements="P" if ac in ("M", "H") else "N",
        privileges_required="N" if au == "N" else "L",
        user_interaction="N",    # v2.0 has no user-interaction concept
        subsequent_impact=False, # v2.0 has no scope concept
        cvss_version="2.0",
    )


# ---------------------------------------------------------------------------
# Tactic fit scoring
# ---------------------------------------------------------------------------

def _tactic_fit_score(tech: AttackTechnique, sig: CVSSSignals) -> int:
    """Return an integer relevance score for a technique given CVSS signals.

    Higher score = more architecturally relevant to this CVE's attack path.
    Techniques are compared pairwise; absolute values are not meaningful.
    """
    tids = {ta.tactic_id for ta in tech.tactics}
    score = 0

    av = sig.attack_vector
    pr = sig.privileges_required
    ui = sig.user_interaction
    at = sig.attack_requirements

    if av == "N":
        if ui in ("P", "A"):
            # User must interact — Execution family is the entry point
            if _EXECUTION in tids:
                score += 3
            elif _INITIAL_ACCESS in tids:
                score += 1
        elif pr == "N":
            # Unauthenticated remote — Initial Access is the entry point
            if _INITIAL_ACCESS in tids:
                score += 3
            elif _EXECUTION in tids:
                score += 1
        else:
            # Authenticated remote — credential access precedes exploitation
            if _CREDENTIAL_ACCESS in tids:
                score += 2
            if _INITIAL_ACCESS in tids:
                score += 1
            if _PRIV_ESC in tids and pr == "H":
                score += 2

    elif av == "A":
        # Adjacent network — both initial access and lateral movement apply
        if _INITIAL_ACCESS in tids:
            score += 2
        if _LATERAL_MOVEMENT in tids:
            score += 2

    else:
        # Local or Physical — attacker is already on the system
        if _INITIAL_ACCESS in tids:
            score -= 3  # remote initial access is irrelevant
        if _PRIV_ESC in tids:
            score += 3
        if _EXECUTION in tids:
            score += 1

    # Precondition required — slight penalty for techniques that assume
    # unconstrained access when the vector demands a prerequisite
    if at == "P" and _INITIAL_ACCESS in tids and av == "N":
        score -= 1

    # Scope change / subsequent system impact — lateral and privesc more relevant
    if sig.subsequent_impact:
        if _LATERAL_MOVEMENT in tids:
            score += 1
        if _PRIV_ESC in tids:
            score += 1

    return score
