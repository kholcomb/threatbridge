"""Tests for CVSSSignals normalisation and technique re-ranking."""

import pytest
from unittest.mock import MagicMock

from cve_intel.mappers.cvss_signals import CVSSSignals, extract_signals, rank_techniques
from cve_intel.models.cve import CVSSData, CVSSSeverity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cvss(version: str, vector: str, score: float = 9.0) -> CVSSData:
    return CVSSData(
        version=version,
        vector_string=vector,
        base_score=score,
        base_severity=CVSSSeverity.CRITICAL,
    )


def _technique(technique_id: str, tactic_ids: list[str], confidence: float = 0.9) -> MagicMock:
    tech = MagicMock()
    tech.technique_id = technique_id
    tech.confidence = confidence
    tech.tactics = [MagicMock(tactic_id=tid) for tid in tactic_ids]
    return tech


# ---------------------------------------------------------------------------
# extract_signals — v4.0
# ---------------------------------------------------------------------------

class TestExtractSignalsV4:
    def test_unauthenticated_remote(self):
        sig = extract_signals(_cvss("4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
        assert sig.attack_vector == "N"
        assert sig.attack_requirements == "N"
        assert sig.privileges_required == "N"
        assert sig.user_interaction == "N"
        assert sig.subsequent_impact is False
        assert sig.cvss_version == "4.0"

    def test_subsequent_impact_when_sc_high(self):
        sig = extract_signals(_cvss("4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:N/SA:N"))
        assert sig.subsequent_impact is True

    def test_subsequent_impact_when_si_high(self):
        sig = extract_signals(_cvss("4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:H/SA:N"))
        assert sig.subsequent_impact is True

    def test_not_defined_subsequent_treated_as_no_impact(self):
        sig = extract_signals(_cvss("4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:X/SI:X/SA:X"))
        assert sig.subsequent_impact is False

    def test_attack_requirements_present(self):
        sig = extract_signals(_cvss("4.0", "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
        assert sig.attack_requirements == "P"

    def test_local_vector(self):
        sig = extract_signals(_cvss("4.0", "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
        assert sig.attack_vector == "L"
        assert sig.privileges_required == "L"

    def test_active_user_interaction(self):
        sig = extract_signals(_cvss("4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
        assert sig.user_interaction == "A"


# ---------------------------------------------------------------------------
# extract_signals — v3.1 / v3.0
# ---------------------------------------------------------------------------

class TestExtractSignalsV3:
    def test_v31_unauthenticated_remote(self):
        sig = extract_signals(_cvss("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        assert sig.attack_vector == "N"
        assert sig.attack_requirements == "N"
        assert sig.privileges_required == "N"
        assert sig.user_interaction == "N"
        assert sig.subsequent_impact is False
        assert sig.cvss_version == "3.1"

    def test_v31_high_complexity_maps_to_at_present(self):
        sig = extract_signals(_cvss("3.1", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        assert sig.attack_requirements == "P"

    def test_v31_scope_changed_maps_to_subsequent_impact(self):
        sig = extract_signals(_cvss("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"))
        assert sig.subsequent_impact is True

    def test_v31_user_interaction_required_maps_to_passive(self):
        sig = extract_signals(_cvss("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"))
        assert sig.user_interaction == "P"

    def test_v30_treated_same_as_v31(self):
        sig = extract_signals(_cvss("3.0", "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"))
        assert sig.attack_vector == "L"
        assert sig.privileges_required == "H"
        assert sig.subsequent_impact is True
        assert sig.cvss_version == "3.0"


# ---------------------------------------------------------------------------
# extract_signals — v2.0
# ---------------------------------------------------------------------------

class TestExtractSignalsV2:
    def test_no_auth_low_complexity(self):
        sig = extract_signals(_cvss("2.0", "AV:N/AC:L/Au:N/C:C/I:C/A:C"))
        assert sig.attack_vector == "N"
        assert sig.privileges_required == "N"
        assert sig.attack_requirements == "N"
        assert sig.user_interaction == "N"
        assert sig.subsequent_impact is False
        assert sig.cvss_version == "2.0"

    def test_single_auth_maps_to_low_privileges(self):
        sig = extract_signals(_cvss("2.0", "AV:N/AC:L/Au:S/C:C/I:C/A:C"))
        assert sig.privileges_required == "L"

    def test_multiple_auth_maps_to_low_privileges(self):
        sig = extract_signals(_cvss("2.0", "AV:N/AC:M/Au:M/C:C/I:C/A:C"))
        assert sig.privileges_required == "L"

    def test_high_complexity_maps_to_at_present(self):
        sig = extract_signals(_cvss("2.0", "AV:N/AC:H/Au:N/C:C/I:C/A:C"))
        assert sig.attack_requirements == "P"

    def test_medium_complexity_maps_to_at_present(self):
        sig = extract_signals(_cvss("2.0", "AV:N/AC:M/Au:N/C:P/I:N/A:N"))
        assert sig.attack_requirements == "P"

    def test_local_vector(self):
        sig = extract_signals(_cvss("2.0", "AV:L/AC:L/Au:N/C:C/I:C/A:C"))
        assert sig.attack_vector == "L"


# ---------------------------------------------------------------------------
# rank_techniques — ordering scenarios
# ---------------------------------------------------------------------------

class TestRankTechniques:
    def _signals(self, av="N", at="N", pr="N", ui="N", subsequent=False, version="4.0"):
        return CVSSSignals(
            attack_vector=av,
            attack_requirements=at,
            privileges_required=pr,
            user_interaction=ui,
            subsequent_impact=subsequent,
            cvss_version=version,
        )

    def test_unauthenticated_network_initial_access_leads(self):
        """T1190 (Initial Access) should rank above T1203 (Execution) for AV:N/PR:N/UI:N."""
        t_initial = _technique("T1190", ["TA0001"], confidence=0.5)
        t_exec    = _technique("T1203", ["TA0002"], confidence=0.9)

        sig = self._signals(av="N", pr="N", ui="N")
        ranked = rank_techniques([t_exec, t_initial], sig)

        assert ranked[0].technique_id == "T1190"

    def test_user_interaction_execution_leads(self):
        """T1203 (Execution) should rank above T1190 (Initial Access) when UI:P."""
        t_initial = _technique("T1190", ["TA0001"], confidence=0.9)
        t_exec    = _technique("T1203", ["TA0002"], confidence=0.5)

        sig = self._signals(av="N", pr="N", ui="P")
        ranked = rank_techniques([t_initial, t_exec], sig)

        assert ranked[0].technique_id == "T1203"

    def test_active_user_interaction_execution_leads(self):
        """UI:A (Active) also promotes Execution over Initial Access."""
        t_initial = _technique("T1190", ["TA0001"], confidence=0.9)
        t_exec    = _technique("T1203", ["TA0002"], confidence=0.5)

        sig = self._signals(av="N", pr="N", ui="A")
        ranked = rank_techniques([t_initial, t_exec], sig)

        assert ranked[0].technique_id == "T1203"

    def test_local_vector_deprioritises_initial_access(self):
        """AV:L should penalise Initial Access techniques below PrivEsc."""
        t_initial = _technique("T1190", ["TA0001"], confidence=0.9)
        t_privesc = _technique("T1068", ["TA0004"], confidence=0.5)

        sig = self._signals(av="L")
        ranked = rank_techniques([t_initial, t_privesc], sig)

        assert ranked[0].technique_id == "T1068"

    def test_adjacent_network_lateral_movement_promoted(self):
        """AV:A should promote Lateral Movement alongside Initial Access."""
        t_initial  = _technique("T1210", ["TA0001"], confidence=0.5)
        t_lateral  = _technique("T1557", ["TA0008"], confidence=0.5)
        t_privesc  = _technique("T1068", ["TA0004"], confidence=0.9)

        sig = self._signals(av="A")
        ranked = rank_techniques([t_privesc, t_initial, t_lateral], sig)

        # PrivEsc has no AV:A bonus; Initial Access and Lateral Movement should rank above it
        top_ids = {t.technique_id for t in ranked[:2]}
        assert "T1210" in top_ids
        assert "T1557" in top_ids

    def test_subsequent_impact_promotes_lateral_and_privesc(self):
        """subsequent_impact=True should boost Lateral Movement and PrivEsc."""
        t_initial  = _technique("T1190", ["TA0001"], confidence=0.9)
        t_lateral  = _technique("T1021", ["TA0008"], confidence=0.5)

        sig = self._signals(av="N", pr="N", ui="N", subsequent=True)
        ranked = rank_techniques([t_initial, t_lateral], sig)

        # T1190 gets +3 (initial access, unauthenticated remote)
        # T1021 gets +1 (lateral movement) + +1 (subsequent_impact) = +2
        # T1190 still leads on fit score, but lateral is promoted vs no-subsequent case
        assert ranked[0].technique_id == "T1190"
        assert ranked[1].technique_id == "T1021"

    def test_none_signals_falls_back_to_confidence_sort(self):
        """Without signals, sort by confidence descending (existing behaviour)."""
        t_low  = _technique("T1190", ["TA0001"], confidence=0.3)
        t_high = _technique("T1203", ["TA0002"], confidence=0.9)

        ranked = rank_techniques([t_low, t_high], signals=None)

        assert ranked[0].technique_id == "T1203"

    def test_confidence_breaks_ties_within_same_fit_score(self):
        """Two techniques with equal fit score should be ordered by confidence."""
        t_low  = _technique("T1190", ["TA0001"], confidence=0.5)
        t_high = _technique("T1133", ["TA0001"], confidence=0.9)  # both Initial Access

        sig = self._signals(av="N", pr="N", ui="N")
        ranked = rank_techniques([t_low, t_high], sig)

        assert ranked[0].technique_id == "T1133"
