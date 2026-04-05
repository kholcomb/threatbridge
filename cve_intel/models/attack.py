from __future__ import annotations

from pydantic import BaseModel, Field


class AttackTactic(BaseModel):
    tactic_id: str
    name: str
    shortname: str


class AttackTechnique(BaseModel):
    technique_id: str
    name: str
    description: str = ""
    is_subtechnique: bool = False
    parent_id: str | None = None
    tactics: list[AttackTactic] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    detection_notes: str = ""
    url: str = ""
    confidence: float = 0.5
    rationale: str = ""


class AttackMapping(BaseModel):
    cve_id: str
    techniques: list[AttackTechnique] = Field(default_factory=list)
    mapping_method: str = "deterministic"
    rationale: str = ""

    @property
    def technique_ids(self) -> list[str]:
        return [t.technique_id for t in self.techniques]

    @property
    def tactic_names(self) -> list[str]:
        names: list[str] = []
        seen: set[str] = set()
        for tech in self.techniques:
            for tactic in tech.tactics:
                if tactic.name not in seen:
                    names.append(tactic.name)
                    seen.add(tactic.name)
        return names
