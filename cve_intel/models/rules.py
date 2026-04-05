from enum import Enum
from datetime import datetime, timezone
from uuid import uuid4
from pydantic import BaseModel, Field


class RuleFormat(str, Enum):
    SIGMA = "sigma"
    YARA = "yara"
    SNORT = "snort"
    SURICATA = "suricata"


class RuleCategory(str, Enum):
    NETWORK_DETECTION = "network_detection"
    FILE_DETECTION = "file_detection"
    PROCESS_DETECTION = "process_detection"
    MEMORY_DETECTION = "memory_detection"
    BEHAVIORAL = "behavioral"


class DetectionRule(BaseModel):
    rule_id: str = Field(default_factory=lambda: str(uuid4()))
    cve_id: str
    rule_format: RuleFormat
    category: RuleCategory
    name: str
    description: str = ""
    rule_text: str
    technique_ids: list[str] = Field(default_factory=list)
    severity: str = "medium"
    confidence: str = "medium"
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    generation_method: str = "hybrid"


class RuleBundle(BaseModel):
    cve_id: str
    sigma_rules: list[DetectionRule] = Field(default_factory=list)
    yara_rules: list[DetectionRule] = Field(default_factory=list)
    snort_rules: list[DetectionRule] = Field(default_factory=list)
    suricata_rules: list[DetectionRule] = Field(default_factory=list)

    def all_rules(self) -> list[DetectionRule]:
        return self.sigma_rules + self.yara_rules + self.snort_rules + self.suricata_rules


class AnalysisResult(BaseModel):
    cve_id: str
    cve_record: "CVERecord"
    attack_mapping: "AttackMapping"
    ioc_bundle: "IOCBundle"
    rule_bundle: RuleBundle
    enriched: bool = True
    metadata: dict = Field(default_factory=dict)


# Resolve forward refs
from .cve import CVERecord  # noqa: E402
from .attack import AttackMapping  # noqa: E402
from .ioc import IOCBundle  # noqa: E402

AnalysisResult.model_rebuild()
