from enum import Enum
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class CVSSSeverity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CVSSData(BaseModel):
    version: str
    vector_string: str
    base_score: float
    base_severity: CVSSSeverity
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None


class Reference(BaseModel):
    url: str
    source: str
    tags: list[str] = Field(default_factory=list)


class CPEMatch(BaseModel):
    criteria: str
    version_start_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    vulnerable: bool = True


class CVERecord(BaseModel):
    cve_id: str
    source_identifier: str = ""
    published: datetime
    last_modified: datetime
    vuln_status: str = ""
    descriptions: dict[str, str] = Field(default_factory=dict)
    cvss: list[CVSSData] = Field(default_factory=list)
    weaknesses: list[str] = Field(default_factory=list)
    cpe_matches: list[CPEMatch] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)

    @property
    def description_en(self) -> str:
        return self.descriptions.get("en", "")

    @property
    def primary_cvss(self) -> Optional[CVSSData]:
        for ver in ("4.0", "3.1", "3.0", "2.0"):
            for c in self.cvss:
                if c.version == ver:
                    return c
        return self.cvss[0] if self.cvss else None

    @property
    def affected_products(self) -> list[str]:
        """Return unique vendor/product strings from CPE matches."""
        products = set()
        for cpe in self.cpe_matches:
            parts = cpe.criteria.split(":")
            if len(parts) >= 5:
                vendor = parts[3]
                product = parts[4]
                if vendor != "*" and product != "*":
                    products.add(f"{vendor}/{product}")
        return sorted(products)
