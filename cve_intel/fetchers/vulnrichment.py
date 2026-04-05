"""CISA Vulnrichment fetcher.

Retrieves exploitation context from CISA's Vulnrichment project:
- KEV (Known Exploited Vulnerabilities) status
- SSVC scores (exploitation level, automatability, technical impact)

Data source: https://github.com/cisagov/vulnrichment
"""

from __future__ import annotations

import re
import urllib.request
from dataclasses import dataclass, field

_BRANCH = "develop"
_BASE_URL = f"https://raw.githubusercontent.com/cisagov/vulnrichment/{_BRANCH}"
_CISA_ORG_ID = "134c704f-9b21-4f2e-91b3-4a467353bcc0"


@dataclass
class SSVCScore:
    exploitation: str = "none"      # "active" | "poc" | "none"
    automatable: str = "unknown"    # "yes" | "no" | "unknown"
    technical_impact: str = "unknown"  # "total" | "partial" | "unknown"


@dataclass
class VulnrichmentData:
    cve_id: str
    in_kev: bool = False
    kev_date_added: str | None = None
    ssvc: SSVCScore = field(default_factory=SSVCScore)
    available: bool = False         # False if no Vulnrichment entry exists

    @property
    def is_actively_exploited(self) -> bool:
        return self.in_kev or self.ssvc.exploitation == "active"

    def suggested_severity_boost(self) -> str | None:
        """Return 'critical' or 'high' if exploitation context warrants upgrading severity."""
        if self.in_kev and self.ssvc.exploitation == "active":
            return "critical"
        if self.in_kev or self.ssvc.exploitation == "active":
            return "high"
        if self.ssvc.exploitation == "poc" and self.ssvc.automatable == "yes":
            return "high"
        return None


def _cve_url(cve_id: str) -> str:
    """Build the raw GitHub URL for a CVE's Vulnrichment JSON."""
    parts = cve_id.upper().split("-")
    year = parts[1]
    num = int(parts[2])
    if num < 1000:
        bucket = "0xxx"
    else:
        bucket = str(num)[:-3] + "xxx"
    return f"{_BASE_URL}/{year}/{bucket}/{cve_id.upper()}.json"


def fetch_vulnrichment(cve_id: str) -> VulnrichmentData:
    """Fetch CISA Vulnrichment data for a CVE.

    Returns a VulnrichmentData with available=False if no entry exists
    or the request fails. Never raises.
    """
    result = VulnrichmentData(cve_id=cve_id)
    try:
        url = _cve_url(cve_id)
        req = urllib.request.Request(url, headers={"User-Agent": "cve-intel/0.1"})
        with urllib.request.urlopen(req, timeout=10) as r:
            import json
            data = json.loads(r.read())
    except Exception:
        return result

    result.available = True

    # Walk ADP containers looking for CISA's data
    for container in data.get("containers", {}).get("adp", []):
        org_id = container.get("providerMetadata", {}).get("orgId", "")
        if org_id != _CISA_ORG_ID:
            continue

        for metric in container.get("metrics", []):
            other = metric.get("other", {})
            mtype = other.get("type", "")
            content = other.get("content", {})

            if mtype == "kev":
                result.in_kev = True
                result.kev_date_added = content.get("dateAdded")

            elif mtype == "ssvc":
                options = {
                    opt_key: opt_val
                    for option in content.get("options", [])
                    for opt_key, opt_val in option.items()
                }
                result.ssvc = SSVCScore(
                    exploitation=options.get("Exploitation", "none").lower(),
                    automatable=options.get("Automatable", "unknown").lower(),
                    technical_impact=options.get("Technical Impact", "unknown").lower(),
                )

    return result
