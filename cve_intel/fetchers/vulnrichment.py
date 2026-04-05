"""CISA Vulnrichment fetcher.

Retrieves exploitation context from CISA's Vulnrichment project:
- KEV (Known Exploited Vulnerabilities) status
- SSVC scores (exploitation level, automatability, technical impact)

Data source: https://github.com/cisagov/vulnrichment
"""

from __future__ import annotations

import logging
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

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


_RETRY_DELAYS = [1, 2]  # seconds to sleep after 1st and 2nd failure
_MAX_ATTEMPTS = 3


def fetch_vulnrichment(cve_id: str) -> VulnrichmentData:
    """Fetch CISA Vulnrichment data for a CVE.

    Returns a VulnrichmentData with available=False if no entry exists
    or the request fails. Never raises. Retries up to 3 times total on
    transient errors (5xx, URLError, OSError) with exponential backoff.

    Caching is opt-in: set VULNRICHMENT_CACHE_TTL (seconds) in config to
    enable. Defaults to 0 (disabled) — always fetches live.
    """
    import json
    from cve_intel.config import settings

    if settings.vulnrichment_cache_ttl > 0:
        import diskcache
        cache = diskcache.Cache(str(settings.cache_dir / "vulnrichment"))
        cache_key = f"vulnrichment:{cve_id.upper()}"
        cached = cache.get(cache_key)
        if cached is not None:
            return _from_dict(cve_id, cached)
    else:
        cache = None
        cache_key = None

    result = VulnrichmentData(cve_id=cve_id)
    url = _cve_url(cve_id)
    req = urllib.request.Request(url, headers={"User-Agent": "cve-intel/0.1"})

    last_exc: Exception | None = None
    for attempt in range(_MAX_ATTEMPTS):
        if attempt > 0:
            time.sleep(_RETRY_DELAYS[attempt - 1])
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            last_exc = None
            break  # success
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                # 4xx — definitive answer, no retry
                if exc.code != 404:
                    logger.warning("Vulnrichment fetch failed for %s: %s", cve_id, exc)
                return result
            last_exc = exc
        except (urllib.error.URLError, OSError) as exc:
            last_exc = exc
        except Exception as exc:
            last_exc = exc
    else:
        # All attempts exhausted
        logger.warning("Vulnrichment fetch failed for %s: %s", cve_id, last_exc)
        return result

    result.available = True
    if cache is not None and cache_key is not None:
        cache.set(cache_key, _to_dict(result), expire=settings.vulnrichment_cache_ttl)

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


def _to_dict(data: VulnrichmentData) -> dict:
    return {
        "cve_id": data.cve_id,
        "in_kev": data.in_kev,
        "kev_date_added": data.kev_date_added,
        "available": data.available,
        "ssvc": {
            "exploitation": data.ssvc.exploitation,
            "automatable": data.ssvc.automatable,
            "technical_impact": data.ssvc.technical_impact,
        },
    }


def _from_dict(cve_id: str, d: dict) -> VulnrichmentData:
    return VulnrichmentData(
        cve_id=cve_id,
        in_kev=d.get("in_kev", False),
        kev_date_added=d.get("kev_date_added"),
        available=d.get("available", False),
        ssvc=SSVCScore(
            exploitation=d.get("ssvc", {}).get("exploitation", "none"),
            automatable=d.get("ssvc", {}).get("automatable", "unknown"),
            technical_impact=d.get("ssvc", {}).get("technical_impact", "unknown"),
        ),
    )
