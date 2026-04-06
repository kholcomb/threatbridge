"""OSV.dev fallback fetcher.

Queries the OSV API (https://api.osv.dev/v1/vulns/{id}) and normalises the
response into a CVERecord.  Used as a fallback when NVD does not have a record
for a given CVE ID (e.g. processing lag, gaps in NVD coverage).

OSV does not provide CPE match data, so cpe_matches is always empty.  CVSS
vectors, CWE IDs, and description are normalised from the OSV response.
"""

from __future__ import annotations

import logging
import time
import threading
import diskcache
import requests
from datetime import datetime, timezone
from typing import Any

from cve_intel.config import settings
from cve_intel.models.cve import CVERecord, CVSSData, CVSSSeverity, Reference

logger = logging.getLogger(__name__)

OSV_BASE_URL = "https://api.osv.dev/v1/vulns"

# Mapping from CVSS vector field abbreviations to full strings used by CVSSData
_AV_MAP = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
_AC_MAP = {"L": "LOW", "H": "HIGH"}
_PR_MAP = {"N": "NONE", "L": "LOW", "H": "HIGH"}
_UI_MAP = {"N": "NONE", "R": "REQUIRED"}
_S_MAP = {"U": "UNCHANGED", "C": "CHANGED"}
_CIA_MAP = {"N": "NONE", "L": "LOW", "H": "HIGH"}


class OSVNotFoundError(Exception):
    pass


class OSVError(Exception):
    pass


class OSVFetcher:
    """Fetches CVE data from OSV.dev and returns a normalised CVERecord."""

    _rate_lock: threading.Lock = threading.Lock()
    _last_request_time: float = 0.0
    _min_interval: float = 0.5  # OSV has generous limits; 0.5s is conservative
    _session: "requests.Session | None" = None
    _session_lock: threading.Lock = threading.Lock()

    @classmethod
    def _throttle(cls) -> None:
        with cls._rate_lock:
            elapsed = time.monotonic() - cls._last_request_time
            wait = cls._min_interval - elapsed
            if wait > 0:
                time.sleep(wait)
            cls._last_request_time = time.monotonic()

    @classmethod
    def _get_session(cls) -> requests.Session:
        if cls._session is None:
            with cls._session_lock:
                if cls._session is None:
                    cls._session = requests.Session()
                    cls._session.headers.update({"User-Agent": "cve-intel/0.1.0"})
        return cls._session

    def __init__(self) -> None:
        self._cache = diskcache.Cache(str(settings.cache_dir / "osv"))

    def fetch(self, cve_id: str, force_refresh: bool = False) -> CVERecord:
        cve_id = cve_id.strip().upper()
        cache_key = f"osv:{cve_id}"
        if not force_refresh:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return CVERecord.model_validate(cached)

        raw = self._fetch_raw(cve_id)
        record = self._parse(raw)
        self._cache.set(cache_key, record.model_dump(mode="json"), expire=settings.cache_ttl_seconds)
        return record

    def _fetch_raw(self, cve_id: str) -> dict[str, Any]:
        self._throttle()
        url = f"{OSV_BASE_URL}/{cve_id}"
        try:
            resp = self._get_session().get(url, timeout=30)
        except requests.RequestException as exc:
            raise OSVError(f"Network error fetching {cve_id} from OSV: {exc}") from exc

        if resp.status_code == 404:
            raise OSVNotFoundError(f"CVE {cve_id} not found in OSV.")
        if not resp.ok:
            raise OSVError(f"OSV returned HTTP {resp.status_code} for {cve_id}: {resp.text[:200]}")

        return resp.json()

    def _parse(self, raw: dict[str, Any]) -> CVERecord:
        cve_id = raw.get("id", "")

        # Description: prefer 'details' (longer), fall back to 'summary'
        description = raw.get("details") or raw.get("summary") or ""

        # Timestamps
        published = _parse_timestamp(raw.get("published"))
        last_modified = _parse_timestamp(raw.get("modified")) or published

        # CVSS
        cvss_list = self._parse_cvss(raw.get("severity", []))

        # CWE IDs — found in database_specific on many OSV entries
        weaknesses = _extract_cwes(raw)

        # References
        references = [
            Reference(url=r.get("url", ""), source="osv", tags=[r.get("type", "").lower()])
            for r in raw.get("references", [])
            if r.get("url")
        ]

        return CVERecord(
            cve_id=cve_id,
            source_identifier="osv.dev",
            published=published or datetime.now(timezone.utc),
            last_modified=last_modified or datetime.now(timezone.utc),
            vuln_status="",
            descriptions={"en": description[:2000]} if description else {},
            cvss=cvss_list,
            weaknesses=weaknesses,
            cpe_matches=[],
            references=references,
        )

    def _parse_cvss(self, severity_list: list[dict]) -> list[CVSSData]:
        result = []
        for entry in severity_list:
            score_str = entry.get("score", "")
            entry_type = entry.get("type", "")
            try:
                cvss_data = _parse_cvss_vector(score_str, entry_type)
                if cvss_data:
                    result.append(cvss_data)
            except Exception:
                logger.debug("Could not parse OSV CVSS vector %r", score_str)
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        from dateutil import parser as dateutil_parser
        return dateutil_parser.parse(value)
    except Exception:
        return None


def _extract_cwes(raw: dict[str, Any]) -> list[str]:
    """Extract CWE IDs from OSV response.  Location varies by data source."""
    cwes: list[str] = []

    # GitHub Advisory Database style: database_specific.cwe_ids
    db_specific = raw.get("database_specific", {})
    for cwe in db_specific.get("cwe_ids", []):
        if isinstance(cwe, str) and cwe.startswith("CWE-"):
            cwes.append(cwe)

    # Some sources embed cwes in affected[].database_specific
    if not cwes:
        for affected in raw.get("affected", []):
            for cwe in affected.get("database_specific", {}).get("cwe_ids", []):
                if isinstance(cwe, str) and cwe.startswith("CWE-"):
                    cwes.append(cwe)

    return list(dict.fromkeys(cwes))  # deduplicate, preserve order


def _parse_cvss_vector(vector: str, entry_type: str) -> CVSSData | None:
    """Parse a CVSS vector string into a CVSSData model."""
    if not vector:
        return None

    # Strip prefix e.g. "CVSS:3.1/"
    raw_vector = vector
    prefix_sep = vector.find("/")
    if prefix_sep != -1 and "CVSS:" in vector[:prefix_sep].upper():
        raw_vector = vector[prefix_sep + 1:]

    # Detect version
    if "CVSS:4" in vector.upper() or entry_type == "CVSS_V4":
        version = "4.0"
    elif "CVSS:3.1" in vector.upper():
        version = "3.1"
    elif "CVSS:3.0" in vector.upper():
        version = "3.0"
    elif entry_type == "CVSS_V3":
        version = "3.1"
    else:
        version = "2.0"

    # Use the cvss library to calculate the base score
    try:
        if version in ("3.0", "3.1"):
            from cvss import CVSS3
            c = CVSS3(vector)
            base_score = float(c.base_score)
        elif version == "4.0":
            # cvss library may not support v4; fall back to vector-only parse
            base_score = _score_from_vector_fields(raw_vector, version)
        else:
            from cvss import CVSS2
            c = CVSS2(vector)
            base_score = float(c.base_score)
    except Exception:
        base_score = _score_from_vector_fields(raw_vector, version)

    severity = _score_to_severity(base_score)

    # Parse individual vector fields
    fields: dict[str, str] = {}
    for part in raw_vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            fields[k] = v

    return CVSSData(
        version=version,
        vector_string=vector,
        base_score=base_score,
        base_severity=severity,
        attack_vector=_AV_MAP.get(fields.get("AV", ""), fields.get("AV")),
        attack_complexity=_AC_MAP.get(fields.get("AC", ""), fields.get("AC")),
        privileges_required=_PR_MAP.get(fields.get("PR", ""), fields.get("PR")),
        user_interaction=_UI_MAP.get(fields.get("UI", ""), fields.get("UI")),
        scope=_S_MAP.get(fields.get("S", ""), fields.get("S")),
        confidentiality_impact=_CIA_MAP.get(fields.get("C", ""), fields.get("C")),
        integrity_impact=_CIA_MAP.get(fields.get("I", ""), fields.get("I")),
        availability_impact=_CIA_MAP.get(fields.get("A", ""), fields.get("A")),
    )


def _score_from_vector_fields(raw_vector: str, version: str) -> float:
    """Fallback: return 0.0 if we can't calculate a score."""
    return 0.0


def _score_to_severity(score: float) -> CVSSSeverity:
    if score == 0.0:
        return CVSSSeverity.NONE
    if score < 4.0:
        return CVSSSeverity.LOW
    if score < 7.0:
        return CVSSSeverity.MEDIUM
    if score < 9.0:
        return CVSSSeverity.HIGH
    return CVSSSeverity.CRITICAL
