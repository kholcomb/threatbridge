"""NVD REST API v2 client with caching and rate limiting."""

from __future__ import annotations

import logging
import re
import diskcache
import requests
from datetime import datetime
from typing import Any
from dateutil import parser as dateutil_parser

logger = logging.getLogger(__name__)

from cve_intel.config import settings
from cve_intel.models.cve import CVERecord, CVSSData, CVSSSeverity, CPEMatch, Reference

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CVE_ID_PATTERN = CVE_PATTERN  # Alias for external consumers


class NVDError(Exception):
    pass


class NVDNotFoundError(NVDError):
    pass


class NVDRateLimitError(NVDError):
    pass


class NVDFetcher:
    def __init__(self) -> None:
        self._cache = diskcache.Cache(str(settings.cache_dir / "nvd"))
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "cve-intel/0.1.0"})

    def validate_cve_id(self, cve_id: str) -> str:
        cve_id = cve_id.strip().upper()
        if not CVE_PATTERN.match(cve_id):
            raise ValueError(f"Invalid CVE ID format: {cve_id!r}. Expected CVE-YYYY-NNNN.")
        return cve_id

    def fetch(self, cve_id: str) -> CVERecord:
        cve_id = self.validate_cve_id(cve_id)
        cache_key = f"nvd:{cve_id}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return CVERecord.model_validate(cached)

        raw = self._fetch_raw(cve_id)
        record = self._parse(raw)
        self._cache.set(cache_key, record.model_dump(mode="json"), expire=settings.cache_ttl_seconds)
        return record

    def _fetch_raw(self, cve_id: str) -> dict[str, Any]:
        params: dict[str, str] = {"cveId": cve_id}
        headers: dict[str, str] = {}
        if settings.has_nvd_key:
            headers["apiKey"] = settings.nvd_api_key

        try:
            resp = self._session.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
        except requests.RequestException as exc:
            raise NVDError(f"Network error fetching {cve_id}: {exc}") from exc

        if resp.status_code == 404:
            raise NVDNotFoundError(f"CVE {cve_id} not found in NVD.")
        if resp.status_code == 403:
            raise NVDRateLimitError("NVD rate limit exceeded. Add NVD_API_KEY or wait 30 seconds.")
        if resp.status_code == 503:
            raise NVDError("NVD API is unavailable (503). Try again later.")
        if not resp.ok:
            raise NVDError(f"NVD returned HTTP {resp.status_code} for {cve_id}: {resp.text[:200]}")

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            raise NVDNotFoundError(f"CVE {cve_id} not found in NVD response.")
        return vulns[0]["cve"]

    def _parse(self, raw: dict) -> CVERecord:
        cve_id = raw["id"]

        descriptions: dict[str, str] = {
            d["lang"]: d["value"]
            for d in raw.get("descriptions", [])
        }

        weaknesses: list[str] = []
        for w in raw.get("weaknesses", []):
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    weaknesses.append(val)

        cvss_list = self._parse_cvss(raw.get("metrics", {}))
        cpe_matches = self._parse_cpe(raw.get("configurations", []))
        references = [
            Reference(
                url=r.get("url", ""),
                source=r.get("source", ""),
                tags=r.get("tags", []),
            )
            for r in raw.get("references", [])
        ]

        return CVERecord(
            cve_id=cve_id,
            source_identifier=raw.get("sourceIdentifier", ""),
            published=dateutil_parser.parse(raw["published"]),
            last_modified=dateutil_parser.parse(raw["lastModified"]),
            vuln_status=raw.get("vulnStatus", ""),
            descriptions=descriptions,
            cvss=cvss_list,
            weaknesses=list(dict.fromkeys(weaknesses)),
            cpe_matches=cpe_matches,
            references=references,
        )

    def _parse_cvss(self, metrics: dict) -> list[CVSSData]:
        result: list[CVSSData] = []

        # CVSSv4.0
        for m in metrics.get("cvssMetricV40", []):
            d = m.get("cvssData", {})
            result.append(self._build_cvss(d, "4.0"))

        # CVSSv3.1
        for m in metrics.get("cvssMetricV31", []):
            d = m.get("cvssData", {})
            result.append(self._build_cvss(d, "3.1"))

        # CVSSv3.0
        for m in metrics.get("cvssMetricV30", []):
            d = m.get("cvssData", {})
            result.append(self._build_cvss(d, "3.0"))

        # CVSSv2
        for m in metrics.get("cvssMetricV2", []):
            d = m.get("cvssData", {})
            result.append(self._build_cvss(d, "2.0"))

        return result

    def _build_cvss(self, d: dict, version: str) -> CVSSData:
        severity_raw = d.get("baseSeverity") or d.get("baseScore", "")
        if isinstance(severity_raw, (int, float)):
            score = float(severity_raw)
            if score == 0:
                severity = CVSSSeverity.NONE
            elif score < 4:
                severity = CVSSSeverity.LOW
            elif score < 7:
                severity = CVSSSeverity.MEDIUM
            elif score < 9:
                severity = CVSSSeverity.HIGH
            else:
                severity = CVSSSeverity.CRITICAL
        else:
            try:
                severity = CVSSSeverity(str(severity_raw).upper())
            except ValueError:
                logger.warning(
                    "Unrecognized CVSS severity %r, defaulting to MEDIUM", severity_raw
                )
                severity = CVSSSeverity.MEDIUM

        return CVSSData(
            version=version,
            vector_string=d.get("vectorString", ""),
            base_score=float(d.get("baseScore", 0.0)),
            base_severity=severity,
            attack_vector=d.get("attackVector"),
            attack_complexity=d.get("attackComplexity"),
            privileges_required=d.get("privilegesRequired"),
            user_interaction=d.get("userInteraction"),
            scope=d.get("scope"),
            confidentiality_impact=d.get("confidentialityImpact"),
            integrity_impact=d.get("integrityImpact"),
            availability_impact=d.get("availabilityImpact"),
        )

    def _parse_cpe(self, configurations: list) -> list[CPEMatch]:
        matches: list[CPEMatch] = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    matches.append(CPEMatch(
                        criteria=cpe_match.get("criteria", ""),
                        version_start_including=cpe_match.get("versionStartIncluding"),
                        version_end_excluding=cpe_match.get("versionEndExcluding"),
                        version_end_including=cpe_match.get("versionEndIncluding"),
                        vulnerable=cpe_match.get("vulnerable", True),
                    ))
        return matches
