"""CVE record resolver with multi-source fallback chain.

Tries data sources in priority order and returns the first successful result:
  1. NVD (National Vulnerability Database) — primary, most complete CPE data
  2. OSV.dev — broader coverage, faster updates, no API key required

Usage:
    from cve_intel.fetchers.resolver import fetch_cve_record

    record = fetch_cve_record("CVE-2024-3400")
    record = fetch_cve_record("CVE-2024-3400", force_refresh=True)
"""

from __future__ import annotations

import logging

from cve_intel.fetchers.nvd import NVDFetcher, NVDNotFoundError, NVDError
from cve_intel.fetchers.osv import OSVFetcher, OSVNotFoundError, OSVError
from cve_intel.models.cve import CVERecord

logger = logging.getLogger(__name__)


def fetch_cve_record(cve_id: str, force_refresh: bool = False) -> CVERecord:
    """Fetch a CVE record, falling back to OSV.dev if NVD does not have it.

    Raises:
        NVDError / OSVError: if both sources fail with a non-404 error.
        OSVNotFoundError: if the CVE is not found in either source.
    """
    try:
        return NVDFetcher().fetch(cve_id, force_refresh=force_refresh)
    except NVDNotFoundError:
        # Retry once — NVD occasionally returns transient 404s that are not
        # genuine "CVE does not exist" responses.  A second attempt catches
        # these without masking truly missing CVEs.
        try:
            return NVDFetcher().fetch(cve_id, force_refresh=True)
        except NVDNotFoundError:
            logger.info("CVE %s not found in NVD after retry — trying OSV.dev fallback", cve_id)

    try:
        record = OSVFetcher().fetch(cve_id, force_refresh=force_refresh)
        logger.info("CVE %s resolved via OSV.dev fallback", cve_id)
        return record
    except OSVNotFoundError:
        raise OSVNotFoundError(
            f"CVE {cve_id} not found in NVD or OSV.dev."
        )
    except OSVError as exc:
        raise OSVError(
            f"CVE {cve_id} not found in NVD; OSV.dev fallback failed: {exc}"
        ) from exc
