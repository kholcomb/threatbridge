"""Health-check logic for `cve-intel doctor`."""

from __future__ import annotations

import importlib.util
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple


class CheckResult(NamedTuple):
    name: str
    status: str  # "PASS" | "WARN" | "FAIL"
    detail: str


_REQUIRED_PACKAGES = [
    "anthropic",
    "mcp",
    "pydantic",
    "requests",
    "diskcache",
    "click",
    "rich",
    "yaml",
    "cvss",
]


def run_checks(full_check: bool = False) -> list[CheckResult]:
    """Run all health checks and return results."""
    results: list[CheckResult] = []
    results.append(_check_anthropic_key(full_check))
    results.append(_check_nvd_key())
    results.extend(_check_cache())
    results.append(_check_attack_bundle())
    results.extend(_check_dependencies())
    results.append(_check_network())
    return results


def _check_anthropic_key(full_check: bool) -> CheckResult:
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        return CheckResult(
            "ANTHROPIC_API_KEY",
            "WARN",
            "Not set — Claude enrichment, IOC extraction, and rule generation disabled.",
        )
    if not full_check:
        masked = key[:8] + "…" + key[-4:] if len(key) > 12 else "****"
        return CheckResult("ANTHROPIC_API_KEY", "PASS", f"Present ({masked})")

    # Live ping
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=key)
        client.models.list()
        return CheckResult("ANTHROPIC_API_KEY", "PASS", "Present and valid (live ping OK)")
    except Exception as exc:
        return CheckResult("ANTHROPIC_API_KEY", "FAIL", f"Key set but API call failed: {exc}")


def _check_nvd_key() -> CheckResult:
    key = os.environ.get("NVD_API_KEY", "")
    if not key:
        return CheckResult(
            "NVD_API_KEY",
            "WARN",
            "Not set — NVD rate-limited to ~5 req/30 s. Set key for 50 req/30 s.",
        )
    masked = key[:8] + "…" + key[-4:] if len(key) > 12 else "****"
    return CheckResult("NVD_API_KEY", "PASS", f"Present ({masked}) — higher rate limit active.")


def _check_cache() -> list[CheckResult]:
    from cve_intel.config import settings

    results: list[CheckResult] = []
    cache_dir = settings.cache_dir

    if not cache_dir.exists():
        results.append(CheckResult("Cache directory", "WARN", f"Does not exist yet: {cache_dir}"))
    elif not os.access(cache_dir, os.W_OK):
        results.append(CheckResult("Cache directory", "FAIL", f"Not writable: {cache_dir}"))
    else:
        size_bytes = sum(
            f.stat().st_size for f in cache_dir.rglob("*") if f.is_file()
        )
        size_mb = size_bytes / (1024 * 1024)
        results.append(
            CheckResult("Cache directory", "PASS", f"{cache_dir}  ({size_mb:.1f} MB)")
        )

    return results


def _check_attack_bundle() -> CheckResult:
    from cve_intel.config import settings

    bundle_path: Path
    if settings.attack_bundle_path and settings.attack_bundle_path.exists():
        bundle_path = settings.attack_bundle_path
    else:
        bundle_path = settings.cache_dir / "attack" / "enterprise-attack.json"

    if not bundle_path.exists():
        return CheckResult(
            "ATT&CK bundle",
            "WARN",
            f"Not downloaded yet — will fetch on first use (~80 MB). Path: {bundle_path}",
        )

    stat = bundle_path.stat()
    size_mb = stat.st_size / (1024 * 1024)
    age_days = (datetime.now(timezone.utc).timestamp() - stat.st_mtime) / 86400

    if age_days > 30:
        return CheckResult(
            "ATT&CK bundle",
            "WARN",
            f"{bundle_path.name}  {size_mb:.0f} MB  age={age_days:.0f} days (consider refreshing)",
        )
    return CheckResult(
        "ATT&CK bundle",
        "PASS",
        f"{bundle_path.name}  {size_mb:.0f} MB  age={age_days:.0f} days",
    )


def _check_dependencies() -> list[CheckResult]:
    results: list[CheckResult] = []
    for pkg in _REQUIRED_PACKAGES:
        spec = importlib.util.find_spec(pkg)
        if spec is None:
            results.append(CheckResult(f"Package: {pkg}", "FAIL", "Not installed"))
        else:
            results.append(CheckResult(f"Package: {pkg}", "PASS", "Installed"))
    return results


def _check_network() -> CheckResult:
    import requests as req

    try:
        resp = req.head("https://services.nvd.nist.gov/", timeout=5)
        return CheckResult(
            "Network (NVD)",
            "PASS" if resp.status_code < 500 else "WARN",
            f"Reachable (HTTP {resp.status_code})",
        )
    except Exception as exc:
        return CheckResult(
            "Network (NVD)",
            "WARN",
            f"Unreachable: {exc}. Cached data may still work.",
        )
