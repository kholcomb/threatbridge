"""Parsers for standardized scanner output formats: SARIF 2.1.0 and CycloneDX JSON.

Produces ScannerFinding objects — lightweight tuples of (cve_id, package,
installed_version, fixed_version) — that feed into the batch triage pipeline
and enrich SARIF/VEX output with package-level context.

Supported input formats
-----------------------
SARIF 2.1.0  — output of Grype (--output sarif), Trivy (--format sarif),
               Snyk (--sarif), Semgrep, CodeQL, Dependabot.
CycloneDX    — output of Grype (--output cyclonedx), Trivy (--format cyclonedx),
               cdxgen, syft, and SBOM-first pipelines.

Auto-detection
--------------
pass fmt="auto" (default) to detect the format from the document structure:
  SARIF     → top-level "version" in ("2.1.0", "2.0") AND "runs" array
  CycloneDX → top-level "bomFormat" == "CycloneDX"
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)


@dataclass
class ScannerFinding:
    """A single vulnerability finding extracted from a scanner report."""
    cve_id: str
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    ecosystem: str | None = None   # "maven", "npm", "pypi", etc. from pURL


@dataclass
class VexDecision:
    """A single applicability decision from a CycloneDX VEX document."""
    cve_id: str
    state: str           # "affected" | "not_affected" | "fixed" | "under_investigation"
    justification: str | None = None
    detail: str | None = None
    raw: dict | None = None   # original VEX vulnerability object, preserved verbatim


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_vex(path: Path) -> list[VexDecision]:
    """Load a CycloneDX VEX document and return all vulnerability decisions.

    Used with --vex-in to carry forward prior triage decisions.
    Only not_affected entries are used for suppression; all entries are
    returned so the caller can reconstruct the full prior state.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    return parse_vex(data)


def parse_vex(data: dict) -> list[VexDecision]:
    """Extract vulnerability decisions from a CycloneDX VEX document.

    Preserves the raw vulnerability object so not_affected entries can be
    written verbatim into subsequent VEX output without loss of team annotations.
    """
    decisions: list[VexDecision] = []
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("id", "")
        if not _is_cve(cve_id):
            continue
        analysis = vuln.get("analysis", {})
        decisions.append(VexDecision(
            cve_id=cve_id.upper(),
            state=analysis.get("state", "under_investigation"),
            justification=analysis.get("justification"),
            detail=analysis.get("detail"),
            raw=vuln,
        ))
    return decisions


def load_findings(path: Path, fmt: str = "auto") -> list[ScannerFinding]:
    """Load and parse a scanner report, returning deduplicated ScannerFindings.

    Args:
        path: Path to the scanner report file.
        fmt:  'sarif' | 'cyclonedx' | 'auto' (default — detect from content).

    Raises:
        ValueError: if fmt='auto' and the format cannot be detected.
        json.JSONDecodeError: if the file is not valid JSON.
    """
    data = json.loads(path.read_text(encoding="utf-8"))

    if fmt == "auto":
        fmt = detect_format(data)

    if fmt == "sarif":
        return parse_sarif(data)
    if fmt == "cyclonedx":
        return parse_cyclonedx(data)
    raise ValueError(f"Unknown format {fmt!r}. Use 'sarif', 'cyclonedx', or 'auto'.")


def detect_format(data: dict) -> str:
    """Return 'sarif' or 'cyclonedx', or raise ValueError if unrecognised."""
    if "runs" in data and data.get("version") in ("2.1.0", "2.0"):
        return "sarif"
    if data.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    raise ValueError(
        "Unrecognised scanner report format. "
        "Expected SARIF 2.1.0 (has 'version' + 'runs') "
        "or CycloneDX JSON (has 'bomFormat': 'CycloneDX'). "
        "For a plain CVE ID list, use --from ids."
    )


def parse_sarif(data: dict) -> list[ScannerFinding]:
    """Extract CVE findings from a SARIF 2.1.0 document.

    Handles output from Grype, Trivy, Snyk, Semgrep, CodeQL, and Dependabot.
    CVE ID is read from result.ruleId. Package and version are extracted from
    logicalLocations. Fix version is sourced from (in order of preference):
      1. result.properties.fix-version / fixedVersion
      2. rule.properties.fix-version (Grype stores it here)
      3. message.text pattern "Fixed Version: X.Y.Z" (Trivy)
    """
    # Index fix versions from the rules array (Grype puts them here)
    fix_by_rule: dict[str, str] = {}
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            rid = rule.get("id", "")
            if _is_cve(rid):
                fv = (
                    rule.get("properties", {}).get("fix-version")
                    or rule.get("properties", {}).get("fixedVersion")
                    or rule.get("properties", {}).get("fixed_version")
                )
                if fv:
                    fix_by_rule[rid.upper()] = str(fv)

    findings: dict[str, ScannerFinding] = {}

    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")

            if not _is_cve(rule_id):
                # ruleId may be a tool-internal ID — try extracting CVE from message
                match = _CVE_RE.search(result.get("message", {}).get("text", ""))
                if match:
                    rule_id = match.group(0)
                else:
                    continue

            cve_id = rule_id.upper()

            # Package name + installed version from logicalLocations
            package, installed_version = _package_from_sarif_locations(
                result.get("locations", [])
            )

            # Fix version: result properties → rule index → message text
            fixed_version = (
                result.get("properties", {}).get("fix-version")
                or result.get("properties", {}).get("fixedVersion")
                or result.get("properties", {}).get("fixed_version")
                or fix_by_rule.get(cve_id)
                or _fixed_version_from_message(result.get("message", {}).get("text", ""))
            )
            if fixed_version:
                fixed_version = str(fixed_version)

            # Keep the richer finding if we've already seen this CVE
            existing = findings.get(cve_id)
            if existing is None or (package and not existing.package):
                findings[cve_id] = ScannerFinding(
                    cve_id=cve_id,
                    package=package,
                    installed_version=installed_version,
                    fixed_version=fixed_version or (existing.fixed_version if existing else None),
                )

    return list(findings.values())


def parse_cyclonedx(data: dict) -> list[ScannerFinding]:
    """Extract CVE findings from a CycloneDX JSON document (spec 1.4+).

    CVE ID from vulnerabilities[].id. Package from affects[].ref (pURL).
    Fix version from the recommendation field or advisories.
    """
    findings: dict[str, ScannerFinding] = {}

    for vuln in data.get("vulnerabilities", []):
        vuln_id = vuln.get("id", "")
        if not _is_cve(vuln_id):
            continue

        cve_id = vuln_id.upper()

        # First affects entry — pURL: pkg:maven/group/artifact@version
        package = installed_version = ecosystem = None
        for affect in vuln.get("affects", [])[:1]:
            package, installed_version, ecosystem = _parse_purl(affect.get("ref", ""))

        # Fix version from recommendation text or advisories
        fixed_version = _fixed_version_from_recommendation(vuln.get("recommendation", ""))
        if not fixed_version:
            for advisory in vuln.get("advisories", []):
                fv = _fixed_version_from_recommendation(advisory.get("title", ""))
                if fv:
                    fixed_version = fv
                    break

        findings[cve_id] = ScannerFinding(
            cve_id=cve_id,
            package=package,
            installed_version=installed_version,
            fixed_version=fixed_version,
            ecosystem=ecosystem,
        )

    return list(findings.values())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_cve(s: str) -> bool:
    return bool(s and _CVE_RE.fullmatch(s.strip()))


def _package_from_sarif_locations(locations: list) -> tuple[str | None, str | None]:
    """Extract (package, installed_version) from a SARIF locations array."""
    for loc in locations:
        for ll in loc.get("logicalLocations", []):
            fqn = ll.get("fullyQualifiedName", "")
            name = ll.get("name", "")
            if fqn:
                # "log4j-core:2.14.1" or "log4j-core:2.14.1 (java)"
                parts = fqn.split(":")
                if len(parts) >= 2:
                    return parts[0].strip(), parts[1].split()[0].strip()
                return fqn.strip(), None
            if name:
                return name, None
    return None, None


def _fixed_version_from_message(text: str) -> str | None:
    """Extract 'Fixed Version: X.Y.Z' from Trivy-style SARIF message text."""
    match = re.search(r'[Ff]ix(?:ed)?\s*[Vv]ersion[:\s]+([^\s\n]+)', text)
    return match.group(1) if match else None


def _fixed_version_from_recommendation(text: str) -> str | None:
    """Extract version from 'Upgrade to X.Y.Z' style CycloneDX recommendation text."""
    match = re.search(r'[Uu]pgrade\s+to\s+([0-9][^\s,;]+)', text)
    return match.group(1) if match else None


def _parse_purl(ref: str) -> tuple[str | None, str | None, str | None]:
    """Parse a pURL into (name, version, ecosystem).

    Examples:
      pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1  → log4j-core, 2.14.1, maven
      pkg:npm/%40angular/core@14.0.0                         → core, 14.0.0, npm
      pkg:pypi/django@3.2.0                                  → django, 3.2.0, pypi
    """
    match = re.match(r'pkg:([^/]+)/(?:[^/]+/)?([^@\?#]+)@([^\?#]+)', ref)
    if match:
        return match.group(2), match.group(3), match.group(1)
    return None, None, None
