"""SigmaHQ community rule fetcher.

Retrieves existing Sigma rules from the SigmaHQ/sigma repository for a given CVE.
Rules live under rules-emerging-threats/{YEAR}/Exploits/CVE-{YEAR}-{NUM}/.

Used to compare generated rules against community-validated baselines.
"""

from __future__ import annotations

import logging
import re
import time
import urllib.error
import urllib.request
import json
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_API_BASE = "https://api.github.com/repos/SigmaHQ/sigma/contents"
_HEADERS = {
    "User-Agent": "cve-intel/0.1",
    "Accept": "application/vnd.github.v3+json",
}
_TIMEOUT = 10

# Compiled regex patterns (module-level for efficiency)
_RE_LOGSOURCE_BLOCK = re.compile(r'logsource:\s*\n((?:\s+\w[^\n]*\n)+)')
_RE_ATTACK_TAG = re.compile(r'attack\.\w+')
_RE_CVE_TAG = re.compile(r'cve\.\d{4}-\d+')


@dataclass
class CommunityRule:
    filename: str
    rule_text: str
    download_url: str


@dataclass
class SigmaHQResult:
    cve_id: str
    found: bool = False
    rules: list[CommunityRule] = field(default_factory=list)
    directory_url: str = ""

    @property
    def logsources(self) -> list[str]:
        """Extract logsource category/product values from all community rules."""
        results = []
        for rule in self.rules:
            for m in _RE_LOGSOURCE_BLOCK.finditer(rule.rule_text):
                block = m.group(1)
                for line in block.splitlines():
                    if ":" in line:
                        key, _, val = line.partition(":")
                        results.append(f"{key.strip()}: {val.strip()}")
        return results

    @property
    def attack_tags(self) -> list[str]:
        """Extract ATT&CK tags from all community rules."""
        tags = []
        for rule in self.rules:
            tags.extend(_RE_ATTACK_TAG.findall(rule.rule_text))
        return sorted(set(tags))

    @property
    def cve_tags(self) -> list[str]:
        """Extract CVE tags from all community rules."""
        tags = []
        for rule in self.rules:
            tags.extend(_RE_CVE_TAG.findall(rule.rule_text))
        return sorted(set(tags))

    def summary(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "found": self.found,
            "rule_count": len(self.rules),
            "filenames": [r.filename for r in self.rules],
            "logsources": self.logsources,
            "attack_tags": self.attack_tags,
            "cve_tags": self.cve_tags,
            "directory_url": self.directory_url,
        }


_DIR_RETRY_DELAYS = [1, 2]   # backoff for directory listing (3 attempts)
_DIR_MAX_ATTEMPTS = 3
_RULE_MAX_ATTEMPTS = 2       # single retry for individual rule fetches


def fetch_community_rules(cve_id: str) -> SigmaHQResult:
    """Fetch community Sigma rules for a CVE from SigmaHQ.

    Returns a SigmaHQResult with found=False if no rules exist.
    Never raises — network failures return found=False.
    Retries the directory listing up to 3 times on transient errors with
    exponential backoff. Each individual rule fetch gets one retry (2 attempts).
    """
    result = SigmaHQResult(cve_id=cve_id)
    year = cve_id.upper().split("-")[1]
    dir_path = f"rules-emerging-threats/{year}/Exploits/{cve_id.upper()}"
    dir_url = f"{_API_BASE}/{dir_path}"
    result.directory_url = dir_url

    # --- Directory listing with retry ---
    dir_req = urllib.request.Request(dir_url, headers=_HEADERS)
    last_exc: Exception | None = None
    files = None
    for attempt in range(_DIR_MAX_ATTEMPTS):
        if attempt > 0:
            time.sleep(_DIR_RETRY_DELAYS[attempt - 1])
        try:
            with urllib.request.urlopen(dir_req, timeout=_TIMEOUT) as r:
                files = json.loads(r.read())
            last_exc = None
            break  # success
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                # 4xx — definitive answer, no retry
                if exc.code != 404:
                    logger.warning("SigmaHQ directory listing failed for %s: %s", cve_id, exc)
                return result
            last_exc = exc
        except Exception as exc:
            last_exc = exc

    if files is None:
        logger.warning("SigmaHQ directory listing failed for %s: %s", cve_id, last_exc)
        return result

    yml_files = [f for f in files if f.get("name", "").endswith(".yml")]
    if not yml_files:
        return result

    result.found = True
    for file_meta in yml_files:
        dl_url = file_meta.get("download_url", "")
        if not dl_url:
            continue

        # --- Individual rule fetch with single retry ---
        rule_req = urllib.request.Request(dl_url, headers={"User-Agent": "cve-intel/0.1"})
        rule_last_exc: Exception | None = None
        rule_text: str | None = None
        for attempt in range(_RULE_MAX_ATTEMPTS):
            if attempt > 0:
                time.sleep(1)
            try:
                with urllib.request.urlopen(rule_req, timeout=_TIMEOUT) as r:
                    rule_text = r.read().decode()
                rule_last_exc = None
                break  # success
            except urllib.error.HTTPError as exc:
                if exc.code < 500:
                    if exc.code != 404:
                        logger.warning(
                            "SigmaHQ rule fetch failed for %s (%s): %s", cve_id, dl_url, exc
                        )
                    rule_last_exc = None  # definitive, don't log again below
                    break
                rule_last_exc = exc
            except Exception as exc:
                rule_last_exc = exc

        if rule_text is None:
            if rule_last_exc is not None:
                logger.warning(
                    "SigmaHQ rule fetch failed for %s (%s): %s", cve_id, dl_url, rule_last_exc
                )
            continue

        result.rules.append(CommunityRule(
            filename=file_meta["name"],
            rule_text=rule_text,
            download_url=dl_url,
        ))

    return result


def compare_with_community(generated_rule_text: str, community: SigmaHQResult) -> dict:
    """Compare a generated Sigma rule against community rules.

    Returns a comparison dict highlighting key differences.
    """
    import yaml

    if not community.found:
        return {
            "community_available": False,
            "note": "No community rule found for this CVE in SigmaHQ/sigma.",
        }

    # Parse generated rule
    try:
        gen_doc = yaml.safe_load(generated_rule_text) or {}
    except Exception:
        gen_doc = {}

    gen_logsource = gen_doc.get("logsource", {})
    gen_tags = [t for t in gen_doc.get("tags", []) if t.startswith("attack.")]
    gen_level = gen_doc.get("level", "unknown")

    comparisons = []
    for crule in community.rules:
        try:
            com_doc = yaml.safe_load(crule.rule_text) or {}
        except Exception:
            com_doc = {}

        com_logsource = com_doc.get("logsource", {})
        com_tags = [t for t in com_doc.get("tags", []) if t.startswith("attack.")]
        com_level = com_doc.get("level", "unknown")

        # Check logsource alignment
        logsource_match = (
            gen_logsource.get("category") == com_logsource.get("category")
            and gen_logsource.get("product") == com_logsource.get("product")
        )

        # ATT&CK tag overlap
        gen_tag_set = set(gen_tags)
        com_tag_set = set(com_tags)
        shared_tags = gen_tag_set & com_tag_set
        missing_tags = com_tag_set - gen_tag_set
        extra_tags = gen_tag_set - com_tag_set

        comparisons.append({
            "community_filename": crule.filename,
            "logsource_match": logsource_match,
            "generated_logsource": gen_logsource,
            "community_logsource": com_logsource,
            "shared_attack_tags": sorted(shared_tags),
            "missing_attack_tags": sorted(missing_tags),
            "extra_attack_tags": sorted(extra_tags),
            "generated_level": gen_level,
            "community_level": com_level,
            "level_match": gen_level == com_level,
        })

    return {
        "community_available": True,
        "community_rule_count": len(community.rules),
        "comparisons": comparisons,
    }
