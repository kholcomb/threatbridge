"""MITRE ATT&CK STIX bundle loader with auto-download and caching."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Callable

import requests

logger = logging.getLogger(__name__)

from cve_intel.config import settings
from cve_intel.models.attack import AttackTechnique, AttackTactic

ATTACK_VERSION = "ATT&CK-v18.1"
_TAG = ATTACK_VERSION.replace("&", "%26")
ENTERPRISE_ATTACK_URL = (
    f"https://raw.githubusercontent.com/mitre/cti/{_TAG}/"
    "enterprise-attack/enterprise-attack.json"
)


class AttackDataError(Exception):
    pass


class AttackData:
    """Wrapper around MITRE ATT&CK STIX data providing technique lookups."""

    def __init__(self, bundle_path: Path) -> None:
        self._path = bundle_path
        self._techniques: dict[str, AttackTechnique] = {}
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise AttackDataError(f"Failed to load ATT&CK bundle from {self._path}: {exc}") from exc

        objects = raw.get("objects", [])
        tactic_map = self._build_tactic_map(objects)
        self._techniques = self._build_technique_map(objects, tactic_map)

    def _build_tactic_map(self, objects: list[dict]) -> dict[str, AttackTactic]:
        tactics: dict[str, AttackTactic] = {}
        for obj in objects:
            if obj.get("type") != "x-mitre-tactic":
                continue
            tactic_id = self._get_external_id(obj)
            if tactic_id:
                tactics[obj.get("x_mitre_shortname", "")] = AttackTactic(
                    tactic_id=tactic_id,
                    name=obj.get("name", ""),
                    shortname=obj.get("x_mitre_shortname", ""),
                )
        return tactics

    def _build_technique_map(
        self, objects: list[dict], tactic_map: dict[str, AttackTactic]
    ) -> dict[str, AttackTechnique]:
        techniques: dict[str, AttackTechnique] = {}
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue

            tech_id = self._get_external_id(obj)
            if not tech_id:
                continue

            is_sub = "." in tech_id
            parent_id = tech_id.split(".")[0] if is_sub else None

            kill_chain_phases = obj.get("kill_chain_phases", [])
            tactic_list = [
                tactic_map[phase["phase_name"]]
                for phase in kill_chain_phases
                if phase.get("kill_chain_name") == "mitre-attack"
                and phase.get("phase_name") in tactic_map
            ]

            platforms = obj.get("x_mitre_platforms", [])
            data_sources = obj.get("x_mitre_data_sources", [])
            detection = obj.get("x_mitre_detection", "")
            description = obj.get("description", "")

            url = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    url = ref.get("url", "")
                    break

            techniques[tech_id] = AttackTechnique(
                technique_id=tech_id,
                name=obj.get("name", ""),
                description=description,
                is_subtechnique=is_sub,
                parent_id=parent_id,
                tactics=tactic_list,
                platforms=platforms,
                data_sources=data_sources,
                detection_notes=detection,
                url=url,
            )

        return techniques

    def _get_external_id(self, obj: dict) -> str | None:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    def get_technique(self, technique_id: str) -> AttackTechnique | None:
        return self._techniques.get(technique_id)

    def get_techniques_by_ids(self, ids: list[str]) -> list[AttackTechnique]:
        result = []
        for tid in ids:
            tech = self._techniques.get(tid)
            if tech:
                result.append(tech)
        return result

    @property
    def all_technique_ids(self) -> list[str]:
        return list(self._techniques.keys())


_CACHED_ATTACK_DATA: "AttackData | None" = None
_CACHE_LOCK = threading.Lock()


def get_attack_data(
    progress_callback: "Callable[[int, int], None] | None" = None,
) -> AttackData:
    """Return an AttackData instance, downloading the bundle if needed.

    Caches the parsed data at module level so the 80 MB bundle is only
    loaded and parsed once per process. Thread-safe via a module-level lock.

    Args:
        progress_callback: Optional ``(bytes_written, total_bytes)`` callable
            called during download for progress reporting.
    """
    global _CACHED_ATTACK_DATA
    if _CACHED_ATTACK_DATA is not None:
        return _CACHED_ATTACK_DATA
    with _CACHE_LOCK:
        # Re-check inside the lock — another thread may have populated it.
        if _CACHED_ATTACK_DATA is not None:
            return _CACHED_ATTACK_DATA
        bundle_path = _resolve_bundle_path()
        if not bundle_path.exists():
            _download_bundle(bundle_path, progress_callback=progress_callback)
        _CACHED_ATTACK_DATA = AttackData(bundle_path)
    return _CACHED_ATTACK_DATA


def _resolve_bundle_path() -> Path:
    if settings.attack_bundle_path and settings.attack_bundle_path.exists():
        return settings.attack_bundle_path
    cache_dir = settings.cache_dir / "attack"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "enterprise-attack.json"


def _download_bundle(
    dest: Path,
    progress_callback: Callable[[int, int], None] | None = None,
) -> None:
    logger.info("Downloading MITRE ATT&CK STIX bundle to %s (~80 MB)...", dest)
    try:
        resp = requests.get(ENTERPRISE_ATTACK_URL, timeout=120, stream=True)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise AttackDataError(f"Failed to download ATT&CK bundle: {exc}") from exc

    total = int(resp.headers.get("content-length", 0))
    dest.parent.mkdir(parents=True, exist_ok=True)
    bytes_written = 0
    try:
        with dest.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=65536):
                f.write(chunk)
                bytes_written += len(chunk)
                if progress_callback is not None:
                    progress_callback(bytes_written, total)
    except Exception:
        dest.unlink(missing_ok=True)
        raise
    logger.info("ATT&CK bundle downloaded.")
