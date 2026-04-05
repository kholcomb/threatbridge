"""JSON output renderer."""

import json
from pathlib import Path

from cve_intel.models.rules import AnalysisResult


def render_json(result: AnalysisResult, indent: int = 2) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=indent, default=str)


def write_json(result: AnalysisResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    dest = output_dir / f"{result.cve_id}.json"
    dest.write_text(render_json(result), encoding="utf-8")
    return dest


def write_rules(result: AnalysisResult, output_dir: Path) -> list[Path]:
    """Write individual rule files to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for rule in result.rule_bundle.sigma_rules:
        p = output_dir / f"{result.cve_id}_sigma_{rule.rule_id[:8]}.yml"
        p.write_text(rule.rule_text, encoding="utf-8")
        written.append(p)

    for rule in result.rule_bundle.yara_rules:
        p = output_dir / f"{result.cve_id}_yara_{rule.rule_id[:8]}.yar"
        p.write_text(rule.rule_text, encoding="utf-8")
        written.append(p)

    for rule in result.rule_bundle.snort_rules:
        p = output_dir / f"{result.cve_id}_snort_{rule.rule_id[:8]}.rules"
        p.write_text(rule.rule_text, encoding="utf-8")
        written.append(p)

    return written
