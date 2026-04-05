"""CLI entry point for cve-intel."""

import sys
from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option(package_name="cve-intel")
def cli() -> None:
    """CVE Threat Intelligence System.

    Maps CVEs to ATT&CK techniques, extracts IOCs, and generates detection rules.
    """


@cli.command()
@click.argument("cve_id")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output directory (writes JSON + rule files).")
@click.option("--format", "-f", "fmt", type=click.Choice(["text", "json", "both"]),
              default="both", show_default=True,
              help="Output format.")
@click.option("--rules", "-r", default="sigma,yara,snort", show_default=True,
              help="Comma-separated list of rule formats to generate.")
@click.option("--no-enrich", "no_enrich", is_flag=True, default=False,
              help="Skip Claude enrichment (deterministic only, no API key needed).")
@click.option("--batch", type=click.Path(exists=True), default=None,
              help="Path to file with newline-separated CVE IDs for batch processing.")
def analyze(
    cve_id: str,
    output: str | None,
    fmt: str,
    rules: str,
    no_enrich: bool,
    batch: str | None,
) -> None:
    """Run full analysis pipeline on a CVE ID."""
    from cve_intel import pipeline
    from cve_intel.output import json_renderer, text_renderer
    from cve_intel.fetchers.attack_data import get_attack_data

    rule_formats = set(r.strip().lower() for r in rules.split(",") if r.strip())
    enrich = not no_enrich
    output_dir = Path(output) if output else None

    if batch:
        cve_ids = [line.strip() for line in Path(batch).read_text().splitlines() if line.strip()]
    else:
        cve_ids = [cve_id]

    # Pre-load ATT&CK data once for batch
    console.print("[dim]Loading ATT&CK data...[/dim]")
    try:
        attack_data = get_attack_data()
    except Exception as exc:
        console.print(f"[red]Failed to load ATT&CK data: {exc}[/red]")
        sys.exit(1)

    for cid in cve_ids:
        console.print(f"\n[bold cyan]Analyzing {cid}...[/bold cyan]")
        try:
            result = pipeline.analyze(
                cve_id=cid,
                enrich=enrich,
                rule_formats=rule_formats,
                attack_data=attack_data,
            )
        except Exception as exc:
            console.print(f"[red]Error analyzing {cid}: {exc}[/red]")
            if len(cve_ids) == 1:
                sys.exit(1)
            continue

        if fmt in ("text", "both"):
            text_renderer.render_text(result)

        if fmt in ("json", "both") and output_dir:
            path = json_renderer.write_json(result, output_dir)
            console.print(f"[dim]JSON written to {path}[/dim]")
            rule_paths = json_renderer.write_rules(result, output_dir / "rules")
            for rp in rule_paths:
                console.print(f"[dim]Rule written to {rp}[/dim]")
        elif fmt == "json" and not output_dir:
            click.echo(json_renderer.render_json(result))


@cli.command()
@click.argument("cve_id")
def fetch(cve_id: str) -> None:
    """Fetch and display raw CVE record from NVD."""
    from cve_intel.fetchers.nvd import NVDFetcher
    import json

    try:
        record = NVDFetcher().fetch(cve_id)
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    click.echo(json.dumps(record.model_dump(mode="json"), indent=2, default=str))


@cli.command()
@click.argument("cve_id")
@click.option("--no-enrich", "no_enrich", is_flag=True, default=False)
def map(cve_id: str, no_enrich: bool) -> None:
    """Map CVE to ATT&CK techniques."""
    from cve_intel import pipeline

    try:
        result = pipeline.analyze(cve_id, enrich=not no_enrich, rule_formats=set())
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    m = result.attack_mapping
    console.print(f"\n[bold yellow]ATT&CK Mapping for {cve_id}[/bold yellow]")
    console.print(f"Method: {m.mapping_method}")
    console.print(f"Rationale: {m.rationale}\n")
    for t in m.techniques:
        console.print(f"  {t.technique_id:12} {t.name:40} conf={t.confidence:.0%}")


@cli.command()
@click.argument("cve_id")
def iocs(cve_id: str) -> None:
    """Extract and display IOCs for a CVE."""
    from cve_intel import pipeline

    try:
        result = pipeline.analyze(cve_id, enrich=True, rule_formats=set())
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    bundle = result.ioc_bundle
    all_iocs = bundle.all_iocs()
    console.print(f"\n[bold magenta]IOCs for {cve_id} ({len(all_iocs)} total)[/bold magenta]\n")
    for ioc in all_iocs:
        console.print(f"  [{ioc.ioc_type.value}] {ioc.value} [{ioc.confidence.value}] — {ioc.context}")


@cli.command()
@click.argument("cve_id")
@click.option("--rules", "-r", default="sigma,yara,snort")
@click.option("--output", "-o", type=click.Path(), default=None)
def rules_cmd(cve_id: str, rules: str, output: str | None) -> None:
    """Generate detection rules for a CVE."""
    from cve_intel import pipeline
    from cve_intel.output import json_renderer

    rule_formats = set(r.strip().lower() for r in rules.split(",") if r.strip())
    try:
        result = pipeline.analyze(cve_id, enrich=True, rule_formats=rule_formats)
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    all_rules = result.rule_bundle.all_rules()
    console.print(f"\n[bold green]{len(all_rules)} rules generated for {cve_id}[/bold green]\n")

    if output:
        out = Path(output)
        paths = json_renderer.write_rules(result, out)
        for p in paths:
            console.print(f"  Written: {p}")
    else:
        for rule in all_rules:
            console.print(f"\n[bold]--- {rule.rule_format.value.upper()}: {rule.name} ---[/bold]")
            click.echo(rule.rule_text)


# Register rules command under its correct name
cli.add_command(rules_cmd, name="rules")


@cli.group()
def cache() -> None:
    """Manage local cache."""


@cache.command("clear")
def cache_clear() -> None:
    """Clear the NVD response cache."""
    import diskcache
    from cve_intel.config import settings

    cache_path = settings.cache_dir / "nvd"
    with diskcache.Cache(str(cache_path)) as c:
        count = len(c)
        c.clear()
    console.print(f"[green]Cleared {count} cached NVD entries.[/green]")


@cache.command("stats")
def cache_stats() -> None:
    """Show cache statistics."""
    import diskcache
    from cve_intel.config import settings

    cache_path = settings.cache_dir / "nvd"
    with diskcache.Cache(str(cache_path)) as c:
        console.print(f"NVD cache entries: {len(c)}")
        console.print(f"NVD cache size: {c.volume() / 1024:.1f} KB")
