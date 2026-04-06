"""Rich terminal output renderer."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.text import Text
from rich import box

from cve_intel.models.rules import AnalysisResult

console = Console()


def render_text(result: AnalysisResult) -> None:
    cve = result.cve_record
    mapping = result.attack_mapping
    iocs = result.ioc_bundle
    rules = result.rule_bundle

    # Header
    cvss = cve.primary_cvss
    severity_color = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "NONE": "dim",
    }.get(cvss.base_severity.value if cvss else "NONE", "white")

    header = Text()
    header.append(f"{cve.cve_id}", style="bold cyan")
    if cvss:
        header.append(f"  [{cvss.base_score} {cvss.base_severity.value}]", style=severity_color)
    header.append(f"\n{cve.description_en[:300]}{'...' if len(cve.description_en) > 300 else ''}")

    console.print(Panel(header, title="CVE Overview", border_style="cyan"))

    # CVE Details
    details_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    details_table.add_column("Field", style="bold")
    details_table.add_column("Value")
    details_table.add_row("Published", str(cve.published.date()))
    details_table.add_row("Status", cve.vuln_status)
    details_table.add_row("CWEs", ", ".join(cve.weaknesses) or "—")
    details_table.add_row("Products", ", ".join(cve.affected_products[:5]) or "—")
    if cvss:
        details_table.add_row("CVSS Vector", cvss.vector_string)
    console.print(details_table)

    # Exploitation Context (Vulnrichment)
    vuln_meta = result.metadata.get("vulnrichment", {})
    if vuln_meta:
        exploit_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        exploit_table.add_column("Field", style="bold")
        exploit_table.add_column("Value")

        kev_text = Text("YES — Known Exploited Vulnerability", style="bold red") if vuln_meta.get("in_kev") else Text("No", style="dim")
        exploit_table.add_row("CISA KEV", kev_text)
        if vuln_meta.get("kev_date_added"):
            exploit_table.add_row("KEV Added", vuln_meta["kev_date_added"])

        exploitation = vuln_meta.get("ssvc_exploitation", "unknown")
        exploit_style = "bold red" if exploitation == "active" else "yellow" if exploitation == "poc" else "dim"
        exploit_table.add_row("SSVC Exploitation", Text(exploitation, style=exploit_style))
        exploit_table.add_row("SSVC Automatable", vuln_meta.get("ssvc_automatable", "unknown"))
        exploit_table.add_row("SSVC Impact", vuln_meta.get("ssvc_technical_impact", "unknown"))

        console.print(Panel(exploit_table, title="Exploitation Context", border_style="red"))

    # ATT&CK Mapping
    if mapping.techniques:
        atk_table = Table(title="ATT&CK Techniques", box=box.ROUNDED, border_style="yellow")
        atk_table.add_column("ID", style="bold yellow", width=12)
        atk_table.add_column("Name", width=40)
        atk_table.add_column("Tactics", width=30)
        atk_table.add_column("Source", width=14)

        _SOURCE_STYLE = {
            "cwe_static": "green",
            "claude_enriched": "cyan",
        }

        for tech in mapping.techniques:
            tactics = ", ".join(t.name for t in tech.tactics[:3])
            src_style = _SOURCE_STYLE.get(tech.mapping_source, "dim")
            atk_table.add_row(
                tech.technique_id,
                tech.name,
                tactics,
                Text(tech.mapping_source, style=src_style),
            )
        console.print(atk_table)
        if mapping.rationale:
            console.print(f"[dim]Mapping rationale:[/dim] {mapping.rationale}\n")

    # IOCs
    all_iocs = iocs.all_iocs()
    if all_iocs:
        ioc_table = Table(title="Indicators of Compromise", box=box.ROUNDED, border_style="magenta")
        ioc_table.add_column("Type", width=18)
        ioc_table.add_column("Value", width=45)
        ioc_table.add_column("Confidence", width=10)
        ioc_table.add_column("Context")

        for ioc in all_iocs[:25]:
            conf_style = {
                "high": "green",
                "medium": "yellow",
                "low": "dim",
                "inferred": "italic dim",
            }.get(ioc.confidence.value, "white")
            ioc_table.add_row(
                ioc.ioc_type.value,
                ioc.value[:44],
                Text(ioc.confidence.value, style=conf_style),
                ioc.context[:60],
            )
        console.print(ioc_table)

    # Detection Rules
    all_rules = rules.all_rules()
    if all_rules:
        console.print(f"\n[bold green]Detection Rules ({len(all_rules)} generated)[/bold green]\n")

        for rule in rules.sigma_rules:
            _render_rule_panel(rule, "Sigma", "yellow", syntax="yaml")

        for rule in rules.yara_rules:
            _render_rule_panel(rule, "YARA", "blue", syntax="c")

        for rule in rules.snort_rules:
            _render_rule_panel(rule, "Snort", "red")

        for rule in rules.suricata_rules:
            _render_rule_panel(rule, "Suricata", "bright_red")
    else:
        console.print("[dim]No detection rules generated.[/dim]")

    enrichment_note = "[green]Claude-enriched[/green]" if result.enriched else "[dim]Deterministic only (--no-enrich)[/dim]"
    console.print(f"\n[dim]Analysis: {enrichment_note}  |  Method: {mapping.mapping_method}[/dim]")


def _render_rule_panel(rule, label: str, color: str, syntax: str = "text") -> None:
    from cve_intel.models.rules import DetectionRule
    is_warning = rule.description.startswith("[QUALITY WARNING]")
    border = "yellow" if is_warning else color
    title_parts = [f"[{color}]{label}[/{color}] — {rule.name}"]
    title_parts.append(f"  [{rule.severity.upper()}]")
    if is_warning:
        title_parts.append("  [yellow]⚠ quality warning[/yellow]")
    subtitle = rule.description if is_warning else None
    console.print(Panel(
        Syntax(rule.rule_text, syntax, theme="monokai", line_numbers=False),
        title="".join(title_parts),
        subtitle=subtitle,
        border_style=border,
    ))
