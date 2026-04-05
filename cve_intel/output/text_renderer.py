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

    # ATT&CK Mapping
    if mapping.techniques:
        atk_table = Table(title="ATT&CK Techniques", box=box.ROUNDED, border_style="yellow")
        atk_table.add_column("ID", style="bold yellow", width=12)
        atk_table.add_column("Name", width=40)
        atk_table.add_column("Tactics", width=30)
        atk_table.add_column("Conf.", width=6)

        for tech in mapping.techniques:
            tactics = ", ".join(t.name for t in tech.tactics[:3])
            conf_style = "green" if tech.confidence >= 0.7 else "yellow" if tech.confidence >= 0.4 else "dim"
            atk_table.add_row(
                tech.technique_id,
                tech.name,
                tactics,
                Text(f"{tech.confidence:.0%}", style=conf_style),
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
            console.print(Panel(
                Syntax(rule.rule_text, "yaml", theme="monokai", line_numbers=False),
                title=f"[yellow]Sigma[/yellow] — {rule.name}",
                border_style="yellow",
            ))

        for rule in rules.yara_rules:
            console.print(Panel(
                Syntax(rule.rule_text, "c", theme="monokai", line_numbers=False),
                title=f"[blue]YARA[/blue] — {rule.name}",
                border_style="blue",
            ))

        for rule in rules.snort_rules:
            console.print(Panel(
                Syntax(rule.rule_text, "text", theme="monokai", line_numbers=False),
                title=f"[red]Snort[/red] — {rule.name}",
                border_style="red",
            ))
    else:
        console.print("[dim]No detection rules generated.[/dim]")

    enrichment_note = "[green]Claude-enriched[/green]" if result.enriched else "[dim]Deterministic only (--no-enrich)[/dim]"
    console.print(f"\n[dim]Analysis: {enrichment_note}  |  Method: {mapping.mapping_method}[/dim]")
