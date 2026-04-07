"""CLI entry point for cve-intel."""

import json
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

console = Console()
err_console = Console(stderr=True)


_FAIL_ON_ORDER = ["error", "warning", "note", "none"]


def _enforce_fail_on(fail_on: str, sarif_data: dict) -> None:
    """Exit 1 if any SARIF result meets or exceeds the fail_on level threshold."""
    if fail_on == "never":
        return
    threshold = _FAIL_ON_ORDER.index(fail_on)
    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            level = result.get("level", "none")
            if level in _FAIL_ON_ORDER and _FAIL_ON_ORDER.index(level) <= threshold:
                err_console.print(
                    f"[red]Pipeline gate triggered:[/red] finding at level '{level}' "
                    f"meets --fail-on '{fail_on}' threshold ({result.get('ruleId', '?')})"
                )
                sys.exit(1)


def _print_warnings(warnings: list[str]) -> None:
    """Render pipeline warnings to stderr as a yellow panel."""
    if not warnings:
        return
    body = "\n".join(f"• {w}" for w in warnings)
    err_console.print(
        Panel(body, title="[bold yellow]Warnings[/bold yellow]", border_style="yellow")
    )


@click.group()
@click.version_option(package_name="cve-intel")
def cli() -> None:
    """CVE Threat Intelligence System.

    Maps CVEs to ATT&CK techniques, extracts IOCs, and generates detection rules.
    """


@cli.command()
@click.argument("cve_id")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output directory. Writes output files here instead of stdout.")
@click.option("--format", "-f", "fmt",
              type=click.Choice(["text", "json", "sarif"]),
              default="text", show_default=True,
              help=(
                  "Output format. "
                  "text: Rich terminal report (stdout). "
                  "json: Full analysis as JSON (stdout or --output DIR). "
                  "sarif: SARIF 2.1.0 (stdout or --output DIR → results.sarif.json)."
              ))
@click.option("--rules", "-r", default="sigma,yara,snort,suricata", show_default=True,
              help="Comma-separated list of rule formats to generate.")
@click.option("--no-enrich", "no_enrich", is_flag=True, default=False,
              help="Skip Claude enrichment (deterministic only, no API key needed).")
@click.option("--force-refresh", "force_refresh", is_flag=True, default=False,
              help="Bypass the NVD cache and fetch live data, overwriting the cached entry.")
@click.option("--sarif-policy", "sarif_policy",
              type=click.Choice(["default", "strict", "lenient"]), default="default",
              show_default=True,
              help="[SARIF] Severity preset. strict=High+Critical→error, lenient=CVSS-only no KEV/SSVC escalation.")
@click.option("--cvss-threshold", "cvss_threshold", type=float, default=None,
              help="[SARIF] Override the CVSS score that triggers level=error (overrides preset).")
@click.option("--no-kev-escalation", "no_kev_escalation", is_flag=True, default=False,
              help="[SARIF] Disable KEV → error escalation (overrides preset).")
@click.option("--no-ssvc-escalation", "no_ssvc_escalation", is_flag=True, default=False,
              help="[SARIF] Disable SSVC active/poc escalation (overrides preset).")
def analyze(
    cve_id: str,
    output: str | None,
    fmt: str,
    rules: str,
    no_enrich: bool,
    force_refresh: bool,
    sarif_policy: str,
    cvss_threshold: float | None,
    no_kev_escalation: bool,
    no_ssvc_escalation: bool,
) -> None:
    """Run full analysis pipeline on a single CVE ID.

    For multiple CVEs, use the ``batch`` command which supports concurrent workers.
    """
    from cve_intel import pipeline
    from cve_intel.output import json_renderer, text_renderer
    from cve_intel.fetchers.attack_data import get_attack_data
    from cve_intel.progress import RichProgress

    rule_formats = set(r.strip().lower() for r in rules.split(",") if r.strip())
    enrich = not no_enrich
    output_dir = Path(output) if output else None

    prog = RichProgress()
    prog.start()

    prog.advance("Loading ATT&CK data…")
    try:
        attack_data = get_attack_data(progress_callback=prog.download_callback())
    except Exception as exc:
        prog.stop()
        console.print(f"[red]Failed to load ATT&CK data: {exc}[/red]")
        sys.exit(1)

    prog.advance(f"Analysing {cve_id}")
    try:
        result = pipeline.analyze(
            cve_id=cve_id,
            enrich=enrich,
            rule_formats=rule_formats,
            attack_data=attack_data,
            progress=prog,
            force_refresh=force_refresh,
        )
    except Exception as exc:
        prog.stop()
        console.print(f"[red]Error: {exc}[/red]")
        sys.exit(1)

    prog.stop()

    _print_warnings(result.warnings)

    if enrich and not result.enriched:
        err_console.print(
            "[red]Error:[/red] Enrichment was requested but failed. "
            "IOCs and detection rules were not generated."
        )
        sys.exit(1)

    if fmt == "text":
        text_renderer.render_text(result)

    elif fmt == "sarif":
        from cve_intel.output.sarif_renderer import render_sarif, SarifPolicy
        import json as _json
        policy = SarifPolicy.from_preset(sarif_policy)
        if cvss_threshold is not None:
            policy.cvss_error = cvss_threshold
        if no_kev_escalation:
            policy.kev_is_error = False
        if no_ssvc_escalation:
            policy.ssvc_active_is_error = False
            policy.ssvc_poc_is_warning = False
        sarif_data = render_sarif([result], policy=policy)
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            out_file = output_dir / "results.sarif.json"
            out_file.write_text(_json.dumps(sarif_data, indent=2))
            console.print(f"[dim]SARIF written to {out_file}[/dim]")
        else:
            click.echo(_json.dumps(sarif_data, indent=2))

    elif fmt == "json":
        if output_dir:
            path = json_renderer.write_json(result, output_dir)
            console.print(f"[dim]JSON written to {path}[/dim]")
            rule_paths = json_renderer.write_rules(result, output_dir / "rules")
            for rp in rule_paths:
                console.print(f"[dim]Rule written to {rp}[/dim]")
        else:
            click.echo(json_renderer.render_json(result))


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--from", "input_fmt",
              type=click.Choice(["auto", "sarif", "cyclonedx", "ids"]),
              default="auto", show_default=True,
              help=(
                  "Input format. "
                  "'sarif' = SARIF 2.1.0 (Grype, Trivy, Snyk, Dependabot). "
                  "'cyclonedx' = CycloneDX JSON vulnerability report. "
                  "'ids' = plain newline-separated CVE IDs (legacy). "
                  "'auto' detects SARIF/CycloneDX from file content; falls back to 'ids'."
              ))
@click.option("--format", "-f", "fmt",
              type=click.Choice(["text", "json", "sarif"]),
              default="text", show_default=True,
              help="Output format.")
@click.option("--output", "-o", type=click.Path(), default=None,
              help=(
                  "Output directory. Writes results.sarif.json (SARIF) and "
                  "results.vex.json (CycloneDX VEX) when --format sarif is set. "
                  "Writes one JSON file per CVE when --format json is set."
              ))
@click.option("--vex-in", "vex_in", type=click.Path(exists=True), default=None,
              help=(
                  "CycloneDX VEX document from a prior run. CVEs with "
                  "state=not_affected are excluded from triage and carried "
                  "forward verbatim into the new VEX output."
              ))
@click.option("--fail-on", "fail_on",
              type=click.Choice(["error", "warning", "note", "never"]),
              default="never", show_default=True,
              help=(
                  "Exit with code 1 if any finding reaches this SARIF level or above. "
                  "'error' = CRITICAL/KEV findings only. "
                  "'warning' = HIGH findings and above. "
                  "Use with --format sarif for GitHub, GitLab, and Azure DevOps gates."
              ))
@click.option("--workers", "-w", default=None, type=click.IntRange(1, 10),
              help=(
                  "Concurrent workers. "
                  "Defaults to 3 with NVD_API_KEY, 1 without. "
                  "The NVD rate limiter serialises fetches regardless, so more workers "
                  "overlap enrichment and rule generation for different CVEs. "
                  "Max 10 with a key, max 3 without."
              ))
@click.option("--no-enrich", "no_enrich", is_flag=True, default=False,
              help="Skip Claude enrichment.")
@click.option("--rules", "-r", default="sigma,yara,snort,suricata", show_default=True,
              help="Comma-separated rule formats.")
@click.option("--sarif-policy", "sarif_policy",
              type=click.Choice(["default", "strict", "lenient"]), default="default",
              show_default=True,
              help="[SARIF] Severity preset. strict=High+Critical→error, lenient=CVSS-only no KEV/SSVC escalation.")
@click.option("--cvss-threshold", "cvss_threshold", type=float, default=None,
              help="[SARIF] Override the CVSS score that triggers level=error (overrides preset).")
@click.option("--no-kev-escalation", "no_kev_escalation", is_flag=True, default=False,
              help="[SARIF] Disable KEV → error escalation (overrides preset).")
@click.option("--no-ssvc-escalation", "no_ssvc_escalation", is_flag=True, default=False,
              help="[SARIF] Disable SSVC active/poc escalation (overrides preset).")
def batch(
    input_file: str,
    input_fmt: str,
    fmt: str,
    output: str | None,
    vex_in: str | None,
    fail_on: str,
    workers: int | None,
    no_enrich: bool,
    rules: str,
    sarif_policy: str,
    cvss_threshold: float | None,
    no_kev_escalation: bool,
    no_ssvc_escalation: bool,
) -> None:
    """Analyse multiple CVEs from a scanner report or CVE ID list.

    \b
    Input formats (--from):
      sarif      SARIF 2.1.0 — Grype, Trivy, Snyk, Semgrep, Dependabot
      cyclonedx  CycloneDX JSON — Grype, Trivy, cdxgen, syft
      ids        Plain newline-separated CVE IDs (legacy / manual lists)
      auto       Detect from file content (default)

    \b
    CI/CD gate (--fail-on):
      error    Exit 1 if any CRITICAL or KEV-listed finding
      warning  Exit 1 if any HIGH finding or above
      note     Exit 1 if any MEDIUM finding or above
      never    Always exit 0 (default — report only)

    \b
    Output (--format sarif --output DIR):
      results.sarif.json  SARIF 2.1.0  — upload to GitHub/GitLab/Azure DevOps
      results.vex.json    CycloneDX VEX — applicability record for re-ingestion

    GitHub Actions:
      uses: github/codeql-action/upload-sarif@v3
      with: { sarif_file: ./security-results/results.sarif.json }

    GitLab (15.0+):
      artifacts: { reports: { sast: results.sarif.json } }
    """
    import concurrent.futures
    import json as _json

    from cve_intel import pipeline
    from cve_intel.config import settings as _settings
    from cve_intel.fetchers.scanner_input import load_findings, ScannerFinding

    has_nvd_key = _settings.has_nvd_key
    if workers is None:
        workers = 3 if has_nvd_key else 1
    elif not has_nvd_key and workers > 3:
        err_console.print(
            "[yellow]Warning:[/yellow] --workers capped at 3 without NVD_API_KEY "
            "(set NVD_API_KEY to use up to 10 workers)."
        )
        workers = 3
    from cve_intel.output import json_renderer, text_renderer
    from cve_intel.fetchers.attack_data import get_attack_data
    from cve_intel.progress import RichProgress
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

    rule_formats = set(r.strip().lower() for r in rules.split(",") if r.strip())
    enrich = not no_enrich
    output_dir = Path(output) if output else None
    input_path = Path(input_file)

    # --- Load input ---
    scanner_findings: dict[str, ScannerFinding] = {}

    if input_fmt == "ids":
        # Legacy plain-text CVE ID list
        cve_ids = [
            line.strip()
            for line in input_path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    else:
        # Try SARIF/CycloneDX (auto-detect or explicit)
        try:
            effective_fmt = input_fmt if input_fmt != "auto" else "auto"
            findings_list = load_findings(input_path, fmt=effective_fmt)
            scanner_findings = {f.cve_id: f for f in findings_list}
            cve_ids = list(scanner_findings.keys())
        except (ValueError, KeyError):
            if input_fmt != "auto":
                raise
            # auto fallback: treat as plain CVE ID list
            cve_ids = [
                line.strip()
                for line in input_path.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            ]

    if not cve_ids:
        err_console.print("[yellow]No CVE IDs found in input.[/yellow]")
        return

    # --- VEX re-ingestion: filter not_affected CVEs from prior run ---
    prior_decisions: list = []
    suppressed: set[str] = set()
    if vex_in:
        from cve_intel.fetchers.scanner_input import load_vex
        try:
            prior_decisions = load_vex(Path(vex_in))
        except (json.JSONDecodeError, OSError) as exc:
            console.print(f"[red]Cannot load VEX file {vex_in!r}: {exc}[/red]")
            sys.exit(1)
        suppressed = {d.cve_id for d in prior_decisions if d.state == "not_affected"}
        if suppressed:
            cve_ids = [c.upper() for c in cve_ids]
            cve_ids = [c for c in cve_ids if c not in suppressed]
            err_console.print(
                f"[dim]Skipped {len(suppressed)} not_affected CVE(s) from prior VEX: "
                f"{', '.join(sorted(suppressed))}[/dim]"
            )

    detected = f" ({len(scanner_findings)} with package context)" if scanner_findings else ""
    err_console.print(f"[dim]Loaded {len(cve_ids)} CVEs{detected}[/dim]")

    load_prog = RichProgress()
    load_prog.start()
    load_prog.advance("Loading ATT&CK data…")
    try:
        attack_data = get_attack_data(progress_callback=load_prog.download_callback())
    except Exception as exc:
        load_prog.stop()
        console.print(f"[red]Failed to load ATT&CK data: {exc}[/red]")
        sys.exit(1)
    load_prog.stop()

    results = []
    errors = []

    def _run(cid: str):
        from cve_intel.fetchers.nvd import NVDRateLimitError, NVDNotFoundError
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                return pipeline.analyze(
                    cve_id=cid,
                    enrich=enrich,
                    rule_formats=rule_formats,
                    attack_data=attack_data,
                )
            except NVDNotFoundError:
                raise  # permanent — CVE doesn't exist, no point retrying
            except NVDRateLimitError:
                if attempt < max_attempts - 1:
                    time.sleep(5 * 2 ** attempt)  # 5s, 10s
                else:
                    raise

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=Console(stderr=True),
        transient=True,
    ) as progress:
        task = progress.add_task("Processing CVEs", total=len(cve_ids))

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_cid = {executor.submit(_run, cid): cid for cid in cve_ids}
            for future in concurrent.futures.as_completed(future_to_cid):
                cid = future_to_cid[future]
                progress.advance(task)
                progress.update(task, description=f"[cyan]Processed {cid}")
                try:
                    results.append(future.result(timeout=120))
                except concurrent.futures.TimeoutError:
                    errors.append((cid, TimeoutError(f"{cid} timed out after 120s")))
                except Exception as exc:
                    errors.append((cid, exc))

    if errors:
        from cve_intel.fetchers.nvd import NVDRateLimitError, NVDNotFoundError
        for cid, exc in errors:
            if isinstance(exc, NVDNotFoundError):
                err_console.print(f"[yellow]Skipped [{cid}]: not found in NVD[/yellow]")
            elif isinstance(exc, NVDRateLimitError):
                err_console.print(f"[red]Failed [{cid}]: NVD rate limit — retry with NVD_API_KEY or reduce --workers[/red]")
            else:
                err_console.print(f"[red]Error [{cid}]: {exc}[/red]")

    if fmt == "sarif":
        from cve_intel.output.sarif_renderer import render_sarif, assign_levels, SarifPolicy
        from cve_intel.output.vex_renderer import render_vex

        policy = SarifPolicy.from_preset(sarif_policy)
        if cvss_threshold is not None:
            policy.cvss_error = cvss_threshold
        if no_kev_escalation:
            policy.kev_is_error = False
        if no_ssvc_escalation:
            policy.ssvc_active_is_error = False
            policy.ssvc_poc_is_warning = False

        sarif_data = render_sarif(results, policy=policy, findings=scanner_findings or None)

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            sarif_file = output_dir / "results.sarif.json"
            sarif_file.write_text(_json.dumps(sarif_data, indent=2))
            err_console.print(f"[dim]SARIF written to {sarif_file}[/dim]")

            # VEX written alongside SARIF automatically
            levels = assign_levels(results, policy=policy)
            vex_data = render_vex(results, sarif_levels=levels, findings=scanner_findings or None, prior_decisions=prior_decisions or None)
            vex_file = output_dir / "results.vex.json"
            vex_file.write_text(_json.dumps(vex_data, indent=2))
            err_console.print(f"[dim]VEX  written to {vex_file}[/dim]")
        else:
            click.echo(_json.dumps(sarif_data, indent=2))

        # --- CI gate ---
        _enforce_fail_on(fail_on, sarif_data)
        return

    enrichment_failures = 0
    for result in results:
        _print_warnings(result.warnings)
        if enrich and not result.enriched:
            enrichment_failures += 1

        if fmt == "text":
            text_renderer.render_text(result)
        elif fmt == "json":
            if output_dir:
                output_dir.mkdir(parents=True, exist_ok=True)
                path = json_renderer.write_json(result, output_dir)
                err_console.print(f"[dim]Written: {path}[/dim]")
                rule_paths = json_renderer.write_rules(result, output_dir / "rules")
                for rp in rule_paths:
                    err_console.print(f"[dim]Rule written to {rp}[/dim]")
            else:
                click.echo(json_renderer.render_json(result))

    summary = f"\n[green]Done.[/green] {len(results)} succeeded, {len(errors)} failed."
    if enrichment_failures:
        summary += f" [yellow]{enrichment_failures} enrichment failure(s) — rules/IOCs not generated.[/yellow]"
    err_console.print(summary)

    # CI gate for non-SARIF formats (compute levels on the fly)
    if fail_on != "never":
        from cve_intel.output.sarif_renderer import assign_levels, SarifPolicy
        policy = SarifPolicy.from_preset(sarif_policy)
        sarif_like = {"runs": [{"results": [
            {"ruleId": r.cve_id, "level": lv}
            for r, lv in zip(results, assign_levels(results, policy).values())
        ]}]}
        _enforce_fail_on(fail_on, sarif_like)


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
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write output to FILE instead of stdout.")
@click.option("--format", "-f", "fmt", type=click.Choice(["text", "json"]),
              default="text", show_default=True)
def map(cve_id: str, output: str | None, fmt: str) -> None:
    """Map CVE to ATT&CK techniques (deterministic, no API key required)."""
    from cve_intel import pipeline
    import json as _json

    try:
        result = pipeline.analyze(cve_id, enrich=False, rule_formats=set(), extract_iocs=False)
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    _print_warnings(result.warnings)

    m = result.attack_mapping

    if fmt == "json":
        data = _json.dumps(m.model_dump(mode="json"), indent=2, default=str)
        if output:
            Path(output).write_text(data)
            console.print(f"[dim]Written to {output}[/dim]")
        else:
            click.echo(data)
        return

    lines = [
        f"\n[bold yellow]ATT&CK Mapping for {cve_id}[/bold yellow]",
        f"Method: {m.mapping_method}",
        f"Rationale: {m.rationale}\n",
    ]
    for t in m.techniques:
        lines.append(f"  {t.technique_id:12} {t.name:40} source={t.mapping_source}  [{t.rationale}]")
    text_out = "\n".join(lines)

    if output:
        Path(output).write_text(text_out + "\n")
        console.print(f"[dim]Written to {output}[/dim]")
    else:
        for line in lines:
            console.print(line)


@cli.command()
@click.argument("cve_id")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write JSON output to FILE instead of stdout.")
def iocs(cve_id: str, output: str | None) -> None:
    """Extract and display IOCs for a CVE (requires ANTHROPIC_API_KEY)."""
    import json as _json
    from cve_intel import pipeline

    try:
        result = pipeline.analyze(cve_id, enrich=True, rule_formats=set())
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    _print_warnings(result.warnings)

    bundle = result.ioc_bundle
    all_iocs = bundle.all_iocs()

    if output:
        data = _json.dumps(bundle.model_dump(mode="json"), indent=2, default=str)
        Path(output).write_text(data)
        console.print(f"[dim]Written to {output}[/dim]")
        return

    console.print(f"\n[bold magenta]IOCs for {cve_id} ({len(all_iocs)} total)[/bold magenta]\n")
    for ioc in all_iocs:
        console.print(f"  [{ioc.ioc_type.value}] {ioc.value} [{ioc.confidence.value}] — {ioc.context}")


@cli.command()
@click.argument("cve_id")
@click.option("--rules", "-r", default="sigma,yara,snort,suricata", show_default=True,
              help="Comma-separated rule formats to generate.")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write rule files to this directory.")
@click.option("--format", "-f", "fmt",
              type=click.Choice(["text", "json"]),
              default="text", show_default=True,
              help=(
                  "Output format. "
                  "text: prints rules inline or writes individual rule files "
                  "(e.g. sigma/*.yml, yara/*.yar) when --output is given. "
                  "json: emits a single JSON blob containing all rules."
              ))
@click.option("--compare-community", "compare_community", is_flag=True, default=False,
              help=(
                  "Compare generated Sigma rule against SigmaHQ community rules. "
                  "Requires network access to api.github.com. "
                  "Set GITHUB_TOKEN to avoid rate limits (60 req/hr unauthenticated)."
              ))
def rules_cmd(cve_id: str, rules: str, output: str | None, fmt: str, compare_community: bool) -> None:
    """Generate detection rules for a CVE (requires ANTHROPIC_API_KEY)."""
    import json as _json
    from cve_intel import pipeline
    from cve_intel.output import json_renderer

    rule_formats = set(r.strip().lower() for r in rules.split(",") if r.strip())
    try:
        result = pipeline.analyze(cve_id, enrich=True, rule_formats=rule_formats)
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    _print_warnings(result.warnings)

    all_rules = result.rule_bundle.all_rules()

    if fmt == "json":
        data = _json.dumps(result.rule_bundle.model_dump(mode="json"), indent=2, default=str)
        if output:
            Path(output).mkdir(parents=True, exist_ok=True)
            out_file = Path(output) / f"{cve_id}-rules.json"
            out_file.write_text(data)
            console.print(f"[dim]Written to {out_file}[/dim]")
        else:
            click.echo(data)
        return

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

    if compare_community:
        _print_community_comparison(cve_id, result.rule_bundle.sigma_rules)


def _print_community_comparison(cve_id: str, sigma_rules: list) -> None:
    """Fetch SigmaHQ community rules and print a comparison panel."""
    import os
    from cve_intel.fetchers.sigmahq import fetch_community_rules, compare_with_community
    from rich.table import Table

    # Pass GITHUB_TOKEN if available to raise the rate limit
    token = os.environ.get("GITHUB_TOKEN", "")
    community = fetch_community_rules(cve_id, github_token=token)

    if not community.found:
        err_console.print(
            f"[dim]No community Sigma rules found for {cve_id} in SigmaHQ/sigma.[/dim]"
        )
        return

    console.print(
        f"\n[bold cyan]Community Sigma comparison ({len(community.rules)} rule(s) found)[/bold cyan]"
    )

    for sigma_rule in sigma_rules:
        comparison = compare_with_community(sigma_rule.rule_text, community)
        if not comparison.get("community_available"):
            continue

        for c in comparison.get("comparisons", []):
            table = Table(
                title=f"vs {c['community_filename']}",
                show_header=True,
                header_style="bold",
                show_lines=False,
            )
            table.add_column("Field", style="dim", width=22)
            table.add_column("Generated")
            table.add_column("Community")
            table.add_column("Match", justify="center")

            def _tick(match: bool) -> str:
                return "[green]✓[/green]" if match else "[red]✗[/red]"

            ls_gen = c["generated_logsource"]
            ls_com = c["community_logsource"]
            table.add_row(
                "logsource.category",
                ls_gen.get("category", "—"),
                ls_com.get("category", "—"),
                _tick(ls_gen.get("category") == ls_com.get("category")),
            )
            table.add_row(
                "logsource.product",
                ls_gen.get("product", "—"),
                ls_com.get("product", "—"),
                _tick(ls_gen.get("product") == ls_com.get("product")),
            )
            table.add_row(
                "level",
                c["generated_level"],
                c["community_level"],
                _tick(c["level_match"]),
            )

            shared = ", ".join(c["shared_attack_tags"]) or "—"
            missing = ", ".join(c["missing_attack_tags"]) or "—"
            extra = ", ".join(c["extra_attack_tags"]) or "—"
            table.add_row("ATT&CK shared", shared, shared, "[green]✓[/green]" if shared != "—" else "")
            table.add_row("ATT&CK missing", "—", missing, "[red]✗[/red]" if missing != "—" else "[green]✓[/green]")
            table.add_row("ATT&CK extra", extra, "—", "")

            console.print(table)


# Register rules command under its correct name
cli.add_command(rules_cmd, name="rules")


@cli.command()
@click.option("--full", is_flag=True, default=False,
              help="Run a live Claude API ping (requires ANTHROPIC_API_KEY).")
def doctor(full: bool) -> None:
    """Check configuration and connectivity health."""
    from cve_intel.doctor import run_checks
    from rich.table import Table

    checks = run_checks(full_check=full)

    table = Table(title="cve-intel health check", show_lines=False, highlight=True)
    table.add_column("Check", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Detail")

    any_fail = False
    for check in checks:
        if check.status == "PASS":
            status_str = "[green]PASS[/green]"
        elif check.status == "WARN":
            status_str = "[yellow]WARN[/yellow]"
        else:
            status_str = "[red]FAIL[/red]"
            any_fail = True
        table.add_row(check.name, status_str, check.detail)

    console.print(table)
    if any_fail:
        sys.exit(1)


@cli.group()
def cache() -> None:
    """Manage local cache."""


@cache.command("clear")
def cache_clear() -> None:
    """Clear all caches (NVD responses, Vulnrichment, and ATT&CK bundle)."""
    import diskcache
    import shutil
    from cve_intel.config import settings

    # NVD
    nvd_path = settings.cache_dir / "nvd"
    nvd_count = 0
    if nvd_path.exists():
        with diskcache.Cache(str(nvd_path)) as c:
            nvd_count = len(c)
            c.clear()
    console.print(f"[green]Cleared {nvd_count} NVD entries.[/green]")

    # Vulnrichment
    vuln_path = settings.cache_dir / "vulnrichment"
    vuln_count = 0
    if vuln_path.exists():
        with diskcache.Cache(str(vuln_path)) as c:
            vuln_count = len(c)
            c.clear()
    console.print(f"[green]Cleared {vuln_count} Vulnrichment entries.[/green]")

    # SigmaHQ
    sigmahq_path = settings.cache_dir / "sigmahq"
    sigmahq_count = 0
    if sigmahq_path.exists():
        with diskcache.Cache(str(sigmahq_path)) as c:
            sigmahq_count = len(c)
            c.clear()
    console.print(f"[green]Cleared {sigmahq_count} SigmaHQ entries.[/green]")

    # ATT&CK bundle
    attack_path = settings.cache_dir / "attack"
    if attack_path.exists():
        shutil.rmtree(attack_path)
        console.print("[green]Cleared ATT&CK bundle (will re-download on next run).[/green]")
    else:
        console.print("[dim]ATT&CK bundle not cached — nothing to clear.[/dim]")


@cache.command("stats")
def cache_stats() -> None:
    """Show cache statistics."""
    import diskcache
    from cve_intel.config import settings

    cache_path = settings.cache_dir / "nvd"
    with diskcache.Cache(str(cache_path)) as c:
        console.print(f"NVD cache entries: {len(c)}")
        console.print(f"NVD cache size: {c.volume() / 1024:.1f} KB")
    console.print(f"Cache directory: {settings.cache_dir}")
