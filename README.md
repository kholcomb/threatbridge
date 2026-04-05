# cve-intel

CVE threat intelligence system — maps CVEs to MITRE ATT&CK techniques, extracts IOCs, and generates detection rules (Sigma, YARA, Snort, Suricata).
---

## Installation

```bash
pip install -e .
cp .env.example .env   # then edit .env to add your API keys
```

Run a health check to verify the setup:

```bash
cve-intel doctor
```

---

## Quick start

```bash
# Full analysis — ATT&CK mapping, IOCs, and detection rules
cve-intel analyze CVE-2024-21762

# Deterministic-only (no API key required)
cve-intel analyze CVE-2024-21762 --no-enrich

# Write results to a directory
cve-intel analyze CVE-2024-21762 --format json --output ./results/

# Write SARIF output (for GitHub Security tab)
cve-intel analyze CVE-2024-21762 --sarif results.sarif.json

# Batch from a file
cve-intel batch cve_list.txt --format json --output ./results/
```

---

## Commands

| Command | Purpose | Key flags |
|---|---|---|
| `analyze CVE-ID` | Full pipeline: ATT&CK + IOCs + rules | `--no-enrich`, `--rules`, `--format`, `--sarif`, `--batch` |
| `batch FILE` | Analyse many CVEs from a file | `--workers`, `--format`, `--output`, `--no-enrich` |
| `fetch CVE-ID` | Raw NVD record as JSON | — |
| `map CVE-ID` | ATT&CK mapping only | `--no-enrich`, `--format`, `--output` |
| `iocs CVE-ID` | IOC extraction | `--no-enrich` |
| `rules CVE-ID` | Detection rule generation | `--rules`, `--output` |
| `doctor` | Health check | `--full` (live API ping) |
| `cache stats` | Cache size and entry count | — |
| `cache clear` | Clear NVD response cache | — |

---

## Configuration

All settings are read from the environment or a `.env` file.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | No¹ | — | Enables Claude enrichment, IOC extraction, and rule generation |
| `NVD_API_KEY` | No | — | Increases NVD rate limit from ~5 req/30 s to 50 req/30 s |
| `CLAUDE_MODEL` | No | `claude-sonnet-4-6` | Claude model for enrichment |
| `CACHE_DIR` | No | OS cache dir | Base directory for NVD + ATT&CK caches |
| `CACHE_TTL_SECONDS` | No | `86400` | NVD response cache TTL (seconds) |
| `ATTACK_BUNDLE_PATH` | No | auto-downloaded | Override path for the ATT&CK STIX bundle |
| `MAX_TOKENS` | No | `4096` | Claude API max tokens per call |

¹ Without an Anthropic API key the tool runs deterministic ATT&CK mapping only — no IOCs or detection rules. A warning is shown in the output.

---

## `cve-intel doctor`

Checks your environment and reports any issues:

```
 Check                  Status  Detail
 ──────────────────────────────────────────────────────────────
 ANTHROPIC_API_KEY      PASS    Present (sk-ant-a…xxxx)
 NVD_API_KEY            WARN    Not set — rate-limited to ~5 req/30 s
 Cache directory        PASS    /home/user/.cache/cve-intel  (42.3 MB)
 ATT&CK bundle          PASS    enterprise-attack.json  82 MB  age=3 days
 Package: anthropic     PASS    Installed
 ...
 Network (NVD)          PASS    Reachable (HTTP 200)
```

Exit code 1 if any check fails — usable in CI scripts.

---

## Batch analysis

Create a plain text file with one CVE ID per line (lines starting with `#` are ignored):

```
# High-priority findings from Grype scan 2026-04-05
CVE-2024-21762
CVE-2024-3400
CVE-2023-44487
```

```bash
cve-intel batch findings.txt --format json --output ./results/ --workers 2
```

- `--workers` enables concurrent processing (default 1, max 3 — Claude API rate limits apply).
- `--output DIR` writes one `CVE-XXXX-XXXXX.json` per CVE.
- `--format sarif` writes a single `results.sarif.json`.

---

## SARIF / GitHub Security tab

Generate a SARIF file and upload it to the GitHub Security tab:

```bash
cve-intel analyze CVE-2024-21762 --sarif cve-results.sarif.json
```

In a GitHub Actions workflow:

```yaml
- name: Analyze CVEs
  run: cve-intel analyze CVE-2024-21762 --sarif results.sarif.json

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif.json
```

---

## MCP server

The MCP server exposes 10 tools for use in Claude Code sessions:

| Tool | Purpose |
|---|---|
| `fetch_cve` | Raw NVD record |
| `get_attack_techniques` | Deterministic ATT&CK mapping |
| `get_cve_summary` | CVE + mapping combined |
| `get_exploitation_context` | CISA KEV + SSVC scores |
| `triage_cve` | Full structured triage with priority tier |
| `batch_triage_cves` | Triage a list, sorted by priority |
| `lookup_technique` | Full technique detail by ID |
| `search_techniques` | Keyword search across all techniques |
| `get_community_sigma_rules` | Community Sigma rules for a CVE |
| `compare_sigma_rule_with_community` | Diff a generated rule against community |

**Configure in Claude Code** (`~/.claude/mcp.json` or `.mcp.json` in the repo root):

```json
{
  "mcpServers": {
    "cve-intel": {
      "command": ".venv/bin/python",
      "args": ["-m", "cve_intel.mcp_server"]
    }
  }
}
```

Then in Claude Code: `batch_triage_cves(["CVE-2024-21762", "CVE-2024-3400"])`

---

## CI integration

The repository ships a GitHub Actions workflow (`.github/workflows/security-triage.yml`) that:

1. Runs [Grype](https://github.com/anchore/grype) against the repository on every PR.
2. Extracts CVE IDs from Grype output with `jq`.
3. **Deterministic gate:** `cve-intel batch --format sarif` fetches CVSS scores from NVD and emits SARIF 2.1.0. CI fails if any result has `level=error` (CVSS ≥ 9.0). No AI involved.
4. Uploads SARIF to the GitHub Security tab via `github/codeql-action/upload-sarif`.
5. **Advisory:** Claude uses the MCP server to post a ranked PR comment with deployment-aware downgrades and remediation steps. This step is `continue-on-error` — it never fails CI.

**Required secrets:** `ANTHROPIC_API_KEY` (advisory step), `NVD_API_KEY` (recommended for gate step)

**Optional repo variable:** Set `FAIL_ON_CRITICAL=false` to disable the CVSS gate.

Customize which services are internet-exposed and which CVEs are accepted risks in `.security/deployment.yml`.

---

## Cache management

The NVD API responses are cached on disk (default TTL: 24 hours).
The ATT&CK STIX bundle (~80 MB) is downloaded once and cached indefinitely.

```bash
cve-intel cache stats   # show location, entry count, and size
cve-intel cache clear   # evict all NVD cached responses
```

To force a fresh ATT&CK bundle download, delete `$CACHE_DIR/attack/enterprise-attack.json`.

---

## Contributing

- Run tests: `pytest`
- Required before commit: `pytest tests/`
- New fetchers/generators should follow the patterns in `cve_intel/fetchers/` and `cve_intel/generators/`
- The MCP server tool signatures are stable — additive changes only
