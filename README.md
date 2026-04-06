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

## How the pipeline works

Every `analyze` or `batch` run executes these stages in order:

1. **Validate** — confirm the CVE ID matches the `CVE-YYYY-NNNNN` format
2. **Fetch NVD** — retrieve CVSS scores, CWEs, CPEs, and references (cached 24 h)
3. **Fetch Vulnrichment** — retrieve CISA KEV status and SSVC scores
4. **Load ATT&CK** — load the MITRE ATT&CK STIX bundle (cached indefinitely)
5. **Deterministic mapping** — map CWEs and CVSS vector to ATT&CK techniques using static lookup tables (no API key needed)
6. **Enrich** *(requires `ANTHROPIC_API_KEY`)* — Claude boosts technique confidence, fills gaps the static map misses, and extracts IOCs
7. **Generate rules** *(requires `ANTHROPIC_API_KEY`)* — Sigma, YARA, Snort, and Suricata rules generated in parallel

If enrichment or rule generation fails, the run completes with a warning — you always get at least the deterministic output from stages 1–5.

---

## Priority tiers

The triage score is deterministic and driven by exploitation evidence, not just CVSS.

| Tier | Criteria | Action |
|------|----------|--------|
| **CRITICAL** | KEV-listed **or** SSVC `exploitation=active` | Patch immediately |
| **HIGH** | SSVC `exploitation=poc`, CVSS ≥ 9.0, unauthenticated network vector with CVSS ≥ 7.0, or SSVC `automatable=yes` with CVSS ≥ 7.0 | Patch urgently |
| **MEDIUM** | SSVC `technical_impact=total` or CVSS ≥ 7.0 | Scheduled remediation |
| **LOW** | Everything else | Track / accept risk |

### SSVC fields

SSVC (Stakeholder-Specific Vulnerability Categorization) scores come from CISA Vulnrichment and add exploitation signal beyond a raw CVSS score:

| Field | Values | What it means |
|-------|--------|---------------|
| `exploitation` | `none` / `poc` / `active` | `poc` = public proof-of-concept exists; `active` = weaponized exploits observed in the wild |
| `automatable` | `yes` / `no` | Can the vulnerability be exploited at scale without human interaction? |
| `technical_impact` | `partial` / `total` | `total` = full system compromise (root/SYSTEM, full data access) is achievable |

---

## Deployment-aware triage

A vulnerability's real risk depends on your deployment. The triage output includes an `attack_requirements` block derived from the CVSS vector:

| Field | When to downgrade urgency |
|-------|--------------------------|
| `network_access_required: true` | The vulnerable service is not internet-exposed or reachable from untrusted networks |
| `adjacent_network_only: true` | Attacker must be on the same LAN or VLAN |
| `authentication_required: true` | Attacker needs valid credentials — significantly raises the bar |
| `high_privileges_required: true` | Attacker needs admin/root first |
| `user_interaction_required: true` | Exploit requires phishing or social engineering |

ATT&CK tactic context works the same way:

| Tactic | Only relevant if… |
|--------|------------------|
| Initial Access (TA0001) | The service is internet-exposed |
| Lateral Movement (TA0008) | An attacker is already inside the network |
| Privilege Escalation (TA0004) | The attacker already has some access |
| Impact (TA0040) | Describes what happens *after* successful exploitation |

### `.security/deployment.yml`

Create this file to give the CI advisory step context about your architecture. Claude reads it to qualify which attack vectors apply and to downgrade findings that don't match your exposure:

```yaml
# .security/deployment.yml
internet_exposed:
  - api-gateway
  - web-frontend

internal_only:
  - database
  - auth-service
  - message-queue

accepted_risks:
  - CVE-2023-44487   # HTTP/2 rapid reset — mitigated at load balancer
```

If the file does not exist, the advisory comment notes the omission and skips deployment qualification.

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

- `--workers` enables concurrent processing. Default: 3 with `NVD_API_KEY`, 1 without. Max: 10 with key, 3 without. Workers overlap enrichment and rule generation for different CVEs; NVD fetches are still serialised by the rate limiter regardless.
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

### SARIF severity policy

Control how risk signals map to SARIF levels with `--sarif-policy`:

| Preset | `level=error` threshold | KEV / SSVC escalation |
|--------|------------------------|-----------------------|
| `default` | CVSS ≥ 9.0 | Yes — KEV and SSVC `active` always escalate to `error`; PoC escalates to `warning` |
| `strict` | CVSS ≥ 7.0 | Yes — zero tolerance for exploitable vulnerabilities |
| `lenient` | CVSS ≥ 9.0 (score only) | No — ignores KEV and SSVC signals entirely |

```bash
cve-intel batch findings.txt --format sarif --sarif-policy strict --output ./results/
```

Override the exact CVSS threshold without switching presets:

```bash
cve-intel analyze CVE-2024-21762 --sarif results.sarif.json --cvss-threshold 8.5
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

### MCP workflows

**Scanner triage** (Grype / Snyk / Trivy output):
```
batch_triage_cves(ids) → cross-reference attack_requirements against your architecture → recommend patches
```
The triage result already contains full KEV and SSVC data — do not follow up with `get_exploitation_context`.

**Single CVE investigation:**
```
triage_cve → lookup_technique (per mapped technique) → get_related_techniques → get_community_sigma_rules → synthesise risk narrative
```

**Detection coverage assessment:**
```
get_attack_techniques → get_community_sigma_rules → lookup_technique (data_sources + detection_notes) → identify gaps
```

All MCP tools are deterministic — no Anthropic API calls inside the server. Claude Code acts as the reasoning layer on top of the structured data they return.

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
