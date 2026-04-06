"""Prompt templates for Claude enrichment calls."""

ATTACK_ENRICHER_SYSTEM = """\
You are a MITRE ATT&CK expert and senior threat intelligence analyst. Your task is to analyze \
a CVE and refine its ATT&CK technique mapping.

Rules:
- Only include techniques that are directly relevant to how this vulnerability is exploited \
  or what an attacker can accomplish by exploiting it.
- Do not include post-exploitation techniques that require additional attacker tools not \
  implied by the CVE itself.
- Provide a concise rationale (1 sentence) citing the specific CVE behavior that maps to each technique.
- Use exact ATT&CK technique IDs (e.g., T1190, T1059.001).
- If a candidate technique does not fit, add it to removed_technique_ids with no rationale needed.
"""

ATTACK_ENRICHER_USER = """\
Analyze this CVE and refine the ATT&CK technique mapping.

CVE ID: {cve_id}
Description: {description}
CVSS Score: {cvss_score} ({cvss_severity}) — Vector: {cvss_vector}
Affected Products: {products}
CWE IDs: {cwes}
Candidate Techniques (from static mapping):
{candidate_techniques}
{unmapped_note}
Return your refined mapping using the provided tool.
"""

ATTACK_ENRICHER_SCHEMA = {
    "type": "object",
    "properties": {
        "confirmed_techniques": {
            "type": "array",
            "description": "Techniques from the candidate list that are correct for this CVE",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["technique_id", "rationale"],
            },
        },
        "added_techniques": {
            "type": "array",
            "description": "New techniques not in the candidate list that are relevant",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["technique_id", "rationale"],
            },
        },
        "removed_technique_ids": {
            "type": "array",
            "description": "Candidate technique IDs that are NOT relevant to this CVE",
            "items": {"type": "string"},
        },
        "overall_rationale": {
            "type": "string",
            "description": "1-2 sentence summary of the attack scenario this CVE enables",
        },
    },
    "required": ["confirmed_techniques", "added_techniques", "removed_technique_ids", "overall_rationale"],
}

IOC_EXTRACTOR_SYSTEM = """\
You are a threat intelligence analyst and detection engineer. Your task is to extract \
Indicators of Compromise (IOCs) from a CVE description and related context.

Rules:
- Extract ONLY IOCs that are directly stated or unambiguously implied by the CVE data provided below.
- If a specific value (URL path, process name, file path, header, port) is not present in the \
  CVE description or affected product context, do NOT include it — leave the array empty.
- For IOCs explicitly stated verbatim in the description, use confidence "high".
- For IOCs that can be precisely named from the affected product (e.g., a known daemon name or \
  install path), use confidence "medium".
- Use confidence "inferred" only for IOCs deducible from the CVE type and product combination. \
  Never use "inferred" for invented values.
- Do not invent IP addresses, hashes, file paths, or domain names.
- Behavioral IOCs must be specific: reference the exact endpoint, parameter, header, or mechanism \
  described. "sends HTTP requests" is NOT acceptable; "POST to /ssl-vpn/portal.cgi with malformed \
  Content-Length" IS acceptable.
- If the CVE description lacks detail for specific IOCs, return empty arrays.
"""

IOC_EXTRACTOR_USER = """\
Extract IOCs from this CVE.

CVE ID: {cve_id}
Description: {description}
Affected Products: {products}
ATT&CK Techniques: {techniques}
CVSS: {cvss_score} {cvss_severity} — {cvss_vector}
CWE IDs: {cwes}

Return all observable IOCs using the provided tool.
"""

IOC_EXTRACTOR_SCHEMA = {
    "type": "object",
    "properties": {
        "network_iocs": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "ioc_type": {"type": "string", "enum": [
                        "ip_address", "domain", "url", "port", "protocol", "user_agent", "http_header"
                    ]},
                    "value": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low", "inferred"]},
                    "context": {"type": "string"},
                },
                "required": ["ioc_type", "value", "confidence", "context"],
            },
        },
        "file_iocs": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "ioc_type": {"type": "string", "enum": [
                        "file_hash_md5", "file_hash_sha1", "file_hash_sha256", "file_path", "file_name"
                    ]},
                    "value": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low", "inferred"]},
                    "context": {"type": "string"},
                },
                "required": ["ioc_type", "value", "confidence", "context"],
            },
        },
        "process_iocs": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "ioc_type": {"type": "string", "enum": [
                        "process_name", "command_line", "registry_key", "mutex"
                    ]},
                    "value": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low", "inferred"]},
                    "context": {"type": "string"},
                },
                "required": ["ioc_type", "value", "confidence", "context"],
            },
        },
        "behavioral_iocs": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "ioc_type": {"type": "string", "enum": ["behavioral"]},
                    "value": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low", "inferred"]},
                    "context": {"type": "string"},
                },
                "required": ["ioc_type", "value", "confidence", "context"],
            },
        },
    },
    "required": ["network_iocs", "file_iocs", "process_iocs", "behavioral_iocs"],
}

SIGMA_GEN_SYSTEM = """\
You are a senior detection engineer. Write high-quality Sigma rules for SIEM detection.

Rules:
- Use proper Sigma YAML syntax.
- Base ALL detection conditions exclusively on the IOCs and CVE description provided in the \
  user message. Do not add detection strings not derived from the provided IOCs.
- Choose logsource matching the CVE attack vector: use category: webserver or product: zeek for \
  network-exploited services; use category: process_creation only for vulnerabilities with \
  observable process activity.
- If specific URL paths, HTTP methods, or parameters appear in IOCs, those MUST appear as \
  detection strings. A rule with only generic strings (e.g., Image|endswith: '.exe') when \
  specific IOCs are available is not acceptable.
- Write detection conditions that are specific enough to avoid massive false positives.
- Include false positive notes where appropriate.
- Use | contains, | startswith, | endswith, | re modifiers correctly.
- Tag rules with relevant ATT&CK technique IDs.
"""

SIGMA_GEN_USER = """\
Write a Sigma detection rule for this CVE.

CVE ID: {cve_id}
Description: {description}
Affected Products: {products}
ATT&CK Techniques: {techniques}
IOCs:
{iocs}
CVSS Severity: {cvss_severity}

Return the Sigma rule and metadata using the provided tool.
"""

SIGMA_GEN_SCHEMA = {
    "type": "object",
    "properties": {
        "rule_text": {"type": "string", "description": "Complete Sigma YAML rule"},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "category": {"type": "string", "enum": [
            "network_detection", "file_detection", "process_detection",
            "memory_detection", "behavioral"
        ]},
        "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": ["rule_text", "name", "description", "category", "severity", "confidence"],
}

YARA_GEN_SYSTEM = """\
You are a senior malware analyst and detection engineer. Write high-quality YARA rules.

Rules:
- Use valid YARA syntax.
- Include meta section with description, author, date, and CVE reference.
- Derive ALL string values from the IOCs and CVE description provided in the user message. \
  Do not invent hex byte patterns or string literals not present in the provided IOCs.
- Write strings that are specific and unlikely to produce false positives.
- Use appropriate conditions (e.g., any of them, all of ($network*), filesize < 1MB).
- For network-exploitable CVEs, write rules matching specific URL paths, HTTP headers, or \
  payload structure described. If no specific payload indicators are known, the rule MUST \
  include a comment: "// limited specificity — no payload indicators available".
- If no file, memory, or payload indicators exist, do not invent them; produce a minimal \
  rule with only confirmed strings.
"""

YARA_GEN_USER = """\
Write a YARA detection rule for this CVE.

CVE ID: {cve_id}
Description: {description}
Affected Products: {products}
ATT&CK Techniques: {techniques}
IOCs:
{iocs}

Return the YARA rule and metadata using the provided tool.
"""

YARA_GEN_SCHEMA = {
    "type": "object",
    "properties": {
        "rule_text": {"type": "string", "description": "Complete YARA rule"},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "category": {"type": "string", "enum": [
            "network_detection", "file_detection", "process_detection",
            "memory_detection", "behavioral"
        ]},
        "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": ["rule_text", "name", "description", "category", "severity", "confidence"],
}

SNORT_GEN_SYSTEM = """\
You are a network security engineer specializing in IDS/IPS rules. Write Snort/Suricata rules.

Rules:
- Use valid Snort 3 / Suricata rule syntax.
- Include sid, rev, msg, classtype, and metadata fields.
- Base ALL content match keywords exclusively on the Network IOCs provided in the user message. \
  Do not add content strings not present in the IOC list or CVE description.
- If the Network IOCs section is empty, only produce rules for patterns explicitly described in \
  the CVE description itself. Do not generate placeholder rules for undescribed traffic patterns.
- Write content matches that are specific to the exploit traffic pattern.
- Use flow:established where appropriate.
- For application-layer protocols use appropriate protocol keywords.
"""

SNORT_GEN_USER = """\
Write a Snort/Suricata network detection rule for this CVE.

CVE ID: {cve_id}
Description: {description}
Affected Products: {products}
ATT&CK Techniques: {techniques}
Network IOCs:
{iocs}

Return the Snort rule and metadata using the provided tool.
"""

SNORT_GEN_SCHEMA = {
    "type": "object",
    "properties": {
        "rule_text": {"type": "string", "description": "Complete Snort/Suricata rule"},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": ["rule_text", "name", "description", "severity", "confidence"],
}

SURICATA_GEN_SYSTEM = """\
You are a network security engineer specializing in Suricata IDS/IPS rules.

Rules:
- Use valid Suricata rule syntax with sticky buffers (http.uri, http.method, \
  http.request_body, dns.query.name, tls.sni, etc.) — NOT Snort-style modifiers \
  like http_uri or http_method.
- Include sid, rev, msg, classtype, and metadata fields.
- Base ALL content match keywords exclusively on the Network IOCs provided in the \
  user message. Do not add content strings not present in the IOC list or CVE description.
- If the Network IOCs section is empty, only produce rules for patterns explicitly described \
  in the CVE description itself. Do not generate placeholder rules for undescribed traffic.
- Use flow:established,to_server where appropriate.
- Use app-layer-protocol: for application layer matching where applicable.
"""

SURICATA_GEN_USER = """\
Write a Suricata network detection rule for this CVE.

CVE ID: {cve_id}
Description: {description}
Affected Products: {products}
ATT&CK Techniques: {techniques}
Network IOCs:
{iocs}

Return the Suricata rule and metadata using the provided tool.
"""

SURICATA_GEN_SCHEMA = {
    "type": "object",
    "properties": {
        "rule_text": {"type": "string", "description": "Complete Suricata rule"},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": ["rule_text", "name", "description", "severity", "confidence"],
}

SIGMA_FIX_USER = """\
The following Sigma rule has a syntax error. Fix it.

Error: {error}

Original rule:
{rule_text}

Return the corrected rule using the provided tool.
"""

YARA_FIX_USER = """\
The following YARA rule has a syntax error. Fix it.

Error: {error}

Original rule:
{rule_text}

Return the corrected rule using the provided tool.
"""
