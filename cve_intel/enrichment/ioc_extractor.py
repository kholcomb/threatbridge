"""IOC extraction — deterministic regex + Claude-powered inference."""

import re
from urllib.parse import urlparse

from cve_intel.enrichment.claude_client import ClaudeClient
from cve_intel.enrichment.prompts import (
    IOC_EXTRACTOR_SYSTEM,
    IOC_EXTRACTOR_USER,
    IOC_EXTRACTOR_SCHEMA,
)
from cve_intel.models.attack import AttackMapping
from cve_intel.models.cve import CVERecord
from cve_intel.models.ioc import IOC, IOCBundle, IOCConfidence, IOCType

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_HASH_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_HASH_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_CVE_URL_RE = re.compile(r"https?://[^\s\"'>]+")


class IOCExtractor:
    def __init__(self, client: ClaudeClient) -> None:
        self._client = client

    def extract(self, cve: CVERecord, mapping: AttackMapping) -> IOCBundle:
        bundle = IOCBundle(cve_id=cve.cve_id)

        # Deterministic extraction from references
        self._extract_from_refs(cve, bundle)

        # Claude-powered extraction from description text
        self._extract_via_claude(cve, mapping, bundle)

        return bundle

    def _extract_from_refs(self, cve: CVERecord, bundle: IOCBundle) -> None:
        for ref in cve.references:
            url = ref.url
            if not url:
                continue
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # Skip well-known advisory sources
            if any(d in domain for d in [
                "nvd.nist.gov", "cve.mitre.org", "github.com", "microsoft.com",
                "redhat.com", "ubuntu.com", "debian.org", "mozilla.org",
            ]):
                continue
            # Flag potentially malicious or PoC domains in references
            if domain and "exploit" in url.lower() or "poc" in url.lower():
                bundle.network.append(IOC(
                    ioc_type=IOCType.URL,
                    value=url,
                    confidence=IOCConfidence.LOW,
                    context="Found in CVE reference — may be PoC or exploit resource",
                    source="nvd_references",
                ))

    def _extract_via_claude(
        self, cve: CVERecord, mapping: AttackMapping, bundle: IOCBundle
    ) -> None:
        cvss = cve.primary_cvss
        techniques_text = ", ".join(
            f"{t.technique_id} ({t.name})" for t in mapping.techniques[:8]
        ) or "N/A"

        user_msg = IOC_EXTRACTOR_USER.format(
            cve_id=cve.cve_id,
            description=cve.description_en[:2000],
            products=", ".join(cve.affected_products[:10]) or "N/A",
            techniques=techniques_text,
            cvss_score=cvss.base_score if cvss else "N/A",
            cvss_severity=cvss.base_severity.value if cvss else "N/A",
            cvss_vector=cvss.vector_string if cvss else "N/A",
            cwes=", ".join(cve.weaknesses) or "N/A",
        )

        result = self._client.complete_structured(
            system=IOC_EXTRACTOR_SYSTEM,
            user=user_msg,
            output_schema=IOC_EXTRACTOR_SCHEMA,
            tool_name="extract_iocs",
        )

        technique_ids = [t.technique_id for t in mapping.techniques]

        for raw_ioc in result.get("network_iocs", []):
            bundle.network.append(self._build_ioc(raw_ioc, technique_ids, "claude_extraction"))

        for raw_ioc in result.get("file_iocs", []):
            bundle.file.append(self._build_ioc(raw_ioc, technique_ids, "claude_extraction"))

        for raw_ioc in result.get("process_iocs", []):
            bundle.process.append(self._build_ioc(raw_ioc, technique_ids, "claude_extraction"))

        for raw_ioc in result.get("behavioral_iocs", []):
            bundle.behavioral.append(self._build_ioc(raw_ioc, technique_ids, "claude_extraction"))

    def _build_ioc(self, raw: dict, technique_ids: list[str], source: str) -> IOC:
        try:
            ioc_type = IOCType(raw["ioc_type"])
        except ValueError:
            ioc_type = IOCType.BEHAVIORAL
        try:
            confidence = IOCConfidence(raw["confidence"])
        except ValueError:
            confidence = IOCConfidence.INFERRED

        return IOC(
            ioc_type=ioc_type,
            value=raw.get("value", ""),
            confidence=confidence,
            context=raw.get("context", ""),
            source=source,
            related_technique_ids=technique_ids,
        )
