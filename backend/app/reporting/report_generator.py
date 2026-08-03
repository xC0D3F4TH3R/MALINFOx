"""
MALINFO — Professional Report Generator
Supports multiple report types: executive_summary, technical_deep_dive, mitre_matrix, kill_chain, ioc_package
Exports: HTML, PDF (via WeasyPrint), JSON, STIX 2.1, MISP, CSV
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import uuid
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import CSS, HTML

from app.config import settings
from app.network_forensics.c2_detection import extract_c2_details

_env = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
    autoescape=select_autoescape(["html"]),
)

# Custom Jinja2 filters
def filesizeformat(value: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} PB"

def tojson(value: Any, indent: int = 2) -> str:
    """JSON filter for templates."""
    return json.dumps(value, indent=indent, default=str, ensure_ascii=False)

_env.filters["filesizeformat"] = filesizeformat
_env.filters["tojson"] = tojson


class ReportGenerator:
    """Professional report generator with multiple output formats."""

    REPORT_TYPES = {
        "executive_summary": "executive_summary.html",
        "technical_deep_dive": "technical_deep_dive.html",
        "mitre_matrix": "mitre_matrix.html",
        "kill_chain": "kill_chain.html",
        "ioc_package": "ioc_package.html",
    }

    def __init__(self, tlp: str = "amber"):
        self.tlp = tlp.upper()
        self.version = "1.0.0-pilot"

    def build_full_report(
        self,
        sample,
        static_report: dict,
        sandbox_report: dict | None,
        network_report: dict | None,
        threat_intel_report: dict | None = None,
    ) -> dict:
        """Build comprehensive report data structure."""
        c2_details = extract_c2_details(network_report or {}, static_report.get("iocs", []))

        # Extract MITRE techniques from all sources
        mitre_techniques = self._extract_mitre_techniques(
            static_report, sandbox_report, network_report, threat_intel_report
        )

        # Build kill chain timeline
        kill_chain = self._build_kill_chain(static_report, sandbox_report, network_report)

        # Top IOCs for executive summary
        top_iocs = self._get_top_iocs(static_report, network_report, threat_intel_report)

        # Recommendations based on verdict
        recommendations = self._generate_recommendations(sample.verdict, sample.risk_score, mitre_techniques)

        return {
            "report_id": sample.id,
            "generated_at": dt.datetime.utcnow().isoformat() + "Z",
            "version": self.version,
            "tlp": self.tlp,
            "sample": {
                "id": sample.id,
                "original_filename": sample.original_filename,
                "file_size": sample.file_size,
                "sha256": sample.sha256,
                "sha1": sample.sha1,
                "md5": sample.md5,
                "ssdeep": sample.ssdeep,
                "file_type": sample.file_type,
                "mime_type": getattr(sample, 'mime_type', 'unknown'),
                "target_os": sample.target_os,
                "submitted_by": sample.submitted_by,
                "source": sample.source,
                "analyzed_at": getattr(sample, 'created_at', dt.datetime.utcnow()).isoformat() + "Z" if hasattr(sample, 'created_at') else dt.datetime.utcnow().isoformat() + "Z",
                "analysis_duration_sec": static_report.get("analysis_duration_sec", 0),
            },
            "verdict": sample.verdict.value if hasattr(sample.verdict, 'value') else str(sample.verdict),
            "risk_score": sample.risk_score,
            "risk_reasons": static_report.get("risk_reasons", []),
            "static_analysis": static_report,
            "dynamic_analysis": sandbox_report or {"available": False, "reason": "Not run"},
            "network_forensics": network_report or {"available": False, "reason": "Not run"},
            "threat_intel": threat_intel_report or {"available": False, "reason": "Not run"},
            "c2_servers": c2_details,
            "iocs": static_report.get("iocs", []),
            "mitre_techniques": mitre_techniques,
            "kill_chain": kill_chain,
            "top_iocs": top_iocs,
            "recommendations": recommendations,
            "executive_summary": self._generate_executive_summary(sample, static_report, sandbox_report, network_report),
            "static_done": bool(static_report),
            "sandbox_done": bool(sandbox_report and sandbox_report.get("available")),
            "network_done": bool(network_report and network_report.get("available")),
            "ti_done": bool(threat_intel_report and threat_intel_report.get("available")),
            "sandbox_score": sandbox_report.get("malscore", 0) if sandbox_report else 0,
        }

    def _extract_mitre_techniques(self, *reports) -> list[dict]:
        """Extract and deduplicate MITRE ATT&CK techniques from all reports."""
        techniques = {}
        for report in reports:
            if not report:
                continue
            # From sandbox signatures
            for sig in report.get("signatures", []):
                for mitre in sig.get("mitre", []):
                    if mitre not in techniques:
                        techniques[mitre] = {
                            "id": mitre,
                            "name": sig.get("name", ""),
                            "tactic": self._mitre_to_tactic(mitre),
                            "source": "sandbox",
                            "confidence": 0.8,
                        }
            # From network C2 indicators
            for c2 in report.get("c2_indicators", []):
                for mitre in c2.get("mitre", []):
                    if mitre not in techniques:
                        techniques[mitre] = {
                            "id": mitre,
                            "name": c2.get("name", ""),
                            "tactic": self._mitre_to_tactic(mitre),
                            "source": "network",
                            "confidence": c2.get("confidence", 0.7),
                        }
            # From threat intel
            for ind in report.get("indicators", []):
                for mitre in ind.get("mitre_techniques", []):
                    if mitre not in techniques:
                        techniques[mitre] = {
                            "id": mitre,
                            "name": ind.get("name", ""),
                            "tactic": self._mitre_to_tactic(mitre),
                            "source": "threat_intel",
                            "confidence": ind.get("confidence", 0.9),
                        }
        return list(techniques.values())

    def _mitre_to_tactic(self, technique_id: str) -> str:
        """Map technique ID to tactic (simplified)."""
        tactic_map = {
            "T1566": "Initial Access", "T1190": "Initial Access", "T1078": "Initial Access",
            "T1059": "Execution", "T1053": "Execution", "T1106": "Execution",
            "T1055": "Defense Evasion", "T1027": "Defense Evasion", "T1140": "Defense Evasion",
            "T1003": "Credential Access", "T1555": "Credential Access",
            "T1083": "Discovery", "T1082": "Discovery", "T1016": "Discovery",
            "T1071": "Command and Control", "T1090": "Command and Control", "T1573": "Command and Control",
            "T1041": "Exfiltration", "T1020": "Exfiltration",
            "T1486": "Impact", "T1490": "Impact",
        }
        # Match prefix (e.g., T1059.001 -> T1059)
        prefix = technique_id.split('.')[0]
        return tactic_map.get(prefix, "Unknown")

    def _build_kill_chain(self, *reports) -> list[dict]:
        """Build Lockheed Martin kill chain timeline."""
        phases = [
            ("Reconnaissance", []),
            ("Weaponization", []),
            ("Delivery", []),
            ("Exploitation", []),
            ("Installation", []),
            ("Command & Control", []),
            ("Actions on Objectives", []),
        ]
        # Map MITRE techniques to kill chain phases
        for report in reports:
            if not report:
                continue
            for sig in report.get("signatures", []):
                for mitre in sig.get("mitre", []):
                    phase = self._mitre_to_kill_chain(mitre)
                    for i, (p_name, p_items) in enumerate(phases):
                        if p_name == phase:
                            p_items.append({
                                "technique": mitre,
                                "description": sig.get("description", ""),
                                "timestamp": sig.get("timestamp", ""),
                                "source": "sandbox",
                            })
        return [{"phase": name, "events": items} for name, items in phases if items]

    def _mitre_to_kill_chain(self, technique_id: str) -> str:
        """Map MITRE technique to kill chain phase."""
        mapping = {
            "T1590": "Reconnaissance", "T1598": "Reconnaissance",
            "T1588": "Weaponization", "T1608": "Weaponization",
            "T1566": "Delivery", "T1189": "Delivery", "T1190": "Delivery",
            "T1203": "Exploitation", "T1211": "Exploitation",
            "T1053": "Installation", "T1547": "Installation", "T1543": "Installation",
            "T1071": "Command & Control", "T1090": "Command & Control", "T1573": "Command & Control",
            "T1005": "Actions on Objectives", "T1003": "Actions on Objectives", "T1041": "Actions on Objectives",
        }
        prefix = technique_id.split('.')[0]
        return mapping.get(prefix, "Unknown")

    def _get_top_iocs(self, *reports) -> list[dict]:
        """Get highest confidence IOCs across all reports."""
        all_iocs = []
        for report in reports:
            if not report:
                continue
            for ioc in report.get("iocs", []):
                all_iocs.append({
                    "ioc_type": ioc.get("ioc_type", ioc.get("type", "unknown")),
                    "value": ioc.get("value", ioc.get("indicator", "")),
                    "confidence": ioc.get("confidence", 0.5),
                    "context": ioc.get("context", ioc.get("description", "")),
                    "source": "static",
                })
            for ioc in report.get("network_iocs", []):
                all_iocs.append({
                    "ioc_type": ioc.get("type", "network"),
                    "value": ioc.get("dst_ip", ioc.get("query", ioc.get("url", ""))),
                    "confidence": ioc.get("confidence", 0.7),
                    "context": ioc.get("context", ""),
                    "source": "network",
                })
        # Sort by confidence, take top 20
        all_iocs.sort(key=lambda x: x["confidence"], reverse=True)
        return all_iocs[:20]

    def _generate_recommendations(self, verdict: str, risk_score: float, mitre_techniques: list) -> list[str]:
        """Generate actionable recommendations based on analysis."""
        verdict_str = verdict.value if hasattr(verdict, 'value') else str(verdict)
        recs = []

        if verdict_str == "malicious":
            recs.extend([
                "Immediately isolate affected systems from the network",
                "Block all identified IOCs (IPs, domains, hashes) at perimeter",
                "Initiate incident response procedure per organizational playbook",
                "Conduct full environment sweep for additional indicators",
                "Reset credentials for potentially compromised accounts",
                "Report to relevant authorities (CERT, law enforcement) per policy",
            ])
        elif verdict_str == "suspicious":
            recs.extend([
                "Quarantine sample and restrict execution",
                "Monitor for IOCs in environment logs (SIEM, EDR)",
                "Submit to sandbox for deeper behavioral analysis",
                "Enrich IOCs with threat intelligence feeds",
                "Review MITRE techniques for detection gaps",
            ])
        else:
            recs.extend([
                "No immediate action required",
                "Archive sample for future reference",
                "Consider adding to allowlist if false positive suspected",
            ])

        # Add MITRE-specific recommendations
        tactics = {t.get("tactic") for t in mitre_techniques}
        if "Defense Evasion" in tactics:
            recs.append("Review EDR/AV coverage for defense evasion techniques (T1055, T1027)")
        if "Command and Control" in tactics:
            recs.append("Verify DNS/proxy logging captures C2 traffic patterns (T1071, T1573)")
        if "Credential Access" in tactics:
            recs.append("Enable credential access monitoring (T1003, T1555)")

        return recs[:10]  # Limit to 10

    def _generate_executive_summary(self, sample, static_report, sandbox_report, network_report) -> str:
        """Generate executive summary text."""
        verdict_str = sample.verdict.value if hasattr(sample.verdict, 'value') else str(sample.verdict)
        risk = sample.risk_score

        verdict_text = {
            "malicious": "CONFIRMED MALICIOUS",
            "suspicious": "SUSPICIOUS - REQUIRES INVESTIGATION",
            "clean": "CLEAN - NO THREATS DETECTED",
            "unknown": "UNKNOWN - INSUFFICIENT DATA",
        }.get(verdict_str, verdict_str.upper())

        parts = [
            f"Sample '{sample.original_filename}' ({sample.file_type}) analyzed by MALINFO.",
            f"Verdict: {verdict_text} (Risk Score: {risk:.1f}/100).",
        ]

        if static_report:
            yara_count = len(static_report.get("yara", {}).get("matches", []))
            ioc_count = len(static_report.get("iocs", []))
            if yara_count:
                parts.append(f"Static analysis triggered {yara_count} YARA rule(s) and extracted {ioc_count} IOC(s).")

        if sandbox_report and sandbox_report.get("available"):
            parts.append(f"Dynamic sandbox execution (malscore: {sandbox_report.get('malscore', 0)}) "
                        f"observed {len(sandbox_report.get('signatures', []))} behavioral signatures "
                        f"mapping to {len(self._extract_mitre_techniques(sandbox_report))} MITRE ATT&CK technique(s).")

        if network_report and network_report.get("available"):
            if network_report.get("beaconing_detected"):
                parts.append("Network forensics detected beaconing behavior indicative of C2 communication.")
            c2_count = len(network_report.get("c2_indicators", []))
            if c2_count:
                parts.append(f"Identified {c2_count} potential C2 server(s) with network IOC correlation.")

        if verdict_str in ("malicious", "suspicious"):
            parts.append("Immediate containment and investigation recommended per organizational policy.")

        return " ".join(parts)

    def render_html(self, report: dict, report_type: str = "technical_deep_dive") -> str:
        """Render report to HTML."""
        template_name = self.REPORT_TYPES.get(report_type, "technical_deep_dive.html")
        template = _env.get_template(template_name)

        # Add CSS to template context
        with open(Path(__file__).parent / "templates" / "report_style.css") as f:
            css = f.read()

        return template.render(report=report, css_style=css)

    def render_pdf(self, html: str, output_path: Path) -> Path:
        """Render HTML to PDF using WeasyPrint."""
        html_doc = HTML(string=html, base_url=str(settings.REPORT_DIR))
        css = CSS(string=self._get_pdf_css())
        html_doc.write_pdf(str(output_path), stylesheets=[css])
        return output_path

    def _get_pdf_css(self) -> str:
        """Additional CSS for PDF output."""
        return """
        @page { size: A4; margin: 2cm; @bottom-center { content: counter(page); } }
        .report-container { box-shadow: none; border: 1px solid #ccc; }
        .verdict-malicious { background: #dc3545 !important; -webkit-print-color-adjust: exact; }
        .verdict-suspicious { background: #ffc107 !important; color: #333 !important; -webkit-print-color-adjust: exact; }
        .verdict-clean { background: #28a745 !important; -webkit-print-color-adjust: exact; }
        .tlp-red { background: #dc3545 !important; -webkit-print-color-adjust: exact; }
        .tlp-amber { background: #ffc107 !important; color: #333 !important; -webkit-print-color-adjust: exact; }
        .tlp-green { background: #28a745 !important; -webkit-print-color-adjust: exact; }
        .report-tabs { display: none; }
        .tab-pane { display: block !important; page-break-before: always; }
        .tab-pane:first-of-type { page-break-before: auto; }
        .json-output, .strings-output { max-height: none; overflow: visible; font-size: 8px; }
        .mitre-matrix { display: block; }
        .mitre-tactic-column { page-break-inside: avoid; }
        """

    def export_json(self, report: dict, output_path: Path) -> Path:
        """Export report as JSON."""
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        return output_path

    def export_stix(self, report: dict, output_path: Path) -> Path:
        """Export IOCs as STIX 2.1 bundle."""
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": [],
        }

        # Add malware object
        malware_obj = {
            "type": "malware",
            "spec_version": "2.1",
            "id": f"malware--{uuid.uuid4()}",
            "created": report["generated_at"],
            "modified": report["generated_at"],
            "name": report["sample"]["original_filename"],
            "description": f"MALINFO analysis of {report['sample']['original_filename']}",
            "malware_types": [report["sample"]["file_type"].lower()],
            "is_family": False,
            "labels": [report["verdict"]],
        }
        bundle["objects"].append(malware_obj)

        # Add indicator objects
        for ioc in report.get("iocs", []):
            pattern = self._ioc_to_stix_pattern(ioc)
            if pattern:
                indicator = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": report["generated_at"],
                    "modified": report["generated_at"],
                    "name": f"{ioc.get('ioc_type', 'ioc')}: {ioc.get('value', '')}",
                    "description": ioc.get("context", ""),
                    "indicator_types": ["malicious-activity"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": report["generated_at"],
                    "confidence": int(ioc.get("confidence", 0.5) * 100),
                    "labels": ["malicious-activity"],
                }
                bundle["objects"].append(indicator)

                # Add relationship
                bundle["objects"].append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": report["generated_at"],
                    "modified": report["generated_at"],
                    "relationship_type": "indicates",
                    "source_ref": indicator["id"],
                    "target_ref": malware_obj["id"],
                })

        with open(output_path, "w") as f:
            json.dump(bundle, f, indent=2)
        return output_path

    def _ioc_to_stix_pattern(self, ioc: dict) -> str | None:
        """Convert IOC to STIX pattern."""
        ioc_type = ioc.get("ioc_type", "").lower()
        value = ioc.get("value", "")
        if not value:
            return None

        patterns = {
            "ipv4": f"[ipv4-addr:value = '{value}']",
            "ipv6": f"[ipv6-addr:value = '{value}']",
            "domain": f"[domain-name:value = '{value}']",
            "url": f"[url:value = '{value}']",
            "email": f"[email-addr:value = '{value}']",
            "sha256": f"[file:hashes.'SHA-256' = '{value}']",
            "sha1": f"[file:hashes.'SHA-1' = '{value}']",
            "md5": f"[file:hashes.MD5 = '{value}']",
            "mutex": f"[mutex:name = '{value}']",
            "registry_key": f"[windows-registry-key:key = '{value}']",
        }
        return patterns.get(ioc_type)

    def export_misp(self, report: dict, output_path: Path) -> Path:
        """Export as MISP event JSON."""
        event = {
            "Event": {
                "info": f"MALINFO Analysis - {report['sample']['original_filename']}",
                "date": report["generated_at"][:10],
                "threat_level_id": self._verdict_to_misp_threat(report["verdict"]),
                "analysis": 2,  # completed
                "distribution": 3,  # connected communities
                "Attribute": [],
                "Tag": [{"name": f"tlp:{self.tlp.lower()}"}, {"name": f"malinfo:verdict={report['verdict']}"}],
            }
        }

        for ioc in report.get("iocs", []):
            attr = self._ioc_to_misp_attribute(ioc)
            if attr:
                event["Event"]["Attribute"].append(attr)

        with open(output_path, "w") as f:
            json.dump(event, f, indent=2)
        return output_path

    def _verdict_to_misp_threat(self, verdict: str) -> str:
        mapping = {"malicious": "1", "suspicious": "2", "clean": "4", "unknown": "3"}
        return mapping.get(str(verdict).lower(), "3")

    def _ioc_to_misp_attribute(self, ioc: dict) -> dict | None:
        """Convert IOC to MISP attribute."""
        ioc_type = ioc.get("ioc_type", "").lower()
        value = ioc.get("value", "")
        if not value:
            return None

        type_map = {
            "ipv4": "ip-src", "ipv6": "ip-src",
            "domain": "domain", "url": "url",
            "email": "email-src", "sha256": "sha256",
            "sha1": "sha1", "md5": "md5",
            "mutex": "mutex", "registry_key": "regkey",
        }
        misp_type = type_map.get(ioc_type)
        if not misp_type:
            return None

        return {
            "type": misp_type,
            "value": value,
            "comment": ioc.get("context", ""),
            "to_ids": True,
            "confidence": int(ioc.get("confidence", 0.5) * 100),
        }

    def export_csv(self, report: dict, output_path: Path) -> Path:
        """Export IOCs as CSV."""
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Value", "Confidence", "Source", "Context", "First Seen", "Last Seen", "Tags"])
            for ioc in report.get("iocs", []):
                writer.writerow([
                    ioc.get("ioc_type", ""),
                    ioc.get("value", ""),
                    ioc.get("confidence", ""),
                    "static",
                    ioc.get("context", ""),
                    report["generated_at"],
                    report["generated_at"],
                    f"malinfo,verdict:{report['verdict']}",
                ])
        return output_path

    def save_all_formats(self, report: dict, base_path: Path) -> dict[str, Path]:
        """Save report in all supported formats."""
        base_path = Path(base_path)
        base_path.parent.mkdir(parents=True, exist_ok=True)

        results = {}

        # HTML (technical deep-dive)
        html = self.render_html(report, "technical_deep_dive")
        html_path = base_path.with_suffix(".html")
        with open(html_path, "w") as f:
            f.write(html)
        results["html"] = html_path

        # Executive Summary HTML
        exec_html = self.render_html(report, "executive_summary")
        exec_path = base_path.with_name(f"{base_path.stem}_executive.html")
        with open(exec_path, "w") as f:
            f.write(exec_html)
        results["executive_html"] = exec_path

        # PDF
        try:
            pdf_path = base_path.with_suffix(".pdf")
            self.render_pdf(html, pdf_path)
            results["pdf"] = pdf_path
        except Exception as e:
            results["pdf_error"] = str(e)

        # JSON
        json_path = base_path.with_suffix(".json")
        self.export_json(report, json_path)
        results["json"] = json_path

        # STIX
        stix_path = base_path.with_suffix(".stix.json")
        self.export_stix(report, stix_path)
        results["stix"] = stix_path

        # MISP
        misp_path = base_path.with_suffix(".misp.json")
        self.export_misp(report, misp_path)
        results["misp"] = misp_path

        # CSV
        csv_path = base_path.with_suffix(".csv")
        self.export_csv(report, csv_path)
        results["csv"] = csv_path

        return results


# Backward compatibility functions
def build_full_report(sample, static_report: dict, sandbox_report: dict | None, network_report: dict | None) -> dict:
    generator = ReportGenerator()
    return generator.build_full_report(sample, static_report, sandbox_report, network_report)


def render_html_report(report: dict) -> str:
    generator = ReportGenerator()
    return generator.render_html(report, "technical_deep_dive")


def save_report(sample_id: str, report: dict, html: str) -> tuple[Path, Path]:
    import json
    json_path = settings.REPORT_DIR / f"{sample_id}.json"
    html_path = settings.REPORT_DIR / f"{sample_id}.html"
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    with open(html_path, "w") as f:
        f.write(html)
    return json_path, html_path