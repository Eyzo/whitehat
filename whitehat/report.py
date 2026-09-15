"""Rendu des résultats : console (rich), JSON et Markdown."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Optional

from . import verdict as _verdict
from .engine import recheck as _recheck
from .engine import verify as _verify
from .exploitation import guide_for
from .models import ScanResult, Vulnerability

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    _RICH = True
except ImportError:  # dégradation gracieuse si rich absent
    _RICH = False


_SEV_COLOR = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


def _sev_label(v: Vulnerability) -> str:
    sev = (v.cvss_severity or "N/A").upper()
    score = f"{v.cvss_score}" if v.cvss_score is not None else "?"
    return f"{sev} ({score})"


# --- Console ---------------------------------------------------------------
def render_console(result: ScanResult, show_exploit: bool = True) -> None:
    if not _RICH:
        _render_plain(result, show_exploit)
        return

    console = Console()
    console.print(Panel.fit(
        f"[bold]Cible[/bold] : {result.target}\n"
        f"[bold]URL finale[/bold] : {result.final_url}  "
        f"[bold]HTTP[/bold] {result.status_code}",
        title="whitehat — rapport de scan", border_style="cyan",
    ))

    # Technos
    tech_table = Table(title="Technologies détectées", show_lines=False, expand=True)
    tech_table.add_column("Techno", style="bold")
    tech_table.add_column("Version")
    tech_table.add_column("Catégorie")
    tech_table.add_column("CVE", justify="right")
    for tech in result.technologies:
        vulns = result.vulnerabilities.get(tech.display, [])
        n = len(vulns)
        cve_cell = f"[red]{n}[/red]" if n else "[green]0[/green]"
        if not tech.cpe_string():
            cve_cell = "[dim]—[/dim]"
        tech_table.add_row(tech.name, tech.version or "[dim]?[/dim]",
                           ", ".join(tech.categories) or "-", cve_cell)
    console.print(tech_table)

    # Vulnérabilités par techno
    for tech in result.technologies:
        vulns = result.vulnerabilities.get(tech.display, [])
        if not vulns:
            continue
        console.print(f"\n[bold underline]Vulnérabilités — {tech.display}[/bold underline]")
        for v in vulns:
            color = _SEV_COLOR.get((v.cvss_severity or "").upper(), "white")
            kev = " [bold bright_red]⚠ EXPLOITÉE (CISA KEV)[/bold bright_red]" if v.known_exploited else ""
            header = f"[{color}]{v.cve_id} — {_sev_label(v)}[/{color}]{kev}"
            body = v.description.strip()
            if len(body) > 400:
                body = body[:400] + "…"
            lines = [body]
            if v.cwe:
                lines.append(f"\n[dim]CWE:[/dim] {', '.join(v.cwe)}")

            if show_exploit:
                g = guide_for(v)
                lines.append(f"\n[bold]Type :[/bold] {g.cwe_title}")
                lines.append(f"[bold]Mécanisme :[/bold] {g.mechanism}")
                lines.append(f"[bold]Reproduction (cadre autorisé) :[/bold] {g.reproduction}")
                lines.append(f"[bold]Remédiation :[/bold] {g.remediation}")

            refs = v.exploit_refs or v.references
            if refs:
                lines.append("\n[bold]Références :[/bold]")
                for r in refs[:5]:
                    lines.append(f"  • {r}")

            console.print(Panel("\n".join(lines), title=header,
                                border_style=color, title_align="left"))


def _render_plain(result: ScanResult, show_exploit: bool) -> None:
    print(f"== whitehat ==\nCible: {result.target}\nURL: {result.final_url} "
          f"(HTTP {result.status_code})\n")
    for tech in result.technologies:
        vulns = result.vulnerabilities.get(tech.display, [])
        print(f"- {tech.display}  [{', '.join(tech.categories)}]  CVE: {len(vulns)}")
    for tech in result.technologies:
        for v in result.vulnerabilities.get(tech.display, []):
            print(f"\n[{tech.display}] {v.cve_id}  {_sev_label(v)}"
                  f"{'  (CISA KEV)' if v.known_exploited else ''}")
            print(f"  {v.description[:300]}")
            if show_exploit:
                g = guide_for(v)
                print(f"  Type: {g.cwe_title}")
                print(f"  Reproduction: {g.reproduction}")
                print(f"  Remédiation: {g.remediation}")


# --- Exports ---------------------------------------------------------------
def to_dict(result: ScanResult, show_exploit: bool = True) -> dict:
    sev_counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    kev = 0
    total_cve = 0
    findings_out = []
    for f in result.findings:
        fd = asdict(f)
        if f.recheck:
            fd["proof"] = _recheck.proof_info(result.final_url, f.recheck)
        findings_out.append(fd)
    out = {
        "target": result.target,
        "final_url": result.final_url,
        "status_code": result.status_code,
        "pages_crawled": result.pages_crawled,
        "technologies": [],
        "findings": findings_out,
    }
    for tech in result.technologies:
        vulns = result.vulnerabilities.get(tech.display, [])
        tech_dict = asdict(tech)
        tech_dict["vulnerabilities"] = []
        for v in vulns:
            total_cve += 1
            sev_counts[(v.cvss_severity or "INFO").upper()] = \
                sev_counts.get((v.cvss_severity or "INFO").upper(), 0) + 1
            if v.known_exploited:
                kev += 1
            vd = asdict(v)
            if show_exploit:
                g = guide_for(v)
                vd["exploit_guide"] = asdict(g)
            vd["verify_available"] = _verify.has_template(v.cve_id)
            tech_dict["vulnerabilities"].append(vd)
        out["technologies"].append(tech_dict)

    for f in result.findings:
        sev_counts[(f.severity or "INFO").upper()] = \
            sev_counts.get((f.severity or "INFO").upper(), 0) + 1

    out["summary"] = {
        "technologies": len(result.technologies),
        "cve": total_cve,
        "findings": len(result.findings),
        "kev": kev,
        "severity": sev_counts,
    }

    # Vue simple (non-experts) : note + liste d'actions en langage clair.
    # La note se base sur le décompte réel des sévérités (CVE + constats),
    # pas sur les issues regroupées, pour rester fidèle.
    issues = _verdict.build_issues(result)
    for it in issues:
        if it.get("recheck"):
            it["proof"] = _recheck.proof_info(result.final_url, it["recheck"])
    out["issues"] = issues
    out["grade"] = _verdict.compute_grade(sev_counts)
    out["summary"]["grade"] = out["grade"]["grade"]
    out["summary"]["level"] = out["grade"]["level"]
    out["summary"]["color"] = out["grade"]["color"]
    out["summary"]["important"] = out["grade"]["counts"]["CRITICAL"] + out["grade"]["counts"]["HIGH"]
    return out


def to_json(result: ScanResult, show_exploit: bool = True) -> str:
    return json.dumps(to_dict(result, show_exploit), indent=2, ensure_ascii=False)


def to_markdown(result: ScanResult, show_exploit: bool = True) -> str:
    md = [f"# Rapport whitehat — {result.target}", ""]
    md.append(f"- **URL finale** : {result.final_url}")
    md.append(f"- **HTTP** : {result.status_code}")
    md.append("")
    md.append("## Technologies détectées\n")
    md.append("| Techno | Version | Catégorie | CVE |")
    md.append("|---|---|---|---|")
    for tech in result.technologies:
        n = len(result.vulnerabilities.get(tech.display, []))
        md.append(f"| {tech.name} | {tech.version or '?'} | "
                  f"{', '.join(tech.categories) or '-'} | {n} |")
    md.append("")
    for tech in result.technologies:
        vulns = result.vulnerabilities.get(tech.display, [])
        if not vulns:
            continue
        md.append(f"## Vulnérabilités — {tech.display}\n")
        for v in vulns:
            kev = " ⚠️ **Exploitée (CISA KEV)**" if v.known_exploited else ""
            md.append(f"### {v.cve_id} — {_sev_label(v)}{kev}\n")
            md.append(v.description.strip() + "\n")
            if v.cwe:
                md.append(f"*CWE : {', '.join(v.cwe)}*\n")
            if show_exploit:
                g = guide_for(v)
                md.append(f"- **Type** : {g.cwe_title}")
                md.append(f"- **Mécanisme** : {g.mechanism}")
                md.append(f"- **Reproduction (cadre autorisé)** : {g.reproduction}")
                md.append(f"- **Remédiation** : {g.remediation}")
            refs = v.exploit_refs or v.references
            if refs:
                md.append("- **Références** :")
                for r in refs[:5]:
                    md.append(f"  - {r}")
            md.append("")
    return "\n".join(md)
