"""Interface en ligne de commande de whitehat."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, report
from .models import ScanResult
from .nvd import NVDClient
from .scanner import scan

BANNER = r"""
        _     _ _       _           _
 __ __ | |_  (_) |_ ___| |_  __ _  | |_
 \ V  V / ' \| |  _/ -_) ' \/ _` | |  _|
  \_/\_/|_||_|_|\__\___|_||_\__,_|  \__|   recon + CVE
"""

NOTICE = ("⚠️  Usage strictement autorisé : ne scanne que des systèmes "
          "dont tu es propriétaire ou pour lesquels tu as un mandat écrit.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="whitehat",
        description="Scanne un site, identifie les technos et liste les CVE connues "
                    "avec explication du mécanisme et de la reproduction (cadre autorisé).",
    )
    p.add_argument("target", help="URL ou domaine cible (ex. example.com)")
    p.add_argument("--no-cve", action="store_true",
                   help="Empreinte technos uniquement, sans interroger la NVD")
    p.add_argument("--no-exploit", action="store_true",
                   help="Ne pas afficher l'explication d'exploitation/reproduction")
    p.add_argument("--max-cve", type=int, default=15,
                   help="Nombre max de CVE remontées par techno (défaut: 15)")
    p.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   help="Filtrer les CVE en dessous de cette sévérité")
    p.add_argument("--api-key", help="Clé API NVD (sinon variable NVD_API_KEY)")
    p.add_argument("--insecure", action="store_true",
                   help="Ne pas vérifier le certificat TLS")
    p.add_argument("--timeout", type=float, default=15.0, help="Timeout HTTP (s)")
    p.add_argument("--json", metavar="FICHIER", help="Exporter le rapport en JSON")
    p.add_argument("--md", metavar="FICHIER", help="Exporter le rapport en Markdown")
    p.add_argument("--html", metavar="FICHIER", nargs="?", const="whitehat-report.html",
                   help="Exporter une page HTML autonome (défaut: whitehat-report.html)")
    p.add_argument("--open", action="store_true",
                   help="Ouvrir le rapport HTML dans le navigateur après génération")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Ne pas afficher la bannière")
    p.add_argument("--version", action="version", version=f"whitehat {__version__}")
    return p


_SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _enrich_with_cve(result: ScanResult, args) -> None:
    client = NVDClient(api_key=args.api_key)
    threshold = _SEV_ORDER.get(args.min_severity or "", 0)
    n_tech = sum(1 for t in result.technologies if t.cpe_string())
    done = 0
    for tech in result.technologies:
        if not tech.cpe_string():
            continue
        done += 1
        print(f"  [NVD {done}/{n_tech}] {tech.display}…", file=sys.stderr, flush=True)
        try:
            vulns = client.query(tech, max_results=args.max_cve)
        except RuntimeError as exc:
            print(f"    ! {exc}", file=sys.stderr)
            continue
        if threshold:
            vulns = [v for v in vulns
                     if _SEV_ORDER.get((v.cvss_severity or "").upper(), 0) >= threshold]
        if vulns:
            result.vulnerabilities[tech.display] = vulns


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.quiet:
        print(BANNER, flush=True)
    print(NOTICE + "\n", file=sys.stderr, flush=True)

    # 1) Empreinte
    try:
        print(f"[*] Scan de {args.target}…", file=sys.stderr, flush=True)
        result = scan(args.target, timeout=args.timeout, verify_tls=not args.insecure)
    except Exception as exc:  # noqa: BLE001 — on veut un message propre en CLI
        print(f"[!] Échec du scan : {exc}", file=sys.stderr)
        return 2

    print(f"[+] {len(result.technologies)} techno(s) détectée(s).", file=sys.stderr)

    # 2) Enrichissement CVE
    if not args.no_cve:
        print("[*] Recherche des CVE dans la NVD (peut être long sans clé API)…",
              file=sys.stderr, flush=True)
        _enrich_with_cve(result, args)

    show_exploit = not args.no_exploit

    # 3) Rendu console
    report.render_console(result, show_exploit=show_exploit)

    # 4) Exports
    if args.json:
        Path(args.json).write_text(report.to_json(result, show_exploit), encoding="utf-8")
        print(f"[+] JSON écrit dans {args.json}", file=sys.stderr)
    if args.md:
        Path(args.md).write_text(report.to_markdown(result, show_exploit), encoding="utf-8")
        print(f"[+] Markdown écrit dans {args.md}", file=sys.stderr)
    if args.html:
        from . import htmlreport
        out = Path(args.html)
        out.write_text(htmlreport.to_html(result, show_exploit), encoding="utf-8")
        print(f"[+] Rapport HTML écrit dans {out}", file=sys.stderr)
        if args.open:
            import webbrowser
            webbrowser.open(out.resolve().as_uri())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
