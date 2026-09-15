"""Orchestrateur : enchaîne toutes les étapes d'un scan complet.

Ordre : fetch → découverte (robots/sitemap) → crawl guidé → empreintes →
extensions WordPress → CVE (NVD par CPE) → CVE librairies (OSV) →
EPSS + risque → audit hygiène → expositions → (Nuclei) → tri.

Un callback `on_progress(stage, message, pct)` alimente la barre de chargement.
Les clés d'étape (`stage`) sont stables et connues de l'UI : voir STAGES.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urljoin

import requests

from . import fingerprints, scanner
from .engine import crawl as crawl_mod
from .engine import discovery as disc_mod
from .engine import (cms, exposures, headers_audit, libdetect, manifests,
                     npmreg, nuclei, osv, retirejs, risk, wordpress)
from .models import Finding, ScanResult, Technology
from .nvd import NVDClient

Progress = Callable[[str, str, int], None]

# Étapes affichées par la barre de chargement (ordre + libellé clair)
STAGES = [
    ("fetch", "Connexion au site"),
    ("discovery", "Lecture du robots.txt et du sitemap"),
    ("crawl", "Parcours des pages"),
    ("fingerprint", "Identification des technologies"),
    ("wordpress", "Extensions WordPress"),
    ("cve", "Recherche des failles connues"),
    ("osv", "Failles des librairies"),
    ("risk", "Calcul du niveau de risque"),
    ("audit", "Vérification des protections"),
    ("exposure", "Fichiers exposés"),
    ("nuclei", "Analyse approfondie"),
    ("done", "Terminé"),
]


@dataclass
class ScanOptions:
    crawl: bool = True
    use_sitemap: bool = True
    max_pages: int = 20
    max_depth: int = 2
    do_cve: bool = True
    do_osv: bool = True
    do_retire: bool = True        # signatures de contenu (libs minifiées/bundlées)
    do_wordpress: bool = True
    do_cms: bool = True           # extensions Drupal/Joomla/PrestaShop
    do_deps: bool = True          # lire les manifestes de dépendances exposés
    wp_max: int = 12              # nb max de plugins/thèmes WP interrogés en CVE
    max_cve: int = 15
    min_severity: Optional[str] = None
    do_audit: bool = True
    do_exposures: bool = True
    do_nuclei: bool = False
    nuclei_severities: str = "low,medium,high,critical"
    timeout: float = 15.0
    verify_tls: bool = True
    api_key: Optional[str] = None


_SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _noop(stage: str, message: str, pct: int) -> None:  # pragma: no cover
    pass


_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)


def _norm_lib(name: str) -> str:
    n = re.sub(r"[^a-z0-9]", "", name.lower())
    if n.endswith("js") and len(n) > 2:
        n = n[:-2]
    return n


def _collect_scripts(final_url: str, html: str, session: requests.Session,
                     timeout: float, max_files: int = 25) -> list[tuple[str, str]]:
    """Récupère le contenu des scripts (pour l'analyse de signatures) + l'inline."""
    assets: list[tuple[str, str]] = [("inline", html[:500_000])]
    seen: set[str] = set()
    for src in _SCRIPT_SRC_RE.findall(html):
        url = urljoin(final_url, src)
        base = url.split("#")[0]
        if url in seen or not re.search(r"\.js(\?|$)", base, re.I):
            continue
        seen.add(url)
        if len(assets) > max_files:
            break
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code == 200 and len(r.content) < 3_000_000:
                assets.append((url, r.text))
        except requests.RequestException:
            continue
    return assets


def _merge_vulns(existing: list, extra: list) -> list:
    """Ajoute `extra` à `existing` sans doublon de CVE (par identifiant)."""
    seen = {v.cve_id for v in existing}
    for v in extra:
        if v.cve_id not in seen:
            existing.append(v)
            seen.add(v.cve_id)
    return existing


def run(target: str, options: Optional[ScanOptions] = None,
        on_progress: Progress = _noop) -> ScanResult:
    opt = options or ScanOptions()

    # 1) Fetch initial
    on_progress("fetch", f"Connexion à {target}…", 4)
    f = scanner.fetch(target, timeout=opt.timeout, verify_tls=opt.verify_tls)

    # 2) Découverte robots.txt / sitemap
    seeds: list[str] = []
    disc = None
    if opt.use_sitemap:
        on_progress("discovery", "Lecture du robots.txt et du sitemap…", 10)
        disc = disc_mod.discover(f.final_url, f.session, timeout=opt.timeout,
                                 max_urls=max(opt.max_pages * 5, 100))
        seeds = disc.seeds(f.final_url, limit=opt.max_pages * 4)
        on_progress("discovery",
                    f"{len(disc.sitemap_urls)} URL(s) via sitemap, "
                    f"{len(disc.robots_paths)} via robots.txt.", 14)

    # 3) Crawl guidé
    merged_html = f.html
    pages = 1
    if opt.crawl:
        on_progress("crawl", "Parcours des pages internes…", 18)
        pages, merged_html, _ = crawl_mod.crawl(
            f.final_url, f.session, max_pages=opt.max_pages, max_depth=opt.max_depth,
            timeout=opt.timeout, first_html=f.html, seed_urls=seeds)
        on_progress("crawl", f"{pages} page(s) analysée(s).", 26)

    # 4) Empreintes
    on_progress("fingerprint", "Identification des technologies…", 30)
    technologies = fingerprints.detect(f.headers, f.cookie_names, merged_html)

    result = ScanResult(
        target=target, final_url=f.final_url, status_code=f.status_code,
        server_headers=f.headers, technologies=technologies, pages_crawled=pages,
    )

    # 5) Extensions WordPress
    is_wp = any(t.name == "WordPress" for t in technologies)
    wp_comps: list = []
    if opt.do_wordpress and is_wp:
        on_progress("wordpress", "Recherche des plugins/thèmes WordPress…", 34)
        wp_comps = wordpress.enumerate_components(f.final_url, merged_html, f.session,
                                                  timeout=opt.timeout)
        technologies.extend(wp_comps)
        on_progress("wordpress", f"{len(wp_comps)} extension(s) WordPress détectée(s).", 36)

        # Obsolescence (plugins ET thèmes) : version installée vs dernière sur wordpress.org
        on_progress("wordpress", "Vérification des versions (obsolescence)…", 37)
        for tech in wp_comps[:opt.wp_max]:
            slug = (tech.nvd_keyword or "").split()[-1] if tech.nvd_keyword else None
            if not slug or not tech.version:
                continue
            kind = "themes" if (tech.categories and "Thème" in tech.categories[0]) else "plugins"
            latest = wordpress.latest_version(slug, kind, f.session, opt.timeout)
            if latest and wordpress.version_lt(tech.version, latest):
                result.findings.append(Finding(
                    category="wordpress",
                    title=f"{tech.categories[0]} obsolète : {slug}",
                    severity="MEDIUM",
                    detail=f"Version installée {tech.version}, dernière disponible {latest}.",
                    remediation="Mettre à jour cette extension vers la dernière version "
                                "(les versions obsolètes cumulent souvent des failles connues).",
                    source="wordpress.org"))

    # 5a) Autres CMS (Drupal, Joomla, PrestaShop) — même approche que WordPress
    if opt.do_cms:
        cms_names = {t.name for t in technologies}
        if cms_names & {"Drupal", "Joomla", "PrestaShop"}:
            on_progress("wordpress", "Recherche des extensions CMS (Drupal/Joomla/PrestaShop)…", 38)
            cms_comps = cms.enumerate_components(f.final_url, merged_html, f.session,
                                                 cms_names, timeout=opt.timeout)
            technologies.extend(cms_comps)
            if cms_comps:
                on_progress("wordpress", f"{len(cms_comps)} extension(s) CMS détectée(s).", 39)

    # 5b) Librairies front-end génériques (CDN + fichiers versionnés)
    if opt.do_osv:
        libs = libdetect.detect_libraries(merged_html, existing=technologies)
        technologies.extend(libs)
        if libs:
            on_progress("fingerprint", f"{len(libs)} librairie(s) supplémentaire(s).", 39)

    on_progress("fingerprint", f"{len(technologies)} technologie(s) au total.", 40)

    # 6) CVE — refléter l'état du site à l'instant T (NVD CPE + OSV + WP + manifestes)
    if opt.do_cve:
        client = NVDClient(api_key=opt.api_key)
        threshold = _SEV_ORDER.get((opt.min_severity or "").upper(), 0)

        # a) NVD par CPE (technos avec CPE fiable)
        cpe_techs = [t for t in technologies if t.cpe_string()]
        for i, tech in enumerate(cpe_techs):
            on_progress("cve", f"Failles connues : {tech.display}",
                        40 + int(12 * (i / max(1, len(cpe_techs)))))
            try:
                vulns = client.query(tech, max_results=opt.max_cve)
            except RuntimeError as exc:
                on_progress("cve", f"! {exc}", 45)
                continue
            if vulns:
                _merge_vulns(result.vulnerabilities.setdefault(tech.display, []), vulns)

        # b) OSV pour toutes les librairies détectées (npm/Packagist…)
        if opt.do_osv:
            lib_techs = [(t, osv.package_for(t), osv.ecosystem_for(t))
                         for t in technologies]
            lib_techs = [(t, p, e) for t, p, e in lib_techs if p and t.version]
            for i, (tech, pkg, eco) in enumerate(lib_techs):
                on_progress("osv", f"Librairies : {tech.display}",
                            52 + int(6 * (i / max(1, len(lib_techs)))))
                extra = osv.query(pkg, tech.version, eco)
                if extra:
                    _merge_vulns(result.vulnerabilities.setdefault(tech.display, []), extra)

        # b2) Signatures retire.js sur le contenu des scripts (libs minifiées/bundlées)
        if opt.do_retire:
            on_progress("osv", "Analyse du contenu des scripts (signatures)…", 57)
            assets = _collect_scripts(f.final_url, merged_html, f.session, opt.timeout)
            dets = retirejs.detect(assets)
            # index des technos existantes (par nom normalisé + version, et sans version)
            exact = {(_norm_lib(t.name), t.version): t.display
                     for t in result.technologies if t.version}
            nameless = {_norm_lib(t.name): t for t in result.technologies if not t.version}
            for d in dets:
                if not d["vulns"]:
                    continue
                nk = _norm_lib(d["name"])
                disp = exact.get((nk, d["version"]))
                if disp is None and nk in nameless:
                    t = nameless.pop(nk)          # complète une empreinte sans version
                    t.version = d["version"]
                    disp = t.display
                    exact[(nk, d["version"])] = disp
                if disp is None:
                    disp = f"{d['name']} {d['version']}"
                    result.technologies.append(Technology(
                        name=d["name"], version=d["version"],
                        categories=["Librairie JS (signature)"],
                        evidence=[f"retire.js ({d['source']})"]))
                    exact[(nk, d["version"])] = disp
                _merge_vulns(result.vulnerabilities.setdefault(disp, []), d["vulns"])

        # b3) Obsolescence des librairies JS : version installée vs dernière sur npm
        if opt.do_osv:
            on_progress("osv", "Vérification des versions de librairies…", 58)
            seen_lib: set[str] = set()
            for tech in list(result.technologies):
                pkg = osv.package_for(tech)
                if not (pkg and tech.version and osv.ecosystem_for(tech) == "npm"):
                    continue
                if pkg.lower() in seen_lib:
                    continue
                seen_lib.add(pkg.lower())
                latest = npmreg.latest_version(pkg, f.session, opt.timeout)
                if latest and wordpress.version_lt(tech.version, latest):
                    result.findings.append(Finding(
                        category="library",
                        title=f"Librairie obsolète : {pkg}",
                        severity="LOW",
                        detail=f"Version installée {tech.version}, dernière disponible {latest} (npm).",
                        remediation="Mettre à jour la librairie ; une version très en retard "
                                    "cumule souvent des failles connues.",
                        source="npm"))

        # c) Extensions CMS (WordPress/Drupal/Joomla/PrestaShop) : OSV Packagist + NVD mots-clés
        kw_techs = [t for t in technologies if t.nvd_keyword]
        for i, tech in enumerate(kw_techs[:opt.wp_max]):
            kw = tech.nvd_keyword
            slug = kw.split()[-1]
            on_progress("cve", f"Extensions : {tech.name}",
                        60 + int(3 * (i / max(1, len(kw_techs)))))
            ext_vulns = []
            if kw.startswith("wordpress") and tech.version:
                for cand in (f"{slug}/{slug}", f"wpackagist-plugin/{slug}",
                             f"wpackagist-theme/{slug}"):
                    ext_vulns += osv.query(cand, tech.version, "Packagist")
            ext_vulns += client.query_keyword(kw, max_results=5)
            if ext_vulns:
                _merge_vulns(result.vulnerabilities.setdefault(tech.display, []), ext_vulns)

        # d) Dépendances issues des manifestes exposés (versions exactes) → OSV
        if opt.do_deps:
            on_progress("osv", "Lecture des manifestes de dépendances…", 60)
            deps = manifests.collect(f.final_url, f.session, timeout=opt.timeout)
            existing_disp = {t.display for t in result.technologies}
            for i, dep in enumerate(deps):
                if i % 10 == 0:
                    on_progress("osv", f"Dépendances : {i+1}/{len(deps)}…", 61)
                dv = osv.query(dep["package"], dep["version"], dep["ecosystem"])
                if not dv:
                    continue
                disp = f"{dep['package']} {dep['version']}"
                if disp not in existing_disp:  # évite les doublons librairie/dépendance
                    result.technologies.append(Technology(
                        name=dep["package"], version=dep["version"],
                        categories=[f"Dépendance {dep['ecosystem']}"],
                        evidence=[f"manifeste {dep['source']}"]))
                    existing_disp.add(disp)
                _merge_vulns(result.vulnerabilities.setdefault(disp, []), dv)

        # Filtre de sévérité + EPSS + risque
        for disp in list(result.vulnerabilities):
            if threshold:
                result.vulnerabilities[disp] = [
                    v for v in result.vulnerabilities[disp]
                    if _SEV_ORDER.get((v.cvss_severity or "").upper(), 0) >= threshold]
        all_v = result.all_vulns()
        if all_v:
            on_progress("risk", "Calcul du niveau de risque (EPSS)…", 66)
            risk.enrich_epss(all_v)
            risk.apply_risk(all_v)

    # 7) Audit d'hygiène
    if opt.do_audit:
        on_progress("audit", "Vérification des protections (en-têtes/TLS/cookies)…", 72)
        result.findings += headers_audit.audit_headers(f.headers)
        result.findings += headers_audit.audit_cookies(f.set_cookie_raw)
        result.findings += headers_audit.audit_tls(f.final_url, timeout=opt.timeout)

    # 8) Expositions
    if opt.do_exposures:
        on_progress("exposure", "Recherche de fichiers/chemins exposés…", 80)
        result.findings += exposures.scan_exposures(f.final_url, f.session, timeout=opt.timeout)

    # 9) Nuclei
    if opt.do_nuclei:
        if not nuclei.is_available():
            on_progress("nuclei", "Analyse approfondie indisponible (Nuclei non installé).", 92)
        else:
            on_progress("nuclei", "Analyse approfondie (Nuclei) — démarrage…", 80)
            state = {"matched": 0}

            def _cb(finding):
                state["matched"] += 1

            def _stats(d):
                pct = d.get("percent")
                if pct is None and d.get("total"):
                    pct = 100.0 * d.get("requests", 0) / max(1, d["total"])
                if pct is not None:
                    pct = max(0.0, min(100.0, float(pct)))
                    mapped = 80 + int(0.17 * pct)   # 80 → 97
                    on_progress("nuclei",
                                f"Analyse approfondie… {int(pct)}% ({state['matched']} détection(s))",
                                mapped)

            try:
                result.findings += nuclei.run(
                    f.final_url, severities=opt.nuclei_severities,
                    on_line=_cb, on_stats=_stats)
            except RuntimeError as exc:
                on_progress("nuclei", f"! {exc}", 96)

    result.findings.sort(key=lambda x: x.severity_rank(), reverse=True)
    on_progress("done", "Analyse terminée.", 100)
    return result
