"""Énumération des extensions WordPress (plugins & thèmes) + versions.

Les plugins/thèmes sont la plus grande surface de vulnérabilités de l'écosystème
WordPress. On les repère dans le HTML agrégé (chemins /wp-content/plugins|themes/)
puis on tente d'en lire la version (paramètre ?ver= ou readme.txt / style.css).

Détection uniquement (+ lecture de fichiers publics readme) : non destructif.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

import requests

from ..models import Technology

_WP_API_PLUGIN = "https://api.wordpress.org/plugins/info/1.0/{}.json"
_WP_API_THEME = "https://api.wordpress.org/themes/info/1.2/"

_PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9][a-z0-9._-]+)/", re.IGNORECASE)
_THEME_RE = re.compile(r"/wp-content/themes/([a-z0-9][a-z0-9._-]+)/", re.IGNORECASE)
_VER_QS_RE = re.compile(r"/wp-content/(?:plugins|themes)/{slug}/[^\"'?]+\?[^\"']*\bver=([\d.]+)")
_STABLE_RE = re.compile(r"(?im)^stable tag:\s*([\d.]+)")
_README_VER_RE = re.compile(r"(?im)^(?:version|=+\s*([\d.]+)\s*=+)")
_STYLE_VER_RE = re.compile(r"(?im)^\s*version:\s*([\d.]+)")


def _find_version(html: str, slug: str, kind: str, base: str,
                  session: requests.Session, timeout: float) -> str | None:
    # 1) via ?ver= dans le HTML
    m = re.search(
        r"/wp-content/" + kind + r"/" + re.escape(slug) + r"/[^\"'?]+\?[^\"']*\bver=([\d.]+)",
        html, re.IGNORECASE)
    if m:
        return m.group(1)
    # 2) via readme.txt (plugins) ou style.css (thèmes)
    try:
        if kind == "plugins":
            r = session.get(urljoin(base, f"wp-content/plugins/{slug}/readme.txt"),
                            timeout=timeout, allow_redirects=False)
            if r.status_code == 200:
                sm = _STABLE_RE.search(r.text)
                if sm:
                    return sm.group(1)
        else:
            r = session.get(urljoin(base, f"wp-content/themes/{slug}/style.css"),
                            timeout=timeout, allow_redirects=False)
            if r.status_code == 200:
                sm = _STYLE_VER_RE.search(r.text[:4000])
                if sm:
                    return sm.group(1)
    except requests.RequestException:
        pass
    return None


def latest_version(slug: str, kind: str, session: requests.Session,
                   timeout: float = 8.0) -> str | None:
    """Dernière version publiée d'un plugin/thème sur wordpress.org (ou None)."""
    try:
        if kind == "plugins":
            r = session.get(_WP_API_PLUGIN.format(slug), timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict):
                    return data.get("version")
        else:
            r = session.get(_WP_API_THEME, timeout=timeout,
                            params={"action": "theme_information", "request[slug]": slug})
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict):
                    return data.get("version")
    except (requests.RequestException, ValueError):
        return None
    return None


def version_lt(a: str, b: str) -> bool:
    """True si la version a est strictement inférieure à b (comparaison numérique)."""
    def parts(v: str) -> list[int]:
        return [int(x) if x.isdigit() else 0 for x in re.split(r"[.\-_]", v)]
    pa, pb = parts(a), parts(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return pa < pb


def enumerate_components(base_url: str, html: str, session: requests.Session,
                         timeout: float = 8.0, max_components: int = 40) -> list[Technology]:
    base = base_url if base_url.endswith("/") else base_url + "/"
    techs: list[Technology] = []

    for kind, regex, label in (("plugins", _PLUGIN_RE, "Plugin WordPress"),
                               ("themes", _THEME_RE, "Thème WordPress")):
        slugs = []
        for m in regex.finditer(html):
            s = m.group(1).lower()
            if s not in slugs:
                slugs.append(s)
        for slug in slugs[:max_components]:
            ver = _find_version(html, slug, kind, base, session, timeout)
            techs.append(Technology(
                name=f"{label} : {slug}", version=ver, categories=[label],
                evidence=[f"html → /wp-content/{kind}/{slug}/"],
                nvd_keyword=f"wordpress {slug}",
            ))
    return techs
