"""Énumération d'extensions pour d'autres CMS (Drupal, Joomla, PrestaShop).

Même principe que WordPress : repérer les extensions dans le HTML agrégé, en
tirer une version si possible, et préparer une recherche CVE par mots-clés NVD.
On n'active chaque énumération que si le CMS correspondant est détecté (évite les
faux positifs sur des chemins génériques comme /modules/ ou /themes/).
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

import requests

from ..models import Technology

# Drupal : modules et thèmes (contrib/custom, core, multisite)
_DRUPAL_MODULE = re.compile(
    r"/(?:sites/[^/\"']+/|core/)?modules/(?:contrib/|custom/)?([a-z0-9_]+)/", re.I)
_DRUPAL_THEME = re.compile(
    r"/(?:sites/[^/\"']+/|core/)?themes/(?:contrib/|custom/)?([a-z0-9_]+)/", re.I)
# PrestaShop : modules
_PRESTA_MODULE = re.compile(r"/modules/([a-z0-9][a-z0-9_-]+)/", re.I)
# Joomla : composants
_JOOMLA_COM = re.compile(r"(?:option=com_|/components/com_)([a-z0-9_]+)", re.I)

_DRUPAL_VER_YML = re.compile(r"(?im)^\s*version:\s*['\"]?([\w.\-]+)['\"]?")

# slugs à ignorer (dossiers génériques, faux positifs)
_IGNORE = {"contrib", "custom", "all", "default", "system", "assets", "files"}


def _versioned_slugs(regex: re.Pattern, html: str, limit: int) -> list[str]:
    slugs: list[str] = []
    for m in regex.finditer(html):
        s = m.group(1).lower()
        if s in _IGNORE or s in slugs:
            continue
        slugs.append(s)
        if len(slugs) >= limit:
            break
    return slugs


def _drupal_version(base: str, slug: str, session: requests.Session, timeout: float) -> str | None:
    for path in (f"modules/contrib/{slug}/{slug}.info.yml",
                 f"modules/{slug}/{slug}.info.yml"):
        try:
            r = session.get(urljoin(base, path), timeout=timeout, allow_redirects=False)
            if r.status_code == 200:
                m = _DRUPAL_VER_YML.search(r.text)
                if m:
                    return m.group(1)
        except requests.RequestException:
            continue
    return None


def enumerate_components(base_url: str, html: str, session: requests.Session,
                         cms_names: set[str], timeout: float = 8.0,
                         max_components: int = 30) -> list[Technology]:
    base = base_url if base_url.endswith("/") else base_url + "/"
    techs: list[Technology] = []

    if "Drupal" in cms_names:
        for slug in _versioned_slugs(_DRUPAL_MODULE, html, max_components):
            ver = _drupal_version(base, slug, session, timeout)
            techs.append(Technology(name=f"Module Drupal : {slug}", version=ver,
                                    categories=["Module Drupal"],
                                    evidence=[f"html → modules/{slug}/"],
                                    nvd_keyword=f"drupal {slug}"))
        for slug in _versioned_slugs(_DRUPAL_THEME, html, max_components):
            techs.append(Technology(name=f"Thème Drupal : {slug}", version=None,
                                    categories=["Thème Drupal"],
                                    evidence=[f"html → themes/{slug}/"],
                                    nvd_keyword=f"drupal {slug}"))

    if "PrestaShop" in cms_names:
        for slug in _versioned_slugs(_PRESTA_MODULE, html, max_components):
            techs.append(Technology(name=f"Module PrestaShop : {slug}", version=None,
                                    categories=["Module PrestaShop"],
                                    evidence=[f"html → modules/{slug}/"],
                                    nvd_keyword=f"prestashop {slug}"))

    if "Joomla" in cms_names:
        for slug in _versioned_slugs(_JOOMLA_COM, html, max_components):
            techs.append(Technology(name=f"Composant Joomla : com_{slug}", version=None,
                                    categories=["Extension Joomla"],
                                    evidence=[f"html → com_{slug}"],
                                    nvd_keyword=f"joomla {slug}"))

    return techs
