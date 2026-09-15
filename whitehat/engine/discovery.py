"""Découverte d'URLs via robots.txt et sitemap(s).

Sert de graine au crawler : au lieu de deviner les pages en suivant les liens,
on lit d'abord ce que le site déclare lui-même (sitemaps + chemins du robots),
ce qui élargit fortement la couverture et cible des pages utiles.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import requests

_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_SITEMAP_RE = re.compile(r"(?im)^\s*sitemap:\s*(\S+)")
_RULE_RE = re.compile(r"(?im)^\s*(dis)?allow:\s*(\S+)")


class Discovery:
    def __init__(self):
        self.robots_found = False
        self.sitemaps: list[str] = []
        self.sitemap_urls: list[str] = []      # pages listées dans les sitemaps
        self.robots_paths: list[str] = []      # chemins Allow/Disallow (endpoints candidats)

    def seeds(self, base_url: str, limit: int = 300) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for u in self.sitemap_urls + self.robots_paths:
            if u not in seen:
                seen.add(u)
                out.append(u)
            if len(out) >= limit:
                break
        return out


def discover(base_url: str, session: requests.Session, timeout: float = 10.0,
             max_urls: int = 300, max_sitemaps: int = 20) -> Discovery:
    d = Discovery()
    origin = urlparse(base_url)
    root = f"{origin.scheme}://{origin.netloc}"

    # 1) robots.txt
    try:
        r = session.get(urljoin(root + "/", "robots.txt"), timeout=timeout)
        if r.status_code == 200 and len(r.text) < 2_000_000:
            d.robots_found = True
            body = r.text
            for m in _SITEMAP_RE.finditer(body):
                d.sitemaps.append(m.group(1).strip())
            for m in _RULE_RE.finditer(body):
                path = m.group(2).strip()
                if path and path not in ("/", "*") and "*" not in path:
                    d.robots_paths.append(urljoin(root + "/", path.lstrip("/")))
    except requests.RequestException:
        pass

    # sitemap par défaut si non déclaré
    if not d.sitemaps:
        d.sitemaps.append(urljoin(root + "/", "sitemap.xml"))

    # 2) sitemaps (avec support des index → sous-sitemaps)
    queue = list(dict.fromkeys(d.sitemaps))
    processed: set[str] = set()
    while queue and len(processed) < max_sitemaps and len(d.sitemap_urls) < max_urls:
        sm = queue.pop(0)
        if sm in processed:
            continue
        processed.add(sm)
        try:
            r = session.get(sm, timeout=timeout)
            if r.status_code != 200:
                continue
            locs = _LOC_RE.findall(r.text)
        except requests.RequestException:
            continue

        is_index = "<sitemapindex" in r.text.lower()
        for loc in locs:
            loc = loc.strip()
            p = urlparse(loc)
            if p.netloc and p.netloc != origin.netloc:
                continue  # même hôte uniquement
            if is_index or loc.lower().endswith(".xml"):
                if loc not in processed:
                    queue.append(loc)
            else:
                d.sitemap_urls.append(loc)
                if len(d.sitemap_urls) >= max_urls:
                    break
    # conserve seulement les sitemaps réellement présents
    d.sitemaps = [s for s in processed]
    return d
