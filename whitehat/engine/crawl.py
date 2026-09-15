"""Crawler léger même-origine.

Agrège le HTML de plusieurs pages internes pour élargir la détection de technos
(certaines n'apparaissent que sur des pages profondes). Reste courtois : même
hôte uniquement, seulement du text/html, limites strictes de pages/profondeur.
"""

from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urlparse

import requests

_LINK_RE = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)
_SKIP_EXT = (".pdf", ".zip", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css",
             ".js", ".ico", ".woff", ".woff2", ".ttf", ".mp4", ".webp")


def crawl(start_url: str, session: requests.Session, max_pages: int = 10,
          max_depth: int = 2, timeout: float = 10.0,
          first_html: str | None = None,
          seed_urls: list[str] | None = None) -> tuple[int, str, list[str]]:
    """Retourne (nombre_de_pages, html_agrégé, urls_visitées).

    `first_html` : HTML de la page de départ déjà récupéré (évite un GET refait).
    `seed_urls`  : URLs prioritaires (issues de robots.txt/sitemap) ajoutées à la file.
    """
    origin = urlparse(start_url)
    seen: set[str] = {start_url}
    visited: list[str] = []
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    for u in (seed_urls or []):
        if u not in seen and urlparse(u).netloc == origin.netloc:
            seen.add(u)
            queue.append((u, 1))  # profondeur 1 : on les visite mais on limite leur expansion
    merged: list[str] = []

    while queue and len(visited) < max_pages:
        url, depth = queue.popleft()
        html = None
        if url == start_url and first_html is not None:
            html = first_html
        else:
            try:
                r = session.get(url, timeout=timeout, allow_redirects=True)
                if "text/html" not in r.headers.get("Content-Type", ""):
                    continue
                html = r.text
            except requests.RequestException:
                continue
        if not html:
            continue

        visited.append(url)
        merged.append(html)

        if depth >= max_depth:
            continue
        for m in _LINK_RE.finditer(html):
            link = urljoin(url, m.group(1))
            p = urlparse(link)
            if p.scheme not in ("http", "https"):
                continue
            if p.netloc != origin.netloc:
                continue  # même hôte uniquement
            if p.path.lower().endswith(_SKIP_EXT):
                continue
            link = link.split("?")[0]
            if link not in seen:
                seen.add(link)
                queue.append((link, depth + 1))

    return len(visited), "\n".join(merged), visited
