"""Scanner HTTP : récupère la cible et en extrait les signaux d'empreinte.

Uniquement des requêtes GET/HEAD passives et non intrusives : on lit ce que le
serveur renvoie normalement à un navigateur. Aucun payload d'attaque.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

from . import __version__
from . import fingerprints
from .models import ScanResult

USER_AGENT = f"whitehat-scanner/{__version__} (+recon autorisé uniquement)"


def _normalize(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


@dataclass
class Fetched:
    """Réponse initiale + session réutilisable, pour les étapes suivantes."""
    session: requests.Session
    final_url: str
    status_code: int
    headers: dict[str, str]
    cookie_names: list[str]
    set_cookie_raw: list[str]
    html: str


def _raw_set_cookies(resp: requests.Response) -> list[str]:
    if hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "get_all"):
        return list(resp.raw.headers.get_all("Set-Cookie") or [])
    sc = resp.headers.get("Set-Cookie")
    return [sc] if sc else []


def fetch(target: str, timeout: float = 15.0, verify_tls: bool = True) -> Fetched:
    """Récupère la page de départ et prépare une session réutilisable."""
    url = _normalize(target)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    if not verify_tls:
        session.verify = False
        try:
            import urllib3
            urllib3.disable_warnings()
        except ImportError:
            pass

    resp = session.get(url, timeout=timeout, allow_redirects=True)
    headers = {k: v for k, v in resp.headers.items()}
    set_cookie_raw = _raw_set_cookies(resp)

    cookie_names = [c.name for c in resp.cookies]
    for raw in set_cookie_raw:
        name = raw.split("=", 1)[0].strip()
        if name and name not in cookie_names:
            cookie_names.append(name)

    html = resp.text if resp.text else ""
    return Fetched(session, resp.url, resp.status_code, headers,
                   cookie_names, set_cookie_raw, html)


def scan(target: str, timeout: float = 15.0, verify_tls: bool = True) -> ScanResult:
    """Scan simple : technos détectées sur la page de départ (sans CVE)."""
    f = fetch(target, timeout=timeout, verify_tls=verify_tls)
    technologies = fingerprints.detect(f.headers, f.cookie_names, f.html)
    return ScanResult(
        target=target,
        final_url=f.final_url,
        status_code=f.status_code,
        server_headers=f.headers,
        technologies=technologies,
    )
