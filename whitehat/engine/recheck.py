"""Re-contrôle d'un point détecté : relance le test précis et met à jour la preuve.

Permet, après une correction, de re-vérifier UN point (fichier exposé, en-tête,
cookie, TLS, template Nuclei) et de savoir s'il est « toujours présent » ou
« corrigé », avec une preuve fraîche. Tout est non destructif (simples requêtes).
"""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse

import requests

from . import headers_audit, verify
from ..scanner import USER_AGENT, _raw_set_cookies


def proof_info(target: str, descriptor: dict) -> dict:
    """D'où vient la preuve + comment la constater soi-même + lien d'accès.
    Retourne {source, manual, link}."""
    d = descriptor or {}
    kind = d.get("kind")
    if kind == "exposure":
        url = d.get("url", "")
        return {"source": "Le contenu est servi directement à cette adresse.",
                "manual": f"curl -i {shlex.quote(url)}",
                "link": url}
    if kind in ("header_missing", "header_present"):
        name = d.get("name", "")
        return {"source": "En-têtes de la réponse HTTP du site.",
                "manual": f"curl -sI {shlex.quote(target)}   # cherchez la ligne « {name}: »",
                "link": target}
    if kind == "cookie":
        name = d.get("name", "")
        return {"source": "En-tête Set-Cookie renvoyé par le site.",
                "manual": f"curl -sI {shlex.quote(target)}   # ligne « Set-Cookie: {name}=… » "
                          "(ou DevTools ▸ Application ▸ Cookies)",
                "link": target}
    if kind == "tls":
        p = urlparse(target)
        host, port = p.hostname or "", p.port or 443
        return {"source": "Certificat et négociation TLS du serveur.",
                "manual": f"echo | openssl s_client -connect {host}:{port} -servername {host} "
                          "2>/dev/null | openssl x509 -noout -issuer -dates   "
                          "(ou le cadenas du navigateur)",
                "link": target}
    if kind == "nuclei":
        tpl = d.get("template", "")
        return {"source": f"Détection par le template Nuclei « {tpl} ».",
                "manual": f"nuclei -u {shlex.quote(target)} -id {tpl}",
                "link": target}
    return {"source": "", "manual": "", "link": None}


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    s.verify = False
    try:
        import urllib3
        urllib3.disable_warnings()
    except ImportError:
        pass
    return s


def run(target: str, descriptor: dict, timeout: float = 12.0) -> dict:
    """Retourne {status: 'present'|'fixed'|'unknown'|'error', evidence}."""
    kind = (descriptor or {}).get("kind")
    try:
        if kind == "exposure":
            return _exposure(descriptor, timeout)
        if kind in ("header_missing", "header_present"):
            return _header(target, descriptor, kind, timeout)
        if kind == "cookie":
            return _cookie(target, descriptor, timeout)
        if kind == "tls":
            return _tls(target, descriptor, timeout)
        if kind == "nuclei":
            r = verify.run_id(target, descriptor.get("template", ""), int(timeout * 6))
            if r["status"] == "confirmed":
                return {"status": "present", "evidence": r.get("evidence", "détecté")}
            if r["status"] == "not_confirmed":
                return {"status": "fixed", "evidence": "le test ne détecte plus rien"}
            return {"status": "unknown", "evidence": r.get("evidence", "")}
    except requests.RequestException as exc:
        return {"status": "error", "evidence": str(exc)}
    return {"status": "unknown", "evidence": "type de contrôle non pris en charge"}


def _exposure(d: dict, timeout: float) -> dict:
    url = d.get("url", "")
    sig = d.get("sig")
    r = _session().get(url, timeout=timeout, allow_redirects=False)
    if r.status_code == 200 and (not sig or re.search(sig, r.text[:20000])):
        return {"status": "present", "evidence": f"HTTP 200 sur {url} (toujours accessible)"}
    return {"status": "fixed", "evidence": f"HTTP {r.status_code} sur {url} (accès bloqué)"}


def _header(target: str, d: dict, kind: str, timeout: float) -> dict:
    name = (d.get("name") or "").lower()
    r = _session().get(target, timeout=timeout)
    val = next((v for k, v in r.headers.items() if k.lower() == name), None)
    present = bool(val and val.strip())
    if kind == "header_missing":
        return ({"status": "fixed", "evidence": f"{name}: {val}"} if present
                else {"status": "present", "evidence": f"{name} toujours absent"})
    # header_present : la présence de l'en-tête EST le problème (divulgation)
    return ({"status": "present", "evidence": f"{name}: {val}"} if present
            else {"status": "fixed", "evidence": f"{name} retiré"})


def _cookie(target: str, d: dict, timeout: float) -> dict:
    name = d.get("name")
    r = _session().get(target, timeout=timeout)
    line = next((c for c in _raw_set_cookies(r)
                 if c.split("=", 1)[0].strip() == name), None)
    if not line:
        return {"status": "unknown", "evidence": "ce cookie n'est pas émis sur cette page"}
    low = line.lower()
    missing = [f for f in ("HttpOnly", "Secure", "SameSite") if f.lower() not in low]
    if missing:
        return {"status": "present", "evidence": f"flags manquants : {', '.join(missing)}"}
    return {"status": "fixed", "evidence": "HttpOnly, Secure et SameSite présents"}


def _tls(target: str, d: dict, timeout: float) -> dict:
    title = d.get("title")
    fs = headers_audit.audit_tls(target, timeout=timeout)
    match = next((f for f in fs if f.title == title), None)
    if match:
        return {"status": "present", "evidence": match.detail}
    return {"status": "fixed", "evidence": "ce contrôle TLS passe désormais"}
