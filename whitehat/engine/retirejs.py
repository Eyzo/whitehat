"""Détection de librairies JS via signatures (façon retire.js).

Contrairement à la détection par nom de fichier, on inspecte le *contenu* des
scripts : les bannières de version (`/*! jQuery v3.4.1 */`) survivent à la
minification et au bundling, ce qui permet de repérer des librairies (et leurs
CVE) même quand l'URL n'indique aucune version.

On réutilise la base communautaire retire.js (jsrepository), qui embarque à la
fois les extracteurs et les vulnérabilités (avec CVE + plages de versions).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

import requests

from ..models import Vulnerability

REPO_URL = ("https://raw.githubusercontent.com/RetireJS/retire.js/master/"
            "repository/jsrepository-master.json")
CACHE_DIR = Path(os.environ.get("WHITEHAT_CACHE", os.path.expanduser("~/.cache/whitehat")))
CACHE_TTL = 24 * 3600
_VER_SUB = r"(?P<ver>[0-9][0-9.a-z_\-]+)"

_SEV_MAP = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}

_repo_cache: dict | None = None


# --- Chargement de la base -------------------------------------------------
def load_repo(timeout: float = 30.0) -> dict:
    global _repo_cache
    if _repo_cache is not None:
        return _repo_cache
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    p = CACHE_DIR / "retirejs_repo.json"
    if p.exists() and (time.time() - p.stat().st_mtime) < CACHE_TTL:
        try:
            _repo_cache = _prepare(json.loads(p.read_text()))
            return _repo_cache
        except (json.JSONDecodeError, OSError):
            pass
    try:
        r = requests.get(REPO_URL, timeout=timeout)
        r.raise_for_status()
        raw = r.json()
        try:
            p.write_text(json.dumps(raw))
        except OSError:
            pass
    except (requests.RequestException, ValueError):
        raw = {}
    _repo_cache = _prepare(raw)
    return _repo_cache


def _compile(patterns, flags=0):
    out = []
    for pat in patterns or []:
        try:
            out.append(re.compile(pat.replace("§§version§§", _VER_SUB), flags))
        except re.error:
            continue
    return out


def _prepare(raw: dict) -> dict:
    """Pré-compile les extracteurs de chaque librairie."""
    prepared = {}
    for name, entry in raw.items():
        ex = entry.get("extractors", {}) or {}
        prepared[name] = {
            "vulnerabilities": entry.get("vulnerabilities", []) or [],
            "fc": _compile(ex.get("filecontent")),                 # sensible à la casse
            "fn": _compile((ex.get("filename") or []) + (ex.get("uri") or []), re.I),
            "hashes": ex.get("hashes", {}) or {},
        }
    return prepared


# --- Comparaison de versions ----------------------------------------------
def _vcmp(a: str, b: str) -> int:
    pa = re.split(r"[.\-+_]", a.lower())
    pb = re.split(r"[.\-+_]", b.lower())
    for i in range(max(len(pa), len(pb))):
        xa = pa[i] if i < len(pa) else "0"
        xb = pb[i] if i < len(pb) else "0"
        if xa == xb:
            continue
        na, nb = xa.isdigit(), xb.isdigit()
        if na and nb:
            d = int(xa) - int(xb)
            if d:
                return 1 if d > 0 else -1
        elif na:
            return 1
        elif nb:
            return -1
        else:
            return 1 if xa > xb else -1
    return 0


def _in_range(ver: str, rng: dict) -> bool:
    try:
        if "atOrAbove" in rng and _vcmp(ver, rng["atOrAbove"]) < 0:
            return False
        if "above" in rng and _vcmp(ver, rng["above"]) <= 0:
            return False
        if "below" in rng and _vcmp(ver, rng["below"]) >= 0:
            return False
        if "atOrBelow" in rng and _vcmp(ver, rng["atOrBelow"]) > 0:
            return False
    except (TypeError, ValueError):
        return False
    return True


def _vulns_for(entry: dict, version: str) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for v in entry["vulnerabilities"]:
        ranges = v.get("ranges") or [v]
        if not any(_in_range(version, r) for r in ranges):
            continue
        ident = v.get("identifiers", {}) or {}
        cves = ident.get("CVE") or []
        cve_id = cves[0] if cves else (ident.get("githubID") or ident.get("summary") or "retire.js")
        out.append(Vulnerability(
            cve_id=cve_id,
            description=v.get("summary") or ident.get("summary") or "(retire.js)",
            cvss_severity=_SEV_MAP.get(str(v.get("severity", "")).lower()),
            references=v.get("info", []) or [],
            cwe=v.get("cwe", []) or [],
        ))
    return out


# --- Détection -------------------------------------------------------------
def detect(assets: list[tuple[str, str]], timeout: float = 30.0) -> list[dict]:
    """`assets` : liste de (url, contenu). Retourne
    [{name, version, source, vulns:[Vulnerability]}] dédupliqué."""
    repo = load_repo(timeout=timeout)
    if not repo:
        return []

    found: dict[tuple[str, str], dict] = {}

    def record(name: str, version: str, source: str):
        key = (name.lower(), version)
        if key in found:
            return
        found[key] = {"name": name, "version": version, "source": source,
                      "vulns": _vulns_for(repo[name], version)}

    for url, content in assets:
        content = content or ""
        sha1 = hashlib.sha1(content.encode("utf-8", "ignore")).hexdigest() if content else ""
        for name, entry in repo.items():
            # 1) hash exact du fichier
            if sha1 and sha1 in entry["hashes"]:
                record(name, entry["hashes"][sha1], "hash")
                continue
            # 2) contenu (bannières) — survit à la minification
            for rx in entry["fc"]:
                m = rx.search(content)
                if m and m.groupdict().get("ver"):
                    record(name, m.group("ver"), "contenu")
                    break
            # 3) nom de fichier / URI
            if url:
                for rx in entry["fn"]:
                    m = rx.search(url)
                    if m and m.groupdict().get("ver"):
                        record(name, m.group("ver"), "fichier")
                        break

    return list(found.values())
