"""Client OSV.dev — vulnérabilités des librairies/dépendances (multi-écosystème).

OSV agrège les avis (GHSA, etc.) pour npm, Packagist (Composer/PHP), PyPI,
RubyGems, Maven, Go, NuGet… Idéal pour refléter l'état CVE réel des librairies
et dépendances d'un site. Gratuit, sans clé. Réponses mises en cache 24 h.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import requests

from ..models import Technology, Vulnerability

OSV_QUERY = "https://api.osv.dev/v1/query"
CACHE_DIR = Path(os.environ.get("WHITEHAT_CACHE", os.path.expanduser("~/.cache/whitehat")))
CACHE_TTL = 24 * 3600

# Techno nommée (fingerprints) -> paquet npm interrogeable dans OSV
_NPM_MAP = {
    "jQuery": "jquery", "Bootstrap": "bootstrap", "Lodash": "lodash",
    "Moment.js": "moment", "AngularJS": "angular", "Angular": "@angular/core",
    "Vue.js": "vue", "React": "react", "Handlebars": "handlebars",
    "DOMPurify": "dompurify", "Select2": "select2", "D3.js": "d3", "Next.js": "next",
}
_SEV_MAP = {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH"}


def package_for(tech: Technology) -> str | None:
    if tech.osv_package:
        return tech.osv_package
    return _NPM_MAP.get(tech.name)


def ecosystem_for(tech: Technology) -> str:
    return tech.osv_ecosystem or "npm"


def _cache(key: str):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    p = CACHE_DIR / ("osv_" + hashlib.sha256(key.encode()).hexdigest()[:24] + ".json")
    if p.exists() and (time.time() - p.stat().st_mtime) < CACHE_TTL:
        try:
            return p, json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            return p, None
    return p, None


def query(package: str, version: str, ecosystem: str = "npm",
          timeout: float = 20.0) -> list[Vulnerability]:
    if not package or not version:
        return []
    key = f"{ecosystem}::{package}::{version}"
    path, data = _cache(key)
    if data is None:
        payload = {"version": version, "package": {"name": package, "ecosystem": ecosystem}}
        try:
            r = requests.post(OSV_QUERY, json=payload, timeout=timeout)
            r.raise_for_status()
            data = r.json()
            try:
                path.write_text(json.dumps(data))
            except OSError:
                pass
        except (requests.RequestException, ValueError):
            return []
    return [_parse(v) for v in data.get("vulns", [])]


# Compat : ancien nom
def query_library(package: str, version: str, timeout: float = 20.0) -> list[Vulnerability]:
    return query(package, version, "npm", timeout)


def _parse(v: dict) -> Vulnerability:
    osv_id = v.get("id", "?")
    aliases = v.get("aliases", []) or []
    cve = next((a for a in aliases if a.startswith("CVE-")), osv_id)

    desc = v.get("summary") or ""
    details = v.get("details") or ""
    if details and details not in desc:
        desc = (desc + " — " + details) if desc else details
    if len(desc) > 600:
        desc = desc[:600] + "…"

    sev = None
    dbs = v.get("database_specific") or {}
    if dbs.get("severity"):
        sev = _SEV_MAP.get(str(dbs["severity"]).upper(), str(dbs["severity"]).upper())
    for aff in v.get("affected", []):
        eco = (aff.get("database_specific") or {})
        if not sev and eco.get("severity"):
            sev = _SEV_MAP.get(str(eco["severity"]).upper(), str(eco["severity"]).upper())

    refs = [r.get("url") for r in v.get("references", []) if r.get("url")]
    return Vulnerability(
        cve_id=cve,
        description=desc or "(pas de description fournie par OSV)",
        cvss_severity=sev,
        published=v.get("published"),
        references=refs,
        exploit_refs=[r.get("url") for r in v.get("references", [])
                      if r.get("type") in ("WEB", "ADVISORY") and r.get("url")][:5],
    )
