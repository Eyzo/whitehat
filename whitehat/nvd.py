"""Client de la National Vulnerability Database (NVD 2.0) + catalogue CISA KEV.

- Interroge l'API NVD par chaîne CPE (vendor:product:version) pour ne remonter
  que les CVE qui concernent réellement la version détectée.
- Respecte le rate-limit NVD (6s sans clé, 0.7s avec clé API dans NVD_API_KEY).
- Met en cache les réponses sur disque pour éviter de retaper l'API.
- Marque les CVE présentes dans le catalogue CISA "Known Exploited
  Vulnerabilities" (exploitation avérée dans la nature).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional

import requests

from .models import Technology, Vulnerability

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CACHE_DIR = Path(os.environ.get("WHITEHAT_CACHE", os.path.expanduser("~/.cache/whitehat")))
CACHE_TTL = 24 * 3600  # 1 jour


class NVDClient:
    def __init__(self, api_key: Optional[str] = None, cache_ttl: int = CACHE_TTL):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.delay = 0.7 if self.api_key else 6.0
        self.cache_ttl = cache_ttl
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._last_request = 0.0
        self._kev: Optional[set[str]] = None

    # --- Cache ------------------------------------------------------------
    def _cache_path(self, key: str) -> Path:
        h = hashlib.sha256(key.encode()).hexdigest()[:24]
        return CACHE_DIR / f"nvd_{h}.json"

    def _cache_get(self, key: str) -> Optional[dict]:
        p = self._cache_path(key)
        if p.exists() and (time.time() - p.stat().st_mtime) < self.cache_ttl:
            try:
                return json.loads(p.read_text())
            except (json.JSONDecodeError, OSError):
                return None
        return None

    def _cache_put(self, key: str, data: dict) -> None:
        try:
            self._cache_path(key).write_text(json.dumps(data))
        except OSError:
            pass

    # --- Rate limit -------------------------------------------------------
    def _throttle(self) -> None:
        elapsed = time.time() - self._last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request = time.time()

    # --- CISA KEV ---------------------------------------------------------
    def _load_kev(self) -> set[str]:
        if self._kev is not None:
            return self._kev
        cached = self._cache_get("kev-catalog")
        if cached is None:
            try:
                r = requests.get(KEV_URL, timeout=30)
                r.raise_for_status()
                cached = r.json()
                self._cache_put("kev-catalog", cached)
            except (requests.RequestException, json.JSONDecodeError):
                cached = {"vulnerabilities": []}
        self._kev = {v["cveID"] for v in cached.get("vulnerabilities", [])}
        return self._kev

    # --- Requête principale ----------------------------------------------
    def query(self, tech: Technology, max_results: int = 25) -> list[Vulnerability]:
        cpe = tech.cpe_string()
        if not cpe:
            return []

        cache_key = f"query::{cpe}::{max_results}"
        raw = self._cache_get(cache_key)
        if raw is None:
            params = {"virtualMatchString": cpe, "resultsPerPage": max_results}
            headers = {"apiKey": self.api_key} if self.api_key else {}
            self._throttle()
            try:
                r = requests.get(NVD_ENDPOINT, params=params, headers=headers, timeout=40)
                r.raise_for_status()
                raw = r.json()
                self._cache_put(cache_key, raw)
            except requests.RequestException as exc:
                raise RuntimeError(f"Erreur NVD pour {tech.display}: {exc}") from exc

        kev = self._load_kev()
        vulns = [self._parse(item, kev) for item in raw.get("vulnerabilities", [])]
        vulns.sort(key=lambda v: (v.known_exploited, v.cvss_score or 0), reverse=True)
        return vulns

    def query_keyword(self, keyword: str, max_results: int = 10) -> list[Vulnerability]:
        """Recherche CVE par mots-clés (best-effort, ex. plugins WordPress)."""
        cache_key = f"kw::{keyword}::{max_results}"
        raw = self._cache_get(cache_key)
        if raw is None:
            params = {"keywordSearch": keyword, "resultsPerPage": max_results}
            headers = {"apiKey": self.api_key} if self.api_key else {}
            self._throttle()
            try:
                r = requests.get(NVD_ENDPOINT, params=params, headers=headers, timeout=40)
                r.raise_for_status()
                raw = r.json()
                self._cache_put(cache_key, raw)
            except requests.RequestException:
                return []
        kev = self._load_kev()
        vulns = [self._parse(item, kev) for item in raw.get("vulnerabilities", [])]
        vulns.sort(key=lambda v: (v.known_exploited, v.cvss_score or 0), reverse=True)
        return vulns

    # --- Parsing ----------------------------------------------------------
    @staticmethod
    def _parse(item: dict, kev: set[str]) -> Vulnerability:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "?")

        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        score = severity = vector = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                data = metrics[key][0].get("cvssData", {})
                score = data.get("baseScore")
                vector = data.get("vectorString")
                severity = (metrics[key][0].get("baseSeverity")
                            or data.get("baseSeverity"))
                break

        references = [r.get("url") for r in cve.get("references", []) if r.get("url")]

        cwes: list[str] = []
        for w in cve.get("weaknesses", []):
            for desc in w.get("description", []):
                val = desc.get("value")
                if val and val not in cwes and val != "NVD-CWE-noinfo":
                    cwes.append(val)

        # PoC / exploits publics reconnus depuis les tags de références NVD
        exploit_refs = [
            r.get("url") for r in cve.get("references", [])
            if r.get("url") and any(
                t.lower() in ("exploit", "third party advisory")
                for t in r.get("tags", [])
            )
        ]

        return Vulnerability(
            cve_id=cve_id,
            description=description,
            cvss_score=score,
            cvss_severity=severity,
            cvss_vector=vector,
            published=cve.get("published"),
            references=references,
            cwe=cwes,
            exploit_refs=exploit_refs,
            known_exploited=cve_id in kev,
        )
