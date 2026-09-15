"""Priorisation : enrichissement EPSS + score de risque combiné.

- EPSS (Exploit Prediction Scoring System, FIRST.org) : probabilité (0-1) qu'une
  CVE soit exploitée dans les 30 jours. Complète le CVSS (gravité) par la
  vraisemblance réelle d'exploitation.
- Score de risque (0-10) : combine gravité (CVSS), vraisemblance (EPSS) et
  exploitation avérée (CISA KEV) pour un tri « à corriger en premier ».
"""

from __future__ import annotations

import requests

from ..models import Vulnerability

EPSS_API = "https://api.first.org/data/v1/epss"


def enrich_epss(vulns: list[Vulnerability], timeout: float = 20.0) -> None:
    """Renseigne .epss sur chaque vuln (requête batch, en place)."""
    ids = sorted({v.cve_id for v in vulns if v.cve_id.startswith("CVE-")})
    if not ids:
        return
    scores: dict[str, float] = {}
    # L'API accepte une liste séparée par des virgules ; on découpe par lots.
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        try:
            r = requests.get(EPSS_API, params={"cve": ",".join(chunk)}, timeout=timeout)
            r.raise_for_status()
            for row in r.json().get("data", []):
                scores[row["cve"]] = float(row.get("epss", 0.0))
        except (requests.RequestException, ValueError, KeyError):
            continue
    for v in vulns:
        if v.cve_id in scores:
            v.epss = scores[v.cve_id]


def compute_risk(v: Vulnerability) -> float:
    """Score de risque 0-10, explicable.

    base = CVSS (ou estimation depuis la sévérité si CVSS absent).
    pondération par EPSS : de -30% (epss~0) à +30% (epss~1).
    KEV : plancher élevé (exploitation avérée = priorité max).
    """
    base = v.cvss_score
    if base is None:
        base = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0}.get(
            (v.cvss_severity or "").upper(), 4.0)
    epss = v.epss if v.epss is not None else 0.0
    score = base * (0.7 + 0.6 * epss)
    if v.known_exploited:
        score = max(score, 9.5)
    return round(min(score, 10.0), 1)


def apply_risk(vulns: list[Vulnerability]) -> None:
    for v in vulns:
        v.risk_score = compute_risk(v)
