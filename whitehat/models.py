"""Structures de données partagées."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Technology:
    """Une techno détectée sur la cible."""

    name: str                       # nom lisible, ex. "Apache HTTP Server"
    version: Optional[str] = None   # version détectée si disponible
    categories: list[str] = field(default_factory=list)
    # Identité CPE pour interroger la NVD : (vendor, product)
    cpe_vendor: Optional[str] = None
    cpe_product: Optional[str] = None
    # Comment on l'a trouvée (header, meta, cookie, script…) — pour la transparence
    evidence: list[str] = field(default_factory=list)
    confidence: int = 100           # 0-100
    # Recherche CVE par mots-clés NVD quand il n'existe pas de CPE fiable
    # (ex. plugins/thèmes WordPress).
    nvd_keyword: Optional[str] = None
    # Identité OSV pour les librairies/dépendances (npm, Packagist, PyPI…)
    osv_ecosystem: Optional[str] = None
    osv_package: Optional[str] = None

    @property
    def display(self) -> str:
        return f"{self.name} {self.version}" if self.version else self.name

    def cpe_string(self) -> Optional[str]:
        """Construit une chaîne CPE 2.3 pour la recherche NVD."""
        if not (self.cpe_vendor and self.cpe_product):
            return None
        version = self.version or "*"
        return f"cpe:2.3:a:{self.cpe_vendor}:{self.cpe_product}:{version}:*:*:*:*:*:*:*"


@dataclass
class Vulnerability:
    """Une CVE mappée à une techno."""

    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None   # LOW / MEDIUM / HIGH / CRITICAL
    cvss_vector: Optional[str] = None
    published: Optional[str] = None
    references: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    # Enrichissement "exploitation" (non-armé) : explication + PoC publics connus
    exploit_refs: list[str] = field(default_factory=list)
    known_exploited: bool = False   # présent dans le catalogue CISA KEV
    # Priorisation
    epss: Optional[float] = None        # probabilité d'exploitation (0-1, source FIRST)
    risk_score: Optional[float] = None  # score combiné 0-10 (voir engine.risk)

    def severity_rank(self) -> int:
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return order.get((self.cvss_severity or "").upper(), 0)


@dataclass
class Finding:
    """Constat de sécurité hors-CVE (en-tête, cookie, TLS, fichier exposé, Nuclei…)."""

    category: str          # "header" | "cookie" | "tls" | "exposure" | "nuclei"
    title: str
    severity: str = "INFO"  # INFO / LOW / MEDIUM / HIGH / CRITICAL
    detail: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    source: str = ""       # moteur ou id de template
    # Descripteur permettant de relancer ce contrôle précis (re-vérification)
    recheck: Optional[dict] = None

    def severity_rank(self) -> int:
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        return order.get((self.severity or "").upper(), 0)


@dataclass
class ScanResult:
    target: str
    final_url: str
    status_code: int
    server_headers: dict[str, str] = field(default_factory=dict)
    technologies: list[Technology] = field(default_factory=list)
    # techno.display -> liste de vulnérabilités
    vulnerabilities: dict[str, list[Vulnerability]] = field(default_factory=dict)
    # Constats hors-CVE (hygiène, exposition, Nuclei…)
    findings: list[Finding] = field(default_factory=list)
    pages_crawled: int = 1

    def all_vulns(self) -> list[Vulnerability]:
        out: list[Vulnerability] = []
        for vs in self.vulnerabilities.values():
            out.extend(vs)
        return out
