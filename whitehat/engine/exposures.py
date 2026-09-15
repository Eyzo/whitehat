"""Détection de fichiers / chemins sensibles exposés.

Envoie des requêtes GET ciblées sur une liste de chemins connus et confirme
l'exposition via une signature (pour limiter les faux positifs dus aux pages
d'erreur 200 "soft"). Non destructif, mais actif : à réserver aux cibles
autorisées.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

import requests

from ..models import Finding

# chemin -> (sévérité, description, signature regex à retrouver dans le corps)
_PATHS: list[tuple[str, str, str, str]] = [
    (".git/config", "HIGH", "Dépôt Git exposé (code source/historique récupérables).",
     r"\[core\]|repositoryformatversion"),
    (".git/HEAD", "HIGH", "Dépôt Git exposé (.git/HEAD accessible).", r"ref:\s*refs/"),
    (".env", "HIGH", "Fichier .env exposé (secrets/identifiants potentiels).",
     r"(?i)(APP_KEY|DB_PASSWORD|SECRET|API_KEY)\s*="),
    ("config.php.bak", "HIGH", "Sauvegarde de configuration exposée.", r"<\?php|define\("),
    ("wp-config.php.bak", "HIGH", "Sauvegarde wp-config exposée.", r"DB_PASSWORD|DB_NAME"),
    ("backup.sql", "HIGH", "Dump SQL exposé.", r"(?i)INSERT INTO|CREATE TABLE"),
    ("server-status", "MEDIUM", "Apache mod_status exposé (infos serveur/requêtes).",
     r"Apache Server Status|Server Version"),
    ("phpinfo.php", "MEDIUM", "phpinfo() exposé (config PHP détaillée).", r"phpinfo\(\)|PHP Version"),
    (".DS_Store", "LOW", "Fichier .DS_Store exposé (arborescence macOS).", r"Bud1|\x00\x00\x00"),
    (".svn/entries", "MEDIUM", "Métadonnées SVN exposées.", r"^\d+|svn"),
    (".htaccess", "LOW", "Fichier .htaccess accessible.", r"(?i)RewriteEngine|Order allow|Require"),
    ("composer.json", "LOW", "composer.json exposé (dépendances PHP).", r"(?i)\"require\"|\"name\""),
    ("package.json", "LOW", "package.json exposé (dépendances JS).", r"(?i)\"dependencies\"|\"name\""),
    ("docker-compose.yml", "MEDIUM", "docker-compose.yml exposé (config/infra).", r"(?i)services:|image:"),
    (".env.bak", "HIGH", "Sauvegarde .env exposée.", r"(?i)(APP_KEY|DB_PASSWORD|SECRET)\s*="),
    ("wp-config.php~", "HIGH", "Sauvegarde wp-config exposée.", r"DB_PASSWORD|DB_NAME"),
    ("actuator/env", "HIGH", "Spring Boot Actuator /env exposé (secrets possibles).", r"(?i)\"propertySources\"|activeProfiles"),
    ("actuator/health", "MEDIUM", "Spring Boot Actuator /health exposé.", r"(?i)\"status\"\s*:"),
    ("phpinfo.php", "MEDIUM", "phpinfo() exposé.", r"phpinfo\(\)|PHP Version"),
    ("info.php", "MEDIUM", "phpinfo() exposé (info.php).", r"phpinfo\(\)|PHP Version"),
    ("robots.txt", "INFO", "robots.txt (peut révéler des chemins sensibles).", r"(?i)Disallow:"),
    (".well-known/security.txt", "INFO", "security.txt présent (contact sécurité).", r"(?i)Contact:"),
    ("sitemap.xml", "INFO", "sitemap.xml (cartographie des URLs).", r"<urlset|<sitemapindex"),
]


def scan_exposures(base_url: str, session: requests.Session,
                   timeout: float = 8.0) -> list[Finding]:
    findings: list[Finding] = []
    base = base_url if base_url.endswith("/") else base_url + "/"

    for path, sev, desc, sig in _PATHS:
        url = urljoin(base, path)
        try:
            r = session.get(url, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        body = r.text[:20000]
        if sig and not re.search(sig, body):
            continue  # 200 mais contenu non concluant → on ignore (anti faux-positif)
        findings.append(Finding(
            category="exposure", severity=sev,
            title=f"Ressource exposée : /{path}",
            detail=desc,
            evidence=f"HTTP 200 sur {url}",
            references=[url],
            remediation="Bloquer l'accès à cette ressource (config serveur) ou la retirer du webroot.",
            source="exposures",
            recheck={"kind": "exposure", "url": url, "sig": sig},
        ))
    return findings
