"""Audit d'hygiène passif : en-têtes de sécurité, cookies, TLS.

Ne fait aucune requête supplémentaire : analyse la réponse déjà récupérée et
l'état de la connexion TLS. Produit des Finding.
"""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..models import Finding

# En-têtes de sécurité attendus : nom -> (sévérité si absent, remédiation)
_SECURITY_HEADERS = {
    "content-security-policy": ("MEDIUM",
        "Définir une Content-Security-Policy pour limiter les sources de scripts (anti-XSS)."),
    "strict-transport-security": ("MEDIUM",
        "Activer HSTS (Strict-Transport-Security) pour forcer HTTPS."),
    "x-frame-options": ("LOW",
        "Définir X-Frame-Options ou frame-ancestors (anti-clickjacking)."),
    "x-content-type-options": ("LOW",
        "Ajouter X-Content-Type-Options: nosniff."),
    "referrer-policy": ("LOW",
        "Définir une Referrer-Policy (ex. strict-origin-when-cross-origin)."),
    "permissions-policy": ("LOW",
        "Définir une Permissions-Policy pour restreindre les API navigateur."),
}

# En-têtes qui divulguent de l'information
_LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version",
                  "x-aspnetmvc-version", "x-generator", "x-drupal-cache"]


def audit_headers(headers: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    lower = {k.lower(): v for k, v in headers.items()}

    for name, (sev, fix) in _SECURITY_HEADERS.items():
        if name not in lower:
            findings.append(Finding(
                category="header", severity=sev,
                title=f"En-tête de sécurité manquant : {name}",
                detail=f"La réponse ne définit pas l'en-tête {name}.",
                remediation=fix, source="headers_audit",
                recheck={"kind": "header_missing", "name": name},
            ))

    for name in _LEAKY_HEADERS:
        if name in lower and lower[name].strip():
            findings.append(Finding(
                category="header", severity="INFO",
                title=f"Divulgation d'information : {name}",
                detail=f"L'en-tête {name} expose : {lower[name]}",
                evidence=f"{name}: {lower[name]}",
                remediation="Masquer/retirer cet en-tête pour réduire la surface d'info.",
                source="headers_audit",
                recheck={"kind": "header_present", "name": name},
            ))
    return findings


def audit_cookies(set_cookie_headers: list[str]) -> list[Finding]:
    """Vérifie les flags de sécurité des cookies (à partir des lignes Set-Cookie brutes)."""
    findings: list[Finding] = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        missing = []
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "secure" not in low:
            missing.append("Secure")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            findings.append(Finding(
                category="cookie",
                severity="MEDIUM" if "HttpOnly" in missing or "Secure" in missing else "LOW",
                title=f"Cookie sans flag(s) de sécurité : {name}",
                detail=f"Flags manquants : {', '.join(missing)}.",
                evidence=raw[:160],
                remediation="Positionner HttpOnly, Secure et SameSite sur les cookies de session.",
                source="headers_audit",
                recheck={"kind": "cookie", "name": name},
            ))
    return findings


def audit_tls(url: str, timeout: float = 8.0) -> list[Finding]:
    """Inspecte le certificat et la version TLS (connexion unique, non intrusive)."""
    findings: list[Finding] = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append(Finding(
            category="tls", severity="HIGH",
            title="Site servi en HTTP (sans TLS)",
            detail=f"L'URL finale n'utilise pas HTTPS : {url}",
            remediation="Servir le site en HTTPS et rediriger HTTP → HTTPS.",
            source="tls_audit",
            recheck={"kind": "tls", "title": "Site servi en HTTP (sans TLS)"},
        ))
        return findings

    host = parsed.hostname
    port = parsed.port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                cert = ssock.getpeercert()
    except (socket.error, ssl.SSLError, OSError) as exc:
        findings.append(Finding(
            category="tls", severity="INFO",
            title="Inspection TLS impossible",
            detail=str(exc), source="tls_audit",
        ))
        return findings

    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(Finding(
            category="tls", severity="MEDIUM",
            title=f"Version TLS obsolète négociée : {version}",
            detail="Le serveur accepte un protocole TLS déprécié.",
            remediation="Désactiver TLS < 1.2 ; privilégier TLS 1.2/1.3.",
            source="tls_audit",
        ))

    # Expiration du certificat
    not_after = cert.get("notAfter") if cert else None
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(Finding(
                    category="tls", severity="HIGH",
                    title="Certificat TLS expiré",
                    detail=f"Expiré depuis {-days} jour(s) (le {not_after}).",
                    remediation="Renouveler le certificat.", source="tls_audit"))
            elif days < 15:
                findings.append(Finding(
                    category="tls", severity="LOW",
                    title="Certificat TLS proche de l'expiration",
                    detail=f"Expire dans {days} jour(s) (le {not_after}).",
                    remediation="Renouveler le certificat.", source="tls_audit"))
        except ValueError:
            pass
    # descripteur de re-contrôle : on relancera l'audit TLS et on cherchera ce constat
    for fnd in findings:
        if fnd.recheck is None and fnd.source == "tls_audit":
            fnd.recheck = {"kind": "tls", "title": fnd.title}
    return findings
