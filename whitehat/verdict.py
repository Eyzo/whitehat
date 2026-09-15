"""Traduction d'un scan en langage clair pour non-experts.

Produit :
- une NOTE de sécurité (A→F) + un niveau/couleur + une phrase de synthèse ;
- une liste d'ISSUES unifiée (CVE + constats) en langage simple :
  « ce que c'est », « le risque », « que faire ».

Le jargon (CVE, CVSS, EPSS, CWE…) est relégué dans le champ `technical`,
affiché seulement à la demande.
"""

from __future__ import annotations

import re

from .exploitation import guide_for
from .models import ScanResult

SEV_LABEL = {
    "CRITICAL": "Critique", "HIGH": "Important", "MEDIUM": "Moyen",
    "LOW": "Mineur", "INFO": "Information",
}
_SEV_SCORE = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 1.0}

# Langage clair par type de constat (hors CVE)
_CATEGORY_PLAIN = {
    "header": dict(
        what="Une protection de sécurité recommandée n'est pas activée sur le site.",
        risk="Cela facilite certaines attaques, comme le vol de session ou l'affichage de faux contenu.",
        action="Demander à la personne qui gère le site d'activer cette protection.",
    ),
    "cookie": dict(
        what="Un cookie du site n'a pas toutes ses options de sécurité.",
        risk="Un cookie de connexion mal protégé peut être volé et servir à usurper un compte.",
        action="Activer les options de sécurité des cookies (HttpOnly, Secure, SameSite).",
    ),
    "tls": dict(
        what="Le chiffrement de la connexion (le cadenas HTTPS) présente un défaut.",
        risk="Les échanges entre le visiteur et le site sont moins bien protégés.",
        action="Mettre à jour la configuration HTTPS ou renouveler le certificat.",
    ),
    "exposure": dict(
        what="Un fichier qui devrait rester privé est accessible publiquement.",
        risk="Il peut contenir du code, des mots de passe ou des données sensibles.",
        action="Bloquer l'accès à ce fichier au niveau du serveur.",
    ),
    "nuclei": dict(
        what="Un contrôle de sécurité automatisé a détecté un problème connu.",
        risk="Selon le cas, cela peut être exploité par un attaquant.",
        action="Corriger selon les indications, ou mettre à jour le composant concerné.",
    ),
    "wordpress": dict(
        what="Une extension WordPress (plugin ou thème) n'est pas à jour.",
        risk="Les versions obsolètes cumulent souvent des failles de sécurité connues.",
        action="Mettre à jour cette extension vers la dernière version disponible.",
    ),
    "library": dict(
        what="Une librairie logicielle utilisée par le site n'est pas à jour.",
        risk="Les versions périmées accumulent souvent des failles connues.",
        action="Mettre à jour la librairie vers une version récente et maintenue.",
    ),
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def _cve_risk_text(kev: bool, epss, severity: str) -> str:
    if kev:
        return ("Cette faille est déjà activement exploitée par des attaquants. "
                "À traiter en urgence.")
    if epss is not None and epss >= 0.5:
        return "Cette faille a de fortes chances d'être exploitée."
    if severity in ("CRITICAL", "HIGH"):
        return "Elle peut permettre à un attaquant de prendre le contrôle ou d'accéder à des données."
    return "Le risque est plus limité, mais réel."


def build_issues(result: ScanResult) -> list[dict]:
    issues: list[dict] = []
    seen_cve: set[str] = set()

    # 1) CVE regroupées par logiciel → un seul point clair par techno
    for tech in result.technologies:
        vulns = result.vulnerabilities.get(tech.display, [])
        if not vulns:
            continue
        for v in vulns:
            seen_cve.add(v.cve_id)

        worst = max(vulns, key=lambda v: (v.known_exploited,
                                          v.risk_score or _SEV_SCORE.get(
                                              (v.cvss_severity or "INFO").upper(), 0)))
        sev = (worst.cvss_severity or "INFO").upper()
        any_kev = any(v.known_exploited for v in vulns)
        n = len(vulns)
        n_crit = sum(1 for v in vulns if (v.cvss_severity or "").upper() == "CRITICAL")
        score = worst.risk_score if worst.risk_score is not None else _SEV_SCORE.get(sev, 4.0)

        detail = f"contient {n} faille(s) de sécurité connue(s)"
        if n_crit:
            detail += f", dont {n_crit} critique(s)"

        # Liste technique lisible (repliée par défaut dans l'UI)
        lines = []
        for v in sorted(vulns, key=lambda v: v.risk_score or 0, reverse=True):
            bits = [v.cve_id]
            if v.cvss_score is not None:
                bits.append(f"CVSS {v.cvss_score}")
            if v.epss is not None:
                bits.append(f"exploit. {round(v.epss * 100)}%")
            if v.known_exploited:
                bits.append("déjà exploitée")
            lines.append("  ·  ".join(bits))

        issues.append(dict(
            kind="cve", title=f"« {tech.display} » doit être mis à jour",
            severity=sev, severity_label=SEV_LABEL.get(sev, sev), score=round(score, 1),
            kev=any_kev, tech=tech.display, count=n,
            what=f"Le logiciel « {tech.name} » utilisé par le site {detail}.",
            risk=_cve_risk_text(any_kev,
                                max((v.epss or 0) for v in vulns), sev),
            action=f"Mettre à jour « {tech.name} » vers une version récente et maintenue.",
            technical="\n".join(lines),
            references=(worst.exploit_refs or worst.references)[:5],
        ))

    # 2) Constats hors CVE
    for f in result.findings:
        sev = (f.severity or "INFO").upper()
        # dédup : un constat Nuclei qui pointe une CVE déjà listée est ignoré
        m = _CVE_RE.search(f"{f.source} {f.detail}")
        if m and m.group(0) in seen_cve:
            continue
        plain = _CATEGORY_PLAIN.get(f.category, _CATEGORY_PLAIN["nuclei"])
        action = f.remediation or plain["action"]
        issues.append(dict(
            kind=f.category, title=f.title,
            severity=sev, severity_label=SEV_LABEL.get(sev, sev),
            score=round(_SEV_SCORE.get(sev, 3.0), 1), kev=False, tech=None,
            what=plain["what"], risk=plain["risk"], action=action,
            technical=(f.detail + (f"\nPreuve : {f.evidence}" if f.evidence else "")).strip(),
            references=f.references[:5],
            evidence=f.evidence, recheck=f.recheck,
        ))

    issues.sort(key=lambda i: (i["kev"], i["score"]), reverse=True)
    return issues


def is_priority(issue: dict) -> bool:
    return (issue["kev"] or issue["severity"] in ("CRITICAL", "HIGH")
            or (issue["kind"] == "exposure" and issue["severity"] in ("HIGH", "MEDIUM")))


def compute_grade(counts: dict) -> dict:
    """`counts` : décompte par sévérité (CVE + constats), pour une note fidèle
    même quand la vue simple regroupe plusieurs failles en un point."""
    counts = {k: counts.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    crit, high, med, low = counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"]

    score = 100 - (crit * 25 + high * 12 + med * 4 + low * 1.5)
    if crit:
        score = min(score, 45)
    elif high:
        score = min(score, 65)
    score = max(0, min(100, int(round(score))))

    if score >= 85:
        grade, level, color = "A", "Très bonne sécurité", "ok"
    elif score >= 70:
        grade, level, color = "B", "Bonne sécurité", "ok"
    elif score >= 55:
        grade, level, color = "C", "Sécurité moyenne", "med"
    elif score >= 35:
        grade, level, color = "D", "Sécurité insuffisante", "high"
    else:
        grade, level, color = "F", "Sécurité préoccupante", "crit"

    important = crit + high
    if important:
        summary = f"{important} problème(s) important(s) à corriger"
        if crit:
            summary += f", dont {crit} critique(s)"
        summary += "."
    elif med:
        summary = f"Pas de problème critique, mais {med} point(s) à améliorer."
    else:
        summary = "Aucun problème majeur détecté lors de cette analyse."

    return dict(score=score, grade=grade, level=level, color=color,
                summary=summary, counts=counts)
