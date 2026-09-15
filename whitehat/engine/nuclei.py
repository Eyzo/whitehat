"""Intégration Nuclei (ProjectDiscovery) — couverture maximale de templates.

Nuclei applique des milliers de templates communautaires (CVE, expositions,
mauvaises configs, identifiants par défaut…). Ce wrapper :
- détecte le binaire `nuclei` et dégrade proprement s'il est absent ;
- l'exécute avec des options sûres (rate-limit, timeout, sortie JSONL) ;
- convertit chaque résultat en Finding.

⚠️ Nuclei envoie des requêtes actives : à n'utiliser que sur des cibles
autorisées. On n'active PAS les templates intrusifs par défaut.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
from typing import Callable, Optional

from ..models import Finding


def is_available() -> bool:
    return shutil.which("nuclei") is not None


def version() -> Optional[str]:
    if not is_available():
        return None
    try:
        out = subprocess.run(["nuclei", "-version"], capture_output=True,
                             text=True, timeout=10)
        text = (out.stderr or "") + (out.stdout or "")
        # nettoie les codes ANSI et cherche la ligne de version du moteur
        clean = re.sub(r"\x1b\[[0-9;]*m", "", text)
        m = re.search(r"Engine Version:\s*(v?[\d.]+)", clean)
        if m:
            return m.group(1)
        m = re.search(r"(v?\d+\.\d+\.\d+)", clean)
        return m.group(1) if m else None
    except (subprocess.SubprocessError, OSError):
        return None


def run(url: str, severities: str = "low,medium,high,critical",
        rate_limit: int = 50, timeout_per_req: int = 10,
        overall_timeout: int = 900,
        extra_args: Optional[list[str]] = None,
        on_line: Optional[Callable[[Finding], None]] = None,
        on_stats: Optional[Callable[[dict], None]] = None) -> list[Finding]:
    """Lance Nuclei sur `url` et retourne les Finding.

    `on_line` reçoit chaque résultat au fil de l'eau ; `on_stats` reçoit les
    statistiques d'avancement de Nuclei (requêtes faites/total, %) pour une
    barre de progression fidèle pendant l'analyse approfondie."""
    if not is_available():
        raise RuntimeError("Le binaire `nuclei` est introuvable (voir README pour l'installer).")

    cmd = [
        "nuclei", "-u", url,
        "-jsonl", "-silent", "-no-color",
        "-severity", severities,
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout_per_req),
        "-disable-update-check",
    ]
    if on_stats:
        cmd += ["-stats", "-stats-json", "-stats-interval", "3"]
    if extra_args:
        cmd += extra_args

    findings: list[Finding] = []
    stderr_dst = subprocess.PIPE if on_stats else subprocess.DEVNULL
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr_dst,
                                text=True, bufsize=1)
    except OSError as exc:
        raise RuntimeError(f"Échec du lancement de Nuclei : {exc}") from exc

    # Les stats Nuclei arrivent sur stderr en JSONL : on les lit dans un thread.
    def _read_stats():
        for line in proc.stderr:  # type: ignore[union-attr]
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if any(k in data for k in ("percent", "requests", "total")) and on_stats:
                on_stats(data)

    stats_thread = None
    if on_stats and proc.stderr:
        stats_thread = threading.Thread(target=_read_stats, daemon=True)
        stats_thread.start()

    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            f = _parse(data)
            findings.append(f)
            if on_line:
                on_line(f)
        proc.wait(timeout=overall_timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
    finally:
        if proc.stdout:
            proc.stdout.close()
        if stats_thread:
            stats_thread.join(timeout=2)
    return findings


def _parse(data: dict) -> Finding:
    info = data.get("info", {})
    classification = info.get("classification") or {}
    cve_ids = classification.get("cve-id") or []
    cwe_ids = classification.get("cwe-id") or []
    refs = info.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]

    title = info.get("name") or data.get("template-id", "nuclei")
    detail = info.get("description", "") or ""
    if cve_ids:
        detail = (detail + f"\nCVE : {', '.join(cve_ids)}").strip()
    if cwe_ids:
        detail = (detail + f"\nCWE : {', '.join(cwe_ids)}").strip()

    template_id = data.get("template-id", "nuclei")
    return Finding(
        category="nuclei",
        severity=(info.get("severity") or "INFO").upper(),
        title=title,
        detail=detail,
        evidence=data.get("matched-at") or data.get("host", ""),
        remediation=info.get("remediation", "") or "",
        references=list(refs),
        source=template_id,
        recheck={"kind": "nuclei", "template": template_id},
    )
