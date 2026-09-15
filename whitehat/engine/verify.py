"""Vérification non destructive d'une CVE via un template Nuclei ciblé.

Objectif : permettre de *constater* qu'une faille est réellement présente sur une
cible autorisée, puis, après correctif, de *confirmer* qu'elle a disparu — sans
exploit offensif. On s'appuie sur les templates Nuclei (vérifiés par la
communauté, non destructifs) indexés par identifiant CVE.

Chaque template Nuclei de type CVE porte un id == l'identifiant CVE, donc
`nuclei -u <cible> -id CVE-XXXX-YYYY` lance exactement le test correspondant.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from pathlib import Path

from . import nuclei

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)
_index: set[str] | None = None


def _templates_dir() -> Path | None:
    for cand in (os.environ.get("NUCLEI_TEMPLATES"),
                 os.path.expanduser("~/nuclei-templates"),
                 os.path.expanduser("~/.local/nuclei-templates")):
        if cand and Path(cand).is_dir():
            return Path(cand)
    return None


def _build_index() -> set[str]:
    global _index
    if _index is not None:
        return _index
    idx: set[str] = set()
    d = _templates_dir()
    if d:
        for p in d.rglob("CVE-*.yaml"):
            idx.add(p.stem.upper())
    _index = idx
    return idx


def has_template(cve_id: str) -> bool:
    """True si une vérification Nuclei existe pour cette CVE."""
    if not cve_id or not _CVE_RE.match(cve_id):
        return False
    return cve_id.upper() in _build_index()


def command(target: str, cve_id: str) -> str:
    """Commande exacte, reproductible à la main."""
    return f"nuclei -u {shlex.quote(target)} -id {cve_id}"


def run_id(target: str, template_id: str, timeout: int = 90) -> dict:
    """Lance un template Nuclei ciblé (par id) et dit s'il matche encore.
    Retourne {status: 'confirmed'|'not_confirmed'|'error', evidence}."""
    if not nuclei.is_available():
        return {"status": "error", "evidence": "Nuclei non installé."}
    cmd = ["nuclei", "-u", target, "-id", template_id, "-jsonl", "-silent",
           "-no-color", "-disable-update-check", "-timeout", "10"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "error", "evidence": "Délai dépassé."}
    except OSError as exc:
        return {"status": "error", "evidence": str(exc)}
    for line in (out.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        return {"status": "confirmed",
                "evidence": data.get("matched-at") or data.get("host") or line}
    return {"status": "not_confirmed", "evidence": ""}


def run(target: str, cve_id: str, timeout: int = 90) -> dict:
    """Vérification d'une CVE. Retourne
    {status: 'confirmed'|'not_confirmed'|'unavailable'|'error', evidence, command}."""
    cmd_str = command(target, cve_id)
    if not nuclei.is_available():
        return {"status": "error", "evidence": "Nuclei non installé.", "command": cmd_str}
    if not has_template(cve_id):
        return {"status": "unavailable", "evidence": "", "command": cmd_str}
    res = run_id(target, cve_id, timeout)
    res["command"] = cmd_str
    return res
