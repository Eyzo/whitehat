"""Obsolescence des librairies JS : version installée vs dernière sur npm.

Comme pour WordPress, une librairie très en retard est un risque même sans CVE
publique connue (elle en accumule souvent). On interroge le registre npm pour la
dernière version publiée.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from urllib.parse import quote

import requests

CACHE_DIR = Path(os.environ.get("WHITEHAT_CACHE", os.path.expanduser("~/.cache/whitehat")))
CACHE_TTL = 24 * 3600


def latest_version(package: str, session: requests.Session, timeout: float = 10.0) -> str | None:
    key = "npm_latest_" + hashlib.sha256(package.encode()).hexdigest()[:20]
    p = CACHE_DIR / (key + ".json")
    if p.exists() and (time.time() - p.stat().st_mtime) < CACHE_TTL:
        try:
            return json.loads(p.read_text()).get("v")
        except (json.JSONDecodeError, OSError):
            pass
    # paquets scoependés : @scope/name -> @scope%2fname
    name = package if not package.startswith("@") else "@" + quote(package[1:], safe="")
    ver = None
    try:
        r = session.get(f"https://registry.npmjs.org/{name}", timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            ver = (data.get("dist-tags") or {}).get("latest")
    except (requests.RequestException, ValueError):
        ver = None
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"v": ver}))
    except OSError:
        pass
    return ver
