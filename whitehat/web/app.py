"""Application FastAPI : lancement de scans, suivi SSE, historique, détail."""

from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from urllib.parse import urlparse

from ..engine import nuclei
from ..engine import recheck as recheck_engine
from ..engine import verify as verify_engine
from ..nvd import NVDClient
from . import tasks
from .db import DB

STATIC = Path(__file__).parent / "static"

app = FastAPI(title="whitehat", docs_url="/api/docs")
db = DB()


class ScanRequest(BaseModel):
    target: str
    authorized: bool = False        # garde-fou obligatoire
    crawl: bool = True
    use_sitemap: bool = True
    max_pages: int = 20
    max_depth: int = 2
    do_cve: bool = True
    do_osv: bool = True
    do_retire: bool = True
    do_wordpress: bool = True
    do_cms: bool = True
    do_deps: bool = True
    max_cve: int = 15
    min_severity: str | None = None
    do_audit: bool = True
    do_exposures: bool = True
    do_nuclei: bool = False
    nuclei_severities: str = "low,medium,high,critical"
    verify_tls: bool = True


# --- Pages ----------------------------------------------------------------
@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/scan/{scan_id}")
def scan_page(scan_id: str):
    return FileResponse(STATIC / "detail.html")


@app.get("/guide")
def guide_page():
    return FileResponse(STATIC / "guide.html")


# --- API : environnement --------------------------------------------------
@app.get("/api/env")
def env():
    import os
    return {
        "nuclei_available": nuclei.is_available(),
        "nuclei_version": nuclei.version(),
        "nvd_key": bool(os.environ.get("NVD_API_KEY")),
    }


# --- API : scans ----------------------------------------------------------
@app.post("/api/scans")
def create_scan(req: ScanRequest):
    if not req.authorized:
        raise HTTPException(
            status_code=400,
            detail="Autorisation requise : coche la case confirmant que tu es "
                   "autorisé à scanner cette cible.")
    if not req.target.strip():
        raise HTTPException(status_code=400, detail="Cible vide.")

    scan_id = uuid.uuid4().hex[:12]
    payload = req.model_dump()
    db.create(scan_id, req.target.strip(), payload)
    options = tasks.options_from_payload(payload)
    tasks.submit(db, scan_id, req.target.strip(), options)
    return {"id": scan_id}


@app.get("/api/scans")
def list_scans():
    return db.list()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    row = db.get(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan introuvable.")
    return row


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str):
    db.delete(scan_id)
    return {"ok": True}


class VerifyRequest(BaseModel):
    scan_id: str
    cve: str


@app.post("/api/verify")
def verify_cve(req: VerifyRequest):
    """Vérifie une CVE (non destructif) sur la cible déjà scannée (donc autorisée)."""
    if not re.match(r"^CVE-\d{4}-\d+$", req.cve, re.I):
        raise HTTPException(status_code=400, detail="Identifiant CVE invalide.")
    row = db.get(req.scan_id)
    if not row or not row.get("result"):
        raise HTTPException(status_code=404, detail="Scan introuvable.")
    target = (row["result"] or {}).get("final_url") or row["target"]
    return verify_engine.run(target, req.cve.upper())


class RecheckRequest(BaseModel):
    scan_id: str
    descriptor: dict


_RECHECK_KINDS = {"exposure", "header_missing", "header_present", "cookie", "tls", "nuclei"}


@app.post("/api/recheck")
def recheck_point(req: RecheckRequest):
    """Relance UN contrôle sur la cible déjà scannée et renvoie une preuve fraîche."""
    d = req.descriptor or {}
    if d.get("kind") not in _RECHECK_KINDS:
        raise HTTPException(status_code=400, detail="Contrôle non pris en charge.")
    row = db.get(req.scan_id)
    if not row or not row.get("result"):
        raise HTTPException(status_code=404, detail="Scan introuvable.")
    target = (row["result"] or {}).get("final_url") or row["target"]
    # garde-fou anti-SSRF : une URL d'exposition doit rester sur l'hôte scanné
    if d.get("kind") == "exposure":
        origin = urlparse(target).netloc
        if urlparse(d.get("url", "")).netloc != origin:
            raise HTTPException(status_code=400, detail="URL hors périmètre du scan.")
    return recheck_engine.run(target, d)


@app.get("/api/scans/{scan_id}/events")
def scan_events(scan_id: str):
    """Flux SSE de progression jusqu'à la fin du scan."""
    def gen():
        last = None
        for _ in range(2000):  # garde-fou (~20 min max)
            row = db.get(scan_id)
            if not row:
                yield _sse({"status": "error", "message": "introuvable"})
                return
            snapshot = (row["status"], row.get("stage"), row.get("pct"), row.get("message"))
            if snapshot != last:
                last = snapshot
                yield _sse({
                    "status": row["status"], "stage": row.get("stage"),
                    "pct": row.get("pct") or 0, "message": row.get("message") or "",
                })
            if row["status"] in ("done", "error"):
                return
            time.sleep(0.6)
    return StreamingResponse(gen(), media_type="text/event-stream")


def _sse(obj: dict) -> str:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"


# Fichiers statiques (css/js additionnels si besoin)
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
