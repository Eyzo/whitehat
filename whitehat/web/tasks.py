"""Exécution des scans en tâche de fond, avec progression persistée en base."""

from __future__ import annotations

import traceback
from concurrent.futures import ThreadPoolExecutor

from .. import report
from ..orchestrator import ScanOptions, run
from .db import DB

_EXECUTOR = ThreadPoolExecutor(max_workers=2)

# Champs acceptés pour construire ScanOptions depuis l'API
_OPT_FIELDS = {
    "crawl", "use_sitemap", "max_pages", "max_depth", "do_cve", "do_osv",
    "do_retire", "do_wordpress", "do_cms", "do_deps", "wp_max", "max_cve",
    "min_severity", "do_audit",
    "do_exposures", "do_nuclei", "nuclei_severities", "timeout", "verify_tls",
    "api_key",
}


def options_from_payload(payload: dict) -> ScanOptions:
    clean = {k: v for k, v in payload.items() if k in _OPT_FIELDS}
    return ScanOptions(**clean)


def submit(db: DB, scan_id: str, target: str, options: ScanOptions) -> None:
    _EXECUTOR.submit(_run, db, scan_id, target, options)


def _run(db: DB, scan_id: str, target: str, options: ScanOptions) -> None:
    db.update_progress(scan_id, "running", "start", 1, "Démarrage du scan…")

    def cb(stage: str, message: str, pct: int) -> None:
        db.update_progress(scan_id, "running", stage, pct, message)

    try:
        result = run(target, options, on_progress=cb)
        data = report.to_dict(result, show_exploit=True)
        db.finish(scan_id, data, data["summary"])
    except Exception as exc:  # noqa: BLE001 — on veut capturer proprement pour l'UI
        db.fail(scan_id, f"{exc}\n{traceback.format_exc(limit=3)}")
