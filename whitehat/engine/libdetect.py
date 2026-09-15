"""Détection générique de librairies front-end (nom + version) pour l'analyse CVE.

But : refléter l'état réel du site à l'instant T. On extrait un maximum de
couples (paquet npm, version) depuis le HTML agrégé :
- CDN structurés : jsdelivr `/npm/<pkg>@<ver>/`, unpkg `<pkg>@<ver>`, cdnjs
  `/ajax/libs/<name>/<ver>/` ;
- noms de fichiers versionnés pour une liste de librairies connues.

Chaque librairie devient une Technology avec osv_ecosystem="npm" + osv_package,
que l'orchestrateur interroge dans OSV. Les paquets inconnus d'OSV ne renvoient
rien (bruit inoffensif).
"""

from __future__ import annotations

import re

from ..models import Technology

_VER = r"(\d+\.\d+(?:\.\d+)?(?:[-.][0-9A-Za-z.]+)?)"
_VER_STRICT = r"(\d+\.\d+(?:\.\d+)?)"

# CDN structurés (nom de paquet npm fiable + version)
_CDN_PATTERNS = [
    re.compile(r"cdn\.jsdelivr\.net/npm/(@?[\w.\-]+(?:/[\w.\-]+)?)@" + _VER, re.I),
    re.compile(r"unpkg\.com/(@?[\w.\-]+(?:/[\w.\-]+)?)@" + _VER, re.I),
    re.compile(r"cdnjs\.cloudflare\.com/ajax/libs/([\w.\-]+)/" + _VER, re.I),
]

# Librairies connues repérables via un nom de fichier versionné (nom fichier -> paquet npm)
_KNOWN = {
    "jquery": "jquery", "jquery-ui": "jquery-ui", "jquery.min": "jquery",
    "bootstrap": "bootstrap", "lodash": "lodash", "underscore": "underscore",
    "moment": "moment", "axios": "axios", "vue": "vue", "react": "react",
    "react-dom": "react-dom", "angular": "angular", "d3": "d3",
    "chart": "chart.js", "chartjs": "chart.js", "swiper": "swiper", "gsap": "gsap",
    "three": "three", "handlebars": "handlebars", "backbone": "backbone",
    "dompurify": "dompurify", "select2": "select2", "slick": "slick-carousel",
    "popper": "@popperjs/core", "tinymce": "tinymce", "video": "video.js",
    "highlight": "highlight.js", "marked": "marked", "dayjs": "dayjs",
    "leaflet": "leaflet", "fullcalendar": "fullcalendar", "fabric": "fabric",
}

# nom de fichier « <lib>-<version> » ou « <lib>.<version> » (version stricte : pas de .min)
_FILE_RE = re.compile(
    r"/([A-Za-z][\w.\-]*?)[-.@]" + _VER_STRICT + r"(?:\.min)?\.(?:js|css)", re.I)

# cdnjs name -> npm name quand ils diffèrent
_CDNJS_TO_NPM = {"lodash.js": "lodash", "underscore.js": "underscore",
                 "jquery-migrate": "jquery-migrate"}


def _clean_name(name: str) -> str:
    return name.lower().rstrip(".")


def detect_libraries(html: str, existing: list[Technology] | None = None,
                     max_libs: int = 40) -> list[Technology]:
    """Retourne des Technology (npm) supplémentaires détectées dans le HTML."""
    # index des paquets déjà repérés par les empreintes (pour dédup / backfill)
    from . import osv as _osv
    existing_by_pkg: dict[str, Technology] = {}
    for t in (existing or []):
        p = _osv.package_for(t) if (t.osv_package or t.name in _osv._NPM_MAP) else None
        if p:
            existing_by_pkg.setdefault(p.lower(), t)

    found: dict[tuple[str, str], Technology] = {}

    def add(pkg: str, ver: str, src: str):
        pkg = _CDNJS_TO_NPM.get(pkg.lower(), pkg)
        keyp = pkg.lower()
        et = existing_by_pkg.get(keyp)
        if et is not None:
            # empreinte déjà présente : on complète sa version si elle manque,
            # sinon on ne recrée pas de ligne.
            if not et.version:
                et.version = ver
                et.osv_ecosystem = "npm"
                et.osv_package = pkg
                et.evidence.append(f"{src} → {pkg}@{ver}")
            return
        k = (keyp, ver)
        if k in found:
            return
        found[k] = Technology(
            name=pkg, version=ver, categories=["Librairie JS"],
            osv_ecosystem="npm", osv_package=pkg,
            evidence=[f"{src} → {pkg}@{ver}"], confidence=80,
        )

    for rx in _CDN_PATTERNS:
        for m in rx.finditer(html):
            add(m.group(1), m.group(2), "CDN")
            if len(found) >= max_libs:
                break

    for m in _FILE_RE.finditer(html):
        raw = _clean_name(m.group(1))
        pkg = _KNOWN.get(raw)
        if pkg:
            add(pkg, m.group(2), "fichier")
        if len(found) >= max_libs:
            break

    return list(found.values())[:max_libs]
