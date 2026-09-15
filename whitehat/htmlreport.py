"""Génère un rapport HTML autonome (page unique) à partir d'un ScanResult.

- Aucune dépendance externe : CSS et JS sont inline, la page s'ouvre hors-ligne
  dans n'importe quel navigateur. Aucune donnée n'est envoyée sur le réseau.
- Interactif : recherche plein-texte, filtres par sévérité, bascule "CISA KEV",
  cartes CVE dépliables (élément <details> natif).
- Thème clair/sombre automatique (prefers-color-scheme).
"""

from __future__ import annotations

import html
from datetime import datetime

from .exploitation import guide_for
from .models import ScanResult, Vulnerability

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _e(text: object) -> str:
    """Échappe pour insertion HTML."""
    return html.escape(str(text), quote=True)


def _sev(v: Vulnerability) -> str:
    return (v.cvss_severity or "NA").upper()


def _link(url: str) -> str:
    safe = _e(url)
    return f'<a href="{safe}" target="_blank" rel="noopener noreferrer">{safe}</a>'


# --- Fragments dynamiques --------------------------------------------------
def _tiles(counts: dict[str, int]) -> str:
    order = [
        ("CRITICAL", "Critiques", "crit"),
        ("HIGH", "Élevées", "high"),
        ("MEDIUM", "Moyennes", "med"),
        ("LOW", "Faibles", "low"),
        ("KEV", "Exploitées (KEV)", "kev"),
    ]
    cells = []
    for key, label, cls in order:
        cells.append(
            f'<div class="tile tile-{cls}"><div class="tile-n">{counts.get(key, 0)}</div>'
            f'<div class="tile-l">{label}</div></div>'
        )
    return '<div class="tiles">' + "".join(cells) + "</div>"


def _tech_row(tech, n_cve: int) -> str:
    if not tech.cpe_string():
        badge = '<span class="pill pill-na">non interrogeable</span>'
    elif n_cve:
        badge = f'<span class="pill pill-bad">{n_cve} CVE</span>'
    else:
        badge = '<span class="pill pill-ok">0 CVE</span>'
    cats = ", ".join(tech.categories) or "—"
    ev = ""
    if tech.evidence:
        items = "".join(f"<li>{_e(x)}</li>" for x in tech.evidence[:6])
        ev = f'<details class="evidence"><summary>preuves</summary><ul>{items}</ul></details>'
    return (
        f'<tr><td class="t-name">{_e(tech.name)}</td>'
        f'<td>{_e(tech.version) if tech.version else "<span class=dim>?</span>"}</td>'
        f'<td>{_e(cats)}</td><td>{badge}{ev}</td></tr>'
    )


def _cve_card(v: Vulnerability, show_exploit: bool) -> str:
    sev = _sev(v)
    sev_cls = sev.lower() if sev in _SEV_ORDER else "na"
    score = v.cvss_score if v.cvss_score is not None else "?"
    kev = ('<span class="badge badge-kev" title="Présente dans le catalogue CISA '
           'Known Exploited Vulnerabilities">⚠ EXPLOITÉE</span>' if v.known_exploited else "")
    cwe = ""
    if v.cwe:
        cwe = '<div class="meta"><span class="k">CWE</span> ' + \
              " ".join(f'<code>{_e(c)}</code>' for c in v.cwe) + "</div>"

    guide_html = ""
    if show_exploit:
        g = guide_for(v)
        guide_html = (
            '<div class="guide">'
            f'<div class="g-type">{_e(g.cwe_title)}</div>'
            f'<div class="g-row"><span class="k">Mécanisme</span>{_e(g.mechanism)}</div>'
            f'<div class="g-row"><span class="k">Reproduction (cadre autorisé)</span>{_e(g.reproduction)}</div>'
            f'<div class="g-row g-fix"><span class="k">Remédiation</span>{_e(g.remediation)}</div>'
            "</div>"
        )

    refs = v.exploit_refs or v.references
    refs_html = ""
    if refs:
        items = "".join(f"<li>{_link(r)}</li>" for r in refs[:8])
        refs_html = f'<details class="refs"><summary>Références ({len(refs)})</summary><ul>{items}</ul></details>'

    published = ""
    if v.published:
        published = f'<span class="pub">{_e(v.published[:10])}</span>'

    search_blob = _e(f"{v.cve_id} {v.description} {' '.join(v.cwe)}").lower()

    return (
        f'<details class="cve sev-{sev_cls}" data-sev="{sev}" '
        f'data-kev="{1 if v.known_exploited else 0}" data-text="{search_blob}">'
        '<summary>'
        f'<span class="sev-tag sev-{sev_cls}">{_e(sev)}</span>'
        f'<span class="cvss">{_e(score)}</span>'
        f'<span class="cve-id">{_e(v.cve_id)}</span>'
        f'{kev}{published}'
        '</summary>'
        f'<div class="cve-body"><p class="desc">{_e(v.description)}</p>{cwe}{guide_html}{refs_html}</div>'
        '</details>'
    )


# --- Assemblage ------------------------------------------------------------
def to_html(result: ScanResult, show_exploit: bool = True) -> str:
    counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "KEV")}
    total_cve = 0
    for vulns in result.vulnerabilities.values():
        for v in vulns:
            total_cve += 1
            counts[_sev(v)] = counts.get(_sev(v), 0) + 1
            if v.known_exploited:
                counts["KEV"] += 1

    tech_rows = "".join(
        _tech_row(t, len(result.vulnerabilities.get(t.display, [])))
        for t in result.technologies
    ) or '<tr><td colspan="4" class="dim">Aucune technologie détectée.</td></tr>'

    sections = []
    # technos triées : celles avec le plus de CVE d'abord
    ordered = sorted(
        result.technologies,
        key=lambda t: len(result.vulnerabilities.get(t.display, [])),
        reverse=True,
    )
    for tech in ordered:
        vulns = result.vulnerabilities.get(tech.display, [])
        if not vulns:
            continue
        vulns = sorted(vulns,
                       key=lambda v: (v.known_exploited, _SEV_ORDER.get(_sev(v), 0),
                                      v.cvss_score or 0),
                       reverse=True)
        cards = "".join(_cve_card(v, show_exploit) for v in vulns)
        sections.append(
            f'<section class="tech-block"><h3>{_e(tech.display)} '
            f'<span class="count">{len(vulns)} CVE</span></h3>{cards}</section>'
        )
    vulns_html = "".join(sections) or '<p class="dim empty">Aucune CVE remontée pour les technologies détectées.</p>'

    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    head = _TEMPLATE_HEAD
    header = (
        '<header class="topbar"><div class="brand">whitehat<span>· rapport</span></div>'
        f'<div class="target"><div class="t-main">{_e(result.target)}</div>'
        f'<div class="t-sub">{_e(result.final_url)} · HTTP {_e(result.status_code)} · '
        f'{len(result.technologies)} techno(s) · {total_cve} CVE · généré le {generated}</div></div></header>'
    )
    controls = (
        '<div class="controls">'
        '<input id="q" type="search" placeholder="Rechercher (CVE, mot-clé, CWE)…" autocomplete="off">'
        '<div class="chips" id="sevChips">'
        '<button data-sev="ALL" class="chip active">Toutes</button>'
        '<button data-sev="CRITICAL" class="chip">Critiques</button>'
        '<button data-sev="HIGH" class="chip">Élevées</button>'
        '<button data-sev="MEDIUM" class="chip">Moyennes</button>'
        '<button data-sev="LOW" class="chip">Faibles</button>'
        '</div>'
        '<label class="kev-toggle"><input type="checkbox" id="kevOnly"> KEV uniquement</label>'
        '</div>'
    )
    body = (
        f'{header}<main>{_tiles(counts)}'
        '<section class="card"><h2>Technologies détectées</h2>'
        '<table class="tech"><thead><tr><th>Techno</th><th>Version</th>'
        '<th>Catégorie</th><th>CVE</th></tr></thead>'
        f'<tbody>{tech_rows}</tbody></table></section>'
        f'<section class="card"><h2>Vulnérabilités</h2>{controls}'
        f'<div id="cveList">{vulns_html}</div></section>'
        '<footer>Scan passif · explications pédagogiques non-armées · '
        'à n\'utiliser que sur des systèmes autorisés.</footer>'
        '</main>'
    )
    return head + body + _TEMPLATE_TAIL


# --- Gabarits statiques (CSS/JS : pas de f-string, accolades libres) -------
_TEMPLATE_HEAD = """<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>whitehat — rapport de scan</title>
<style>
:root{
  --bg:#f4f5f7; --panel:#ffffff; --ink:#1a1d21; --muted:#6b7280; --line:#e5e7eb;
  --accent:#2563eb; --crit:#b91c1c; --high:#ea580c; --med:#ca8a04; --low:#16a34a;
  --na:#6b7280; --kev:#7c2d12; --kevbg:#fee2e2;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#0e1116; --panel:#171b22; --ink:#e6e8eb; --muted:#9aa4b2; --line:#262c36;
    --accent:#60a5fa; --crit:#f87171; --high:#fb923c; --med:#facc15; --low:#4ade80;
    --na:#9aa4b2; --kev:#fecaca; --kevbg:#3b1414;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent)}
.topbar{display:flex;align-items:center;gap:20px;padding:16px 22px;
  background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.brand{font-weight:800;font-size:18px;letter-spacing:.3px}
.brand span{color:var(--muted);font-weight:500;margin-left:6px;font-size:13px}
.target .t-main{font-weight:700;font-size:15px}
.target .t-sub{color:var(--muted);font-size:12.5px;word-break:break-all}
main{max-width:1000px;margin:0 auto;padding:22px 18px 60px}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:14px;text-align:center}
.tile-n{font-size:26px;font-weight:800}
.tile-l{font-size:12px;color:var(--muted);margin-top:2px}
.tile-crit .tile-n{color:var(--crit)} .tile-high .tile-n{color:var(--high)}
.tile-med .tile-n{color:var(--med)} .tile-low .tile-n{color:var(--low)}
.tile-kev .tile-n{color:var(--crit)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;
  padding:18px 20px;margin-bottom:20px}
.card h2{margin:0 0 14px;font-size:16px}
table.tech{width:100%;border-collapse:collapse;font-size:13.5px}
table.tech th{text-align:left;color:var(--muted);font-weight:600;padding:6px 8px;
  border-bottom:1px solid var(--line)}
table.tech td{padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
.t-name{font-weight:600}
.dim{color:var(--muted)} .empty{padding:20px 0}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600}
.pill-bad{background:var(--kevbg);color:var(--crit)}
.pill-ok{background:rgba(22,163,74,.15);color:var(--low)}
.pill-na{background:rgba(107,114,128,.15);color:var(--muted)}
.evidence{margin-top:6px} .evidence summary{cursor:pointer;color:var(--muted);font-size:12px}
.evidence ul{margin:6px 0 0;padding-left:18px;color:var(--muted);font-size:12px}
.controls{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-bottom:16px}
#q{flex:1;min-width:220px;padding:9px 12px;border:1px solid var(--line);border-radius:9px;
  background:var(--bg);color:var(--ink);font-size:13.5px}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{cursor:pointer;border:1px solid var(--line);background:var(--panel);color:var(--ink);
  padding:7px 12px;border-radius:999px;font-size:12.5px;font-weight:600}
.chip.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.kev-toggle{display:flex;align-items:center;gap:6px;font-size:12.5px;color:var(--muted)}
.tech-block{margin-bottom:22px}
.tech-block h3{font-size:14.5px;margin:0 0 10px;padding-bottom:6px;border-bottom:1px dashed var(--line)}
.tech-block h3 .count{color:var(--muted);font-weight:500;font-size:12.5px;margin-left:6px}
.cve{background:var(--bg);border:1px solid var(--line);border-left-width:4px;
  border-radius:10px;margin-bottom:9px;overflow:hidden}
.cve summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:10px;
  padding:11px 14px;flex-wrap:wrap}
.cve summary::-webkit-details-marker{display:none}
.sev-crit{border-left-color:var(--crit)} .sev-high{border-left-color:var(--high)}
.sev-med{border-left-color:var(--med)} .sev-low{border-left-color:var(--low)}
.sev-na{border-left-color:var(--na)}
.sev-tag{font-size:11px;font-weight:800;padding:3px 8px;border-radius:6px;color:#fff}
.sev-tag.sev-crit{background:var(--crit)} .sev-tag.sev-high{background:var(--high)}
.sev-tag.sev-med{background:var(--med)} .sev-tag.sev-low{background:var(--low)}
.sev-tag.sev-na{background:var(--na)}
.cvss{font-weight:700;min-width:34px}
.cve-id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:600}
.badge-kev{background:var(--kevbg);color:var(--crit);font-size:11px;font-weight:800;
  padding:3px 8px;border-radius:6px}
.pub{color:var(--muted);font-size:12px;margin-left:auto}
.cve-body{padding:2px 14px 14px;border-top:1px solid var(--line)}
.desc{margin:10px 0}
.meta{font-size:12.5px;color:var(--muted);margin:6px 0}
.meta .k,.g-row .k{display:inline-block;font-weight:700;color:var(--ink);margin-right:6px}
.meta code,code{background:rgba(127,127,127,.15);padding:1px 6px;border-radius:5px;
  font-family:ui-monospace,Menlo,monospace;font-size:12px}
.guide{background:var(--panel);border:1px solid var(--line);border-radius:9px;
  padding:12px 14px;margin:10px 0}
.g-type{font-weight:800;margin-bottom:8px}
.g-row{margin:7px 0}
.g-row .k{display:block;margin-bottom:2px;font-size:12px;text-transform:uppercase;
  letter-spacing:.4px;color:var(--muted)}
.g-fix .k{color:var(--low)}
.refs{margin-top:10px} .refs summary{cursor:pointer;font-weight:600;font-size:12.5px}
.refs ul{margin:8px 0 0;padding-left:18px} .refs li{margin:3px 0;word-break:break-all}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:30px}
@media (max-width:640px){.tiles{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
"""

_TEMPLATE_TAIL = """
<script>
(function(){
  var q=document.getElementById('q');
  var kevOnly=document.getElementById('kevOnly');
  var chips=document.querySelectorAll('#sevChips .chip');
  var cards=Array.prototype.slice.call(document.querySelectorAll('.cve'));
  var sev='ALL';
  function apply(){
    var term=(q.value||'').trim().toLowerCase();
    var onlyKev=kevOnly.checked;
    cards.forEach(function(c){
      var okSev = sev==='ALL' || c.getAttribute('data-sev')===sev;
      var okKev = !onlyKev || c.getAttribute('data-kev')==='1';
      var okText = !term || c.getAttribute('data-text').indexOf(term)>=0;
      c.style.display = (okSev&&okKev&&okText)?'':'none';
    });
    // masque les blocs techno devenus vides
    document.querySelectorAll('.tech-block').forEach(function(b){
      var visible=b.querySelectorAll('.cve:not([style*="display: none"])').length;
      b.style.display=visible?'':'none';
    });
  }
  chips.forEach(function(ch){ch.addEventListener('click',function(){
    chips.forEach(function(x){x.classList.remove('active')});
    ch.classList.add('active'); sev=ch.getAttribute('data-sev'); apply();
  });});
  q.addEventListener('input',apply);
  kevOnly.addEventListener('change',apply);
})();
</script>
</body>
</html>
"""
