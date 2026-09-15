"""Règles d'empreinte : détecte technos + versions à partir de la réponse HTTP.

Chaque règle est data-driven. Une règle inspecte une "source" de la réponse
(header, cookie, corps HTML, meta generator, url de script) via une regex, et
produit une Technology. La regex peut capturer une version dans un groupe nommé
`ver` ou dans le premier groupe.

Ce n'est volontairement pas exhaustif : le but est de couvrir les technos les
plus courantes de façon fiable, et d'être facilement extensible (ajoute une
entrée dans RULES).
"""

from __future__ import annotations

import re
from typing import Optional

from .models import Technology

# --- Structure d'une règle -------------------------------------------------
# source : "header:<Nom>", "cookie", "html", "meta-generator", "script-src"
# pattern: regex (insensible à la casse). Groupe (?P<ver>...) => version.
# tech   : gabarit de Technology (name, categories, cpe_vendor, cpe_product)
#
# Plusieurs règles peuvent pointer la même techno ; on fusionne (la meilleure
# version + toutes les preuves l'emportent).

RULES: list[dict] = [
    # --- Serveurs web ---
    {
        "source": "header:Server",
        "pattern": r"apache(?:/(?P<ver>[\d.]+))?",
        "tech": dict(name="Apache HTTP Server", categories=["Serveur web"],
                     cpe_vendor="apache", cpe_product="http_server"),
    },
    {
        "source": "header:Server",
        "pattern": r"nginx(?:/(?P<ver>[\d.]+))?",
        "tech": dict(name="nginx", categories=["Serveur web"],
                     cpe_vendor="nginx", cpe_product="nginx"),
    },
    {
        "source": "header:Server",
        "pattern": r"microsoft-iis(?:/(?P<ver>[\d.]+))?",
        "tech": dict(name="Microsoft IIS", categories=["Serveur web"],
                     cpe_vendor="microsoft", cpe_product="internet_information_services"),
    },
    {
        "source": "header:Server",
        "pattern": r"(?:apache-coyote|tomcat)(?:/(?P<ver>[\d.]+))?",
        "tech": dict(name="Apache Tomcat", categories=["Serveur applicatif"],
                     cpe_vendor="apache", cpe_product="tomcat"),
    },
    {
        "source": "header:Server",
        "pattern": r"litespeed(?:/(?P<ver>[\d.]+))?",
        "tech": dict(name="LiteSpeed", categories=["Serveur web"],
                     cpe_vendor="litespeedtech", cpe_product="litespeed_web_server"),
    },
    # --- Langages / runtimes ---
    {
        "source": "header:X-Powered-By",
        "pattern": r"php(?:/(?P<ver>[\d.]+))?",
        "tech": dict(name="PHP", categories=["Langage"],
                     cpe_vendor="php", cpe_product="php"),
    },
    {
        "source": "header:Server",
        "pattern": r"php(?:/(?P<ver>[\d.]+))?",
        "tech": dict(name="PHP", categories=["Langage"],
                     cpe_vendor="php", cpe_product="php"),
    },
    {
        "source": "header:X-Powered-By",
        "pattern": r"asp\.net",
        "tech": dict(name="ASP.NET", categories=["Framework"]),
    },
    {
        "source": "header:X-Powered-By",
        "pattern": r"express",
        "tech": dict(name="Express", categories=["Framework"]),
    },
    {
        "source": "header:X-AspNet-Version",
        "pattern": r"(?P<ver>[\d.]+)",
        "tech": dict(name="ASP.NET", categories=["Framework"]),
    },
    # --- CMS ---
    {
        "source": "meta-generator",
        "pattern": r"wordpress(?:\s+(?P<ver>[\d.]+))?",
        "tech": dict(name="WordPress", categories=["CMS"],
                     cpe_vendor="wordpress", cpe_product="wordpress"),
    },
    {
        "source": "html",
        "pattern": r"/wp-(?:content|includes)/",
        "tech": dict(name="WordPress", categories=["CMS"],
                     cpe_vendor="wordpress", cpe_product="wordpress"),
    },
    {
        "source": "meta-generator",
        "pattern": r"drupal(?:\s+(?P<ver>[\d.]+))?",
        "tech": dict(name="Drupal", categories=["CMS"],
                     cpe_vendor="drupal", cpe_product="drupal"),
    },
    {
        "source": "header:X-Generator",
        "pattern": r"drupal\s*(?P<ver>[\d.]+)?",
        "tech": dict(name="Drupal", categories=["CMS"],
                     cpe_vendor="drupal", cpe_product="drupal"),
    },
    {
        "source": "meta-generator",
        "pattern": r"joomla!?(?:\s+(?P<ver>[\d.]+))?",
        "tech": dict(name="Joomla", categories=["CMS"],
                     cpe_vendor="joomla", cpe_product="joomla\\!"),
    },
    {
        "source": "meta-generator",
        "pattern": r"typo3",
        "tech": dict(name="TYPO3", categories=["CMS"],
                     cpe_vendor="typo3", cpe_product="typo3"),
    },
    {
        "source": "cookie",
        "pattern": r"prestashop",
        "tech": dict(name="PrestaShop", categories=["E-commerce"],
                     cpe_vendor="prestashop", cpe_product="prestashop"),
    },
    {
        "source": "cookie",
        "pattern": r"magento",
        "tech": dict(name="Magento", categories=["E-commerce"],
                     cpe_vendor="magento", cpe_product="magento"),
    },
    # --- Frameworks JS front ---
    {
        "source": "script-src",
        "pattern": r"jquery[-.](?P<ver>\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js",
        "tech": dict(name="jQuery", categories=["Bibliothèque JS"],
                     cpe_vendor="jquery", cpe_product="jquery"),
    },
    {
        "source": "script-src",
        "pattern": r"bootstrap[-.](?P<ver>\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)",
        "tech": dict(name="Bootstrap", categories=["Framework CSS"],
                     cpe_vendor="getbootstrap", cpe_product="bootstrap"),
    },
    {
        "source": "html",
        "pattern": r"ng-version=\"(?P<ver>[\d.]+)\"",
        "tech": dict(name="Angular", categories=["Framework JS"],
                     cpe_vendor="angular", cpe_product="angular"),
    },
    {
        "source": "html",
        "pattern": r"data-reactroot|react(?:-dom)?[-.](?P<ver>\d+\.\d+\.\d+)",
        "tech": dict(name="React", categories=["Framework JS"]),
    },
    {
        "source": "script-src",
        "pattern": r"vue(?:[-.](?P<ver>\d+\.\d+\.\d+))?(?:\.min)?\.js",
        "tech": dict(name="Vue.js", categories=["Framework JS"],
                     cpe_vendor="vuejs", cpe_product="vue"),
    },
    # --- Reverse proxies / CDN / cache (infra, généralement pas de CVE ciblée) ---
    {
        "source": "header:Server",
        "pattern": r"cloudflare",
        "tech": dict(name="Cloudflare", categories=["CDN"]),
    },
    {
        "source": "header:Via",
        "pattern": r"varnish",
        "tech": dict(name="Varnish", categories=["Cache"],
                     cpe_vendor="varnish-cache", cpe_product="varnish_cache"),
    },
    {
        "source": "header:X-Powered-By",
        "pattern": r"next\.js",
        "tech": dict(name="Next.js", categories=["Framework JS"],
                     cpe_vendor="vercel", cpe_product="next.js"),
    },
    # --- Serveurs / proxys additionnels ---
    {
        "source": "header:Server",
        "pattern": r"openresty(?:/(?P<ver>[\d.]+))?",
        "tech": dict(name="OpenResty", categories=["Serveur web"],
                     cpe_vendor="openresty", cpe_product="openresty"),
    },
    {
        "source": "header:Server",
        "pattern": r"caddy",
        "tech": dict(name="Caddy", categories=["Serveur web"],
                     cpe_vendor="caddyserver", cpe_product="caddy"),
    },
    {
        "source": "header:Server",
        "pattern": r"jetty(?:/(?P<ver>[\d.]+))?",
        "tech": dict(name="Eclipse Jetty", categories=["Serveur applicatif"],
                     cpe_vendor="eclipse", cpe_product="jetty"),
    },
    {
        "source": "header:Server",
        "pattern": r"gunicorn(?:/(?P<ver>[\d.]+))?",
        "tech": dict(name="Gunicorn", categories=["Serveur applicatif"],
                     cpe_vendor="gunicorn", cpe_product="gunicorn"),
    },
    {
        "source": "header:Server",
        "pattern": r"kestrel",
        "tech": dict(name="Kestrel (ASP.NET Core)", categories=["Serveur applicatif"]),
    },
    # --- Langages / frameworks serveur ---
    {
        "source": "cookie",
        "pattern": r"csrftoken|django",
        "tech": dict(name="Django", categories=["Framework"],
                     cpe_vendor="djangoproject", cpe_product="django"),
    },
    {
        "source": "cookie",
        "pattern": r"_rails|_session_id",
        "tech": dict(name="Ruby on Rails", categories=["Framework"],
                     cpe_vendor="rubyonrails", cpe_product="rails"),
    },
    {
        "source": "cookie",
        "pattern": r"laravel_session|xsrf-token",
        "tech": dict(name="Laravel", categories=["Framework"],
                     cpe_vendor="laravel", cpe_product="laravel"),
    },
    {
        "source": "header:X-Powered-By",
        "pattern": r"servlet|jsp",
        "tech": dict(name="Java Servlet", categories=["Langage"]),
    },
    {
        "source": "header:X-Generator",
        "pattern": r"typo3",
        "tech": dict(name="TYPO3", categories=["CMS"],
                     cpe_vendor="typo3", cpe_product="typo3"),
    },
    # --- CMS / e-commerce additionnels ---
    {
        "source": "meta-generator",
        "pattern": r"shopify",
        "tech": dict(name="Shopify", categories=["E-commerce"]),
    },
    {
        "source": "meta-generator",
        "pattern": r"wix\.com",
        "tech": dict(name="Wix", categories=["CMS"]),
    },
    {
        "source": "meta-generator",
        "pattern": r"squarespace",
        "tech": dict(name="Squarespace", categories=["CMS"]),
    },
    {
        "source": "meta-generator",
        "pattern": r"ghost(?:\s+(?P<ver>[\d.]+))?",
        "tech": dict(name="Ghost", categories=["CMS"],
                     cpe_vendor="ghost", cpe_product="ghost"),
    },
    {
        "source": "header:MicrosoftSharePointTeamServices",
        "pattern": r"(?P<ver>[\d.]+)",
        "tech": dict(name="Microsoft SharePoint", categories=["CMS"],
                     cpe_vendor="microsoft", cpe_product="sharepoint_server"),
    },
    # --- Bibliothèques JS (surface CVE via version dans l'URL) ---
    {
        "source": "script-src",
        "pattern": r"lodash[-.](?P<ver>\d+\.\d+\.\d+)(?:\.min)?\.js",
        "tech": dict(name="Lodash", categories=["Bibliothèque JS"],
                     cpe_vendor="lodash", cpe_product="lodash"),
    },
    {
        "source": "script-src",
        "pattern": r"(?:moment)[-.](?P<ver>\d+\.\d+\.\d+)(?:\.min)?\.js",
        "tech": dict(name="Moment.js", categories=["Bibliothèque JS"],
                     cpe_vendor="momentjs", cpe_product="moment"),
    },
    {
        "source": "script-src",
        "pattern": r"angular[-.](?P<ver>1\.\d+\.\d+)(?:\.min)?\.js",
        "tech": dict(name="AngularJS", categories=["Framework JS"],
                     cpe_vendor="angularjs", cpe_product="angular.js"),
    },
    {
        "source": "script-src",
        "pattern": r"d3[-.](?P<ver>\d+\.\d+\.\d+)(?:\.min)?\.js",
        "tech": dict(name="D3.js", categories=["Bibliothèque JS"]),
    },
    {
        "source": "script-src",
        "pattern": r"handlebars[-.](?P<ver>\d+\.\d+\.\d+)(?:\.min)?\.js",
        "tech": dict(name="Handlebars", categories=["Bibliothèque JS"],
                     cpe_vendor="handlebarsjs", cpe_product="handlebars"),
    },
    {
        "source": "script-src",
        "pattern": r"(?:underscore|backbone)[-.](?P<ver>\d+\.\d+\.\d+)(?:\.min)?\.js",
        "tech": dict(name="Underscore/Backbone", categories=["Bibliothèque JS"]),
    },
    {
        "source": "script-src",
        "pattern": r"select2[-.](?P<ver>\d+\.\d+\.\d+)",
        "tech": dict(name="Select2", categories=["Bibliothèque JS"]),
    },
    {
        "source": "script-src",
        "pattern": r"dompurify[-.](?P<ver>\d+\.\d+\.\d+)",
        "tech": dict(name="DOMPurify", categories=["Bibliothèque JS"],
                     cpe_vendor="cure53", cpe_product="dompurify"),
    },
    # --- Analytics / tags / infra (pas de CVE ciblée) ---
    {
        "source": "script-src",
        "pattern": r"googletagmanager\.com/gtm\.js",
        "tech": dict(name="Google Tag Manager", categories=["Analytics"]),
    },
    {
        "source": "script-src",
        "pattern": r"google-analytics\.com|gtag/js",
        "tech": dict(name="Google Analytics", categories=["Analytics"]),
    },
    {
        "source": "header:X-Served-By",
        "pattern": r"fastly|cache-",
        "tech": dict(name="Fastly", categories=["CDN"]),
    },
    {
        "source": "header:X-Amz-Cf-Id",
        "pattern": r".+",
        "tech": dict(name="Amazon CloudFront", categories=["CDN"]),
    },
    {
        "source": "header:X-Akamai-Transformed",
        "pattern": r".+",
        "tech": dict(name="Akamai", categories=["CDN"]),
    },
]

# Pré-compilation
for _r in RULES:
    _r["_re"] = re.compile(_r["pattern"], re.IGNORECASE)

_META_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"'](?P<content>[^\"']+)[\"']",
    re.IGNORECASE,
)
_SCRIPT_SRC_RE = re.compile(r"<(?:script|link)[^>]+(?:src|href)=[\"']([^\"']+)[\"']", re.IGNORECASE)


def _iter_sources(headers: dict[str, str], cookies: list[str], html: str):
    """Yield (source_key, valeur) pour chaque fragment analysable."""
    # Headers
    for name, value in headers.items():
        yield f"header:{name.lower()}", value
    # Cookies (noms)
    for c in cookies:
        yield "cookie", c
    # meta generator
    for m in _META_GENERATOR_RE.finditer(html):
        yield "meta-generator", m.group("content")
    # scripts / links
    for m in _SCRIPT_SRC_RE.finditer(html):
        yield "script-src", m.group(1)
    # HTML brut (limité pour perf)
    yield "html", html[:200_000]


def detect(headers: dict[str, str], cookies: list[str], html: str) -> list[Technology]:
    """Applique toutes les règles, fusionne et retourne les technos détectées."""
    found: dict[str, Technology] = {}

    for rule in RULES:
        source = rule["source"]
        regex: re.Pattern = rule["_re"]
        tmpl = rule["tech"]

        for src_key, value in _iter_sources(headers, cookies, html):
            # Match du type de source. "header:server" doit matcher exactement.
            if source.startswith("header:"):
                if src_key != source.lower():
                    continue
            elif src_key != source:
                continue

            m = regex.search(value)
            if not m:
                continue

            version: Optional[str] = None
            if "ver" in regex.groupindex:
                version = m.group("ver")

            key = tmpl["name"]
            tech = found.get(key)
            if tech is None:
                tech = Technology(
                    name=tmpl["name"],
                    categories=list(tmpl.get("categories", [])),
                    cpe_vendor=tmpl.get("cpe_vendor"),
                    cpe_product=tmpl.get("cpe_product"),
                )
                found[key] = tech

            if version and not tech.version:
                tech.version = version

            ev = f"{src_key} → {value[:120]}"
            if ev not in tech.evidence:
                tech.evidence.append(ev)

    return list(found.values())
