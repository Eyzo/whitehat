"""Lecture des manifestes de dépendances exposés publiquement.

Si un site laisse accessibles package.json / composer.json / *.lock /
requirements.txt, on en extrait les dépendances *avec version exacte* (surtout
via les lock-files) pour interroger OSV et refléter l'état CVE réel à l'instant T.

Best-effort et non destructif : simples GET de fichiers publics.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin

import requests

# fichiers candidats (chemin, écosystème OSV, type de parseur)
_MANIFESTS = [
    ("package-lock.json", "npm", "npm_lock"),
    ("yarn.lock", "npm", "yarn_lock"),
    ("package.json", "npm", "npm_json"),
    ("composer.lock", "Packagist", "composer_lock"),
    ("composer.json", "Packagist", "composer_json"),
    ("requirements.txt", "PyPI", "requirements"),
    ("Pipfile.lock", "PyPI", "pipfile_lock"),
    ("Gemfile.lock", "RubyGems", "gemfile_lock"),
    ("go.sum", "Go", "go_sum"),
    ("go.mod", "Go", "go_mod"),
    ("pom.xml", "Maven", "pom_xml"),
]

_VER_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def _clean_version(spec: str) -> str | None:
    if not spec or any(x in spec for x in ("*", "x", "X")) and not _VER_RE.search(spec):
        return None
    m = _VER_RE.search(spec)
    return m.group(1) if m else None


def _parse(kind: str, text: str) -> list[tuple[str, str]]:
    """Retourne [(package, version_exacte)]."""
    out: list[tuple[str, str]] = []
    try:
        if kind == "requirements":
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"([A-Za-z0-9_.\-]+)\s*==\s*([\d.]+)", line)
                if m:
                    out.append((m.group(1), m.group(2)))
            return out

        if kind == "yarn_lock":
            header = None
            for line in text.splitlines():
                if line and not line[0].isspace() and line.rstrip().endswith(":"):
                    spec = line.split(",")[0].strip().strip('"').rstrip(":")
                    header = spec[:spec.rfind("@")] if spec.rfind("@") > 0 else spec
                elif header:
                    m = re.match(r'\s+version\s+"?([\d][\w.\-]*)"?', line)
                    if m:
                        out.append((header, m.group(1)))
                        header = None
            return out

        if kind == "gemfile_lock":
            for line in text.splitlines():
                m = re.match(r"\s+([A-Za-z0-9_.\-]+) \(([0-9][^\) ]*)\)\s*$", line)
                if m:
                    out.append((m.group(1), m.group(2)))
            return out

        if kind == "go_mod":
            for line in text.splitlines():
                s = line.strip()
                if s.startswith(("module ", "go ", "require (", ")", "//")):
                    continue
                m = re.match(r"(?:require\s+)?([A-Za-z0-9._~\-/]+)\s+v([0-9][^\s/]+)", s)
                if m and "." in m.group(1):
                    out.append((m.group(1), m.group(2)))
            return out

        if kind == "go_sum":
            seen = set()
            for line in text.splitlines():
                m = re.match(r"([A-Za-z0-9._~\-/]+)\s+v([0-9][^\s/]+)", line)
                if m and (m.group(1), m.group(2)) not in seen:
                    seen.add((m.group(1), m.group(2)))
                    out.append((m.group(1), m.group(2)))
            return out

        if kind == "pom_xml":
            for block in re.findall(r"<dependency>(.*?)</dependency>", text, re.S):
                g = re.search(r"<groupId>\s*([^<${]+?)\s*</groupId>", block)
                a = re.search(r"<artifactId>\s*([^<${]+?)\s*</artifactId>", block)
                v = re.search(r"<version>\s*([^<${]+?)\s*</version>", block)
                if g and a and v:
                    out.append((f"{g.group(1)}:{a.group(1)}", v.group(1)))
            return out

        data = json.loads(text)
        if kind == "pipfile_lock":
            for sect in ("default", "develop"):
                for name, meta in (data.get(sect) or {}).items():
                    ver = (meta or {}).get("version", "")
                    m = re.search(r"([0-9][\w.\-]*)", str(ver))
                    if m:
                        out.append((name, m.group(1)))
            return out
        if kind == "npm_json":
            for sect in ("dependencies", "devDependencies"):
                for name, spec in (data.get(sect) or {}).items():
                    v = _clean_version(str(spec))
                    if v:
                        out.append((name, v))
        elif kind == "npm_lock":
            pkgs = data.get("packages")
            if isinstance(pkgs, dict):  # lockfile v2/v3
                for path, meta in pkgs.items():
                    if path.startswith("node_modules/") and meta.get("version"):
                        out.append((path.split("node_modules/")[-1], meta["version"]))
            deps = data.get("dependencies")
            if isinstance(deps, dict):  # lockfile v1
                for name, meta in deps.items():
                    if isinstance(meta, dict) and meta.get("version"):
                        out.append((name, str(meta["version"]).lstrip("^~=v ")))
        elif kind == "composer_json":
            for sect in ("require", "require-dev"):
                for name, spec in (data.get(sect) or {}).items():
                    if "/" not in name:
                        continue  # ignore php, ext-*
                    v = _clean_version(str(spec))
                    if v:
                        out.append((name, v))
        elif kind == "composer_lock":
            for sect in ("packages", "packages-dev"):
                for pkg in (data.get(sect) or []):
                    if pkg.get("name") and pkg.get("version"):
                        out.append((pkg["name"], str(pkg["version"]).lstrip("v")))
    except (json.JSONDecodeError, ValueError, TypeError):
        return out
    return out


def collect(base_url: str, session: requests.Session, timeout: float = 8.0,
            max_deps: int = 200) -> list[dict]:
    """Retourne [{ecosystem, package, version, source}] pour les manifestes trouvés."""
    base = base_url if base_url.endswith("/") else base_url + "/"
    seen: set[tuple[str, str, str]] = set()
    deps: list[dict] = []

    for path, ecosystem, kind in _MANIFESTS:
        try:
            r = session.get(urljoin(base, path), timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code != 200 or len(r.text) > 5_000_000:
            continue
        for pkg, ver in _parse(kind, r.text):
            key = (ecosystem, pkg.lower(), ver)
            if key in seen:
                continue
            seen.add(key)
            deps.append({"ecosystem": ecosystem, "package": pkg,
                         "version": ver, "source": path})
            if len(deps) >= max_deps:
                return deps
    return deps
