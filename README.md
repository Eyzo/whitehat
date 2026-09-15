# whitehat

Scanner de reconnaissance web : **identifie les technologies** d'un site,
**mappe les CVE connues** (base NVD/NIST) et, pour chaque faille, fournit une
**explication du mécanisme, une méthode de reproduction (cadre autorisé) et la
remédiation**, avec les références publiques (advisories, PoC, ExploitDB).

> ⚠️ **Usage strictement autorisé.** N'utilise cet outil que sur des systèmes
> dont tu es propriétaire ou pour lesquels tu disposes d'un **mandat écrit**
> (pentest, bug bounty dans le scope, CTF, labo). Le scan reste passif (requêtes
> GET normales) ; aucune charge d'attaque n'est envoyée. Les explications
> d'exploitation sont **pédagogiques et non-armées** : elles décrivent le
> principe et renvoient aux advisories, pas des exploits clé en main.

## Fonctionnement

```
   cible ──▶ scanner (HTTP) ──▶ empreintes (technos+versions)
                                      │
                                      ▼
                             CPE ──▶ NVD API ──▶ CVE (CVSS, CWE, refs)
                                      │                 │
                                      │                 ▼
                                      │         CISA KEV (exploitée ?)
                                      ▼
                          guide d'exploitation par CWE
                                      │
                                      ▼
                       rapport console / JSON / Markdown
```

## Installation

L'outil requiert `requests` et `rich`.

```bash
# option A : installation éditable (fournit la commande `whitehat`)
python3 -m pip install -e .

# option B : dépendances seules, exécution en module
python3 -m pip install -r requirements.txt
```

### Clé API NVD (recommandée)

Sans clé, la NVD limite à ~5 requêtes / 30 s (le scan est alors lent). Demande
une clé gratuite sur <https://nvd.nist.gov/developers/request-an-api-key> puis :

```bash
export NVD_API_KEY="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Les réponses NVD et le catalogue CISA KEV sont mis en cache 24 h dans
`~/.cache/whitehat` (personnalisable via `WHITEHAT_CACHE`).

## Console web (recommandé)

Lance les scans et consulte les rapports depuis le navigateur, avec historique,
progression en temps réel et priorisation par risque.

```bash
python3 -m pip install -e ".[web]"     # backend web (FastAPI + uvicorn)
whitehat-web                            # → http://127.0.0.1:8787
# ou : python3 -m whitehat.web.server --port 8787
```

- **Deux vues** : *Vue simple* par défaut (une note A→F, une synthèse en une
  phrase, et chaque problème expliqué « Ce que c'est / Le risque / Que faire »
  en langage clair) et *Vue technique* (CVE, CVSS, EPSS, CWE, en-têtes…) pour
  les experts. Toute l'analyse tient derrière un seul champ + le bouton
  « Analyser » ; les réglages sont repliés dans « Options avancées ».
- Écoute en **local uniquement** (`127.0.0.1`) : le scanner doit émettre des
  requêtes réseau vers tes cibles, ce qu'un service hébergé/sandboxé ne peut pas
  faire ; les données de scan restent sur ta machine.
- **Case d'autorisation obligatoire** avant chaque lancement.
- Historique stocké en SQLite (`~/.local/share/whitehat/scans.db`, override
  `WHITEHAT_DB`).

Ce que couvre un scan complet :

| Couche | Détail |
|---|---|
| Découverte | Lit `robots.txt` (Sitemap/Disallow) et `sitemap.xml` (+ index) pour guider le parcours |
| Crawl multi-pages | Suit les liens même-origine, amorcé par la découverte |
| Empreintes + CVE | ~50 règles technos/versions → CVE NVD par CPE |
| Librairies (détection large) | cdnjs/jsdelivr/unpkg + fichiers versionnés → paquet+version |
| Librairies minifiées (signatures) | retire.js : bannières dans le **contenu** des scripts → détecte même bundlé/minifié, avec CVE |
| CVE librairies (OSV) | npm, **Packagist (PHP)**, **PyPI**… (avis GitHub, sans clé) |
| Dépendances (manifestes) | `package.json`/`package-lock`/`yarn.lock`/`composer.*`/`requirements.txt`/`Pipfile.lock`/`Gemfile.lock`/`go.mod`/`go.sum`/`pom.xml` exposés → OSV (npm/Packagist/PyPI/RubyGems/Go/Maven) |
| Obsolescence libs JS | version installée vs dernière sur npm |
| WordPress | Plugins **et thèmes** + versions → OSV Packagist + NVD mots-clés ; obsolescence (wordpress.org) |
| Autres CMS | Modules/thèmes **Drupal**, extensions **Joomla**, modules **PrestaShop** → NVD mots-clés |
| Priorisation | **CVSS × EPSS × CISA KEV** → score de risque 0-10 |
| Hygiène | En-têtes de sécurité, flags cookies, version/cert TLS |
| Expositions | `.git`, `.env`, backups, `server-status`, actuator, phpinfo… |
| Nuclei (option) | Milliers de templates communautaires (couverture max) |

La console propose un **guide d'utilisation** intégré (`/guide`) et une **barre
de progression détaillée** (étapes cochées en temps réel) pendant l'analyse.

**Vérification par CVE (non destructive).** Pour chaque CVE disposant d'un
template Nuclei (~4400 en local), la vue technique affiche la commande
reproductible (`nuclei -u <cible> -id CVE-…`) et un bouton **« Vérifier »** qui
lance ce test ciblé contre la cible déjà scannée → *présent* / *non confirmé*.
On relance après le correctif pour confirmer la remédiation. Aucun exploit
offensif n'est généré : ce sont des sondes de détection, sûres et reproductibles.

### Activer Nuclei (couverture maximale)

Installe le binaire ProjectDiscovery (la case « Nuclei » s'active alors seule) :

```bash
# via Go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# ou binaire pré-compilé : https://github.com/projectdiscovery/nuclei/releases
nuclei -update-templates
```

## Utilisation en ligne de commande

```bash
# scan complet (technos + CVE + explication)
whitehat example.com
# ou sans installation :
python3 -m whitehat example.com

# empreinte seule, sans requête NVD
whitehat example.com --no-cve

# filtrer par sévérité et limiter le nombre de CVE
whitehat example.com --min-severity HIGH --max-cve 10

# exports (JSON, Markdown, page HTML autonome)
whitehat example.com --json rapport.json --md rapport.md
whitehat example.com --html rapport.html        # page consultable au navigateur
whitehat example.com --html --open              # génère + ouvre dans le navigateur

# sans explication d'exploitation
whitehat example.com --no-exploit
```

### Principales options

| Option | Effet |
|---|---|
| `--no-cve` | Détection des technos uniquement |
| `--no-exploit` | Masque l'explication mécanisme/reproduction |
| `--max-cve N` | Nombre max de CVE par techno (défaut 15) |
| `--min-severity` | `LOW`/`MEDIUM`/`HIGH`/`CRITICAL` |
| `--api-key` | Clé NVD (sinon `NVD_API_KEY`) |
| `--insecure` | Ne pas vérifier le TLS |
| `--json` / `--md` | Export fichier |
| `--html [FICHIER]` | Page HTML autonome consultable (défaut `whitehat-report.html`) |
| `--open` | Ouvre le rapport HTML dans le navigateur |

## Structure du code

| Module | Rôle |
|---|---|
| `scanner.py` | Récupération HTTP passive de la cible |
| `fingerprints.py` | Règles de détection technos/versions (extensible) |
| `nvd.py` | Client NVD 2.0 (CPE, cache, rate-limit) + CISA KEV |
| `exploitation.py` | Base de connaissances mécanisme/reproduction par CWE |
| `report.py` | Rendu console (rich), JSON, Markdown |
| `htmlreport.py` | Génère la page HTML autonome (CSS/JS inline, filtrable) |
| `orchestrator.py` | Enchaîne toutes les étapes d'un scan complet (+ progression) |
| `engine/discovery.py` | Découverte d'URLs via robots.txt + sitemap(s) |
| `engine/crawl.py` | Crawler léger même-origine (amorcé par la découverte) |
| `engine/osv.py` | Client OSV.dev multi-écosystème (npm/Packagist/PyPI…) + cache |
| `engine/libdetect.py` | Détection large de librairies (CDN + fichiers versionnés) |
| `engine/retirejs.py` | Signatures de contenu (retire.js) : libs minifiées/bundlées + CVE |
| `engine/manifests.py` | Manifestes de dépendances exposés (npm/PHP/Python/Ruby/Go/Maven) |
| `engine/npmreg.py` | Obsolescence des librairies JS (registre npm) |
| `engine/wordpress.py` | Énumération plugins/thèmes WordPress + versions + obsolescence |
| `engine/cms.py` | Extensions Drupal/Joomla/PrestaShop |
| `engine/headers_audit.py` | Audit en-têtes / cookies / TLS |
| `engine/exposures.py` | Détection de fichiers/chemins sensibles exposés |
| `engine/risk.py` | EPSS + score de risque combiné |
| `engine/nuclei.py` | Wrapper Nuclei (détection + parsing JSONL) |
| `verdict.py` | Traduction en langage clair : note A→F + actions simples |
| `web/` | Console web FastAPI (API, SSE, SQLite, dashboard + détail) |
| `cli.py` | Orchestration ligne de commande |

## Étendre la détection

Ajoute une entrée dans `RULES` (`whitehat/fingerprints.py`). Exemple :

```python
{
    "source": "header:Server",
    "pattern": r"openresty(?:/(?P<ver>[\d.]+))?",
    "tech": dict(name="OpenResty", categories=["Serveur web"],
                 cpe_vendor="openresty", cpe_product="openresty"),
},
```

Le `cpe_vendor`/`cpe_product` doit correspondre au dictionnaire CPE de la NVD
pour que le mapping CVE fonctionne.

## Limites connues

- La détection dépend des signaux exposés : un WAF/CDN (Cloudflare…) ou un
  serveur qui masque ses en-têtes réduit la surface détectable.
- Le mapping CVE est fiable surtout quand une **version** est identifiée ; sans
  version, la CPE remonte parfois du bruit.
- L'outil ne confirme pas *activement* qu'une CVE est exploitable sur la cible
  (pas de probe intrusif) — c'est un choix de sécurité et de légalité.
