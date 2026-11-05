#!/usr/bin/env python3
"""Surface — audit web passif d'une page d'accueil.

Surface envoie une requête GET ordinaire vers la page d'accueil d'un domaine,
lit les en-têtes de la réponse et les transforme en recommandations classées :

    PRIORITAIRE   un réglage observé pose problème
    À VÉRIFIER    un signal manque ou demande une vérification humaine
    OK            le réglage attendu est présent
    NON ÉVALUÉ    l'information n'est pas visible depuis une réponse HTTP

Aucun test intrusif : pas de fuzzing, pas d'injection, pas de scan de ports.
Sans dépendance externe (bibliothèque standard Python 3.9+).

Exemples :
    python3 surface.py example.com
    python3 surface.py example.com --format markdown > rapport.md
    python3 surface.py --from-file examples/reponse-fictive.txt
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import ssl
import sys
from dataclasses import asdict, dataclass, field
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

__version__ = "1.0.0"

USER_AGENT = f"surface-audit/{__version__} (+https://github.com/NicolasJaumotte/surface-audit)"
MAX_REDIRECTS = 5
TIMEOUT_S = 10
SIX_MONTHS = 15_552_000

PRIORITAIRE = "PRIORITAIRE"
A_VERIFIER = "À VÉRIFIER"
OK = "OK"
NON_EVALUE = "NON ÉVALUÉ"
ORDER = {PRIORITAIRE: 0, A_VERIFIER: 1, OK: 2, NON_EVALUE: 3}

Headers = List[Tuple[str, str]]


# --------------------------------------------------------------------------
# Modèle
# --------------------------------------------------------------------------

@dataclass
class Response:
    """Ce que Surface a observé : URL finale, en-têtes, redirections."""

    url: str
    status: int
    headers: Headers
    redirects: List[str] = field(default_factory=list)
    http_redirects_to_https: Optional[bool] = None  # None = non testé

    def get(self, name: str) -> Optional[str]:
        values = self.get_all(name)
        return values[-1] if values else None

    def get_all(self, name: str) -> List[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]


@dataclass
class Finding:
    check: str
    status: str
    observed: str
    next_step: str
    ref: str = ""


# --------------------------------------------------------------------------
# Contrôles (fonctions pures : Response -> Finding)
# --------------------------------------------------------------------------

OWASP_HEADERS = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"


def check_https(r: Response) -> Finding:
    if urlsplit(r.url).scheme == "https":
        return Finding("HTTPS", OK, f"Page servie en HTTPS ({r.url}).",
                       "Rien à faire sur ce point.")
    return Finding("HTTPS", PRIORITAIRE, f"Page finale servie en HTTP ({r.url}).",
                   "Servir le site en HTTPS et rediriger tout le trafic HTTP.",
                   "https://letsencrypt.org/fr/getting-started/")


def check_http_redirect(r: Response) -> Finding:
    name = "Redirection HTTP → HTTPS"
    if r.http_redirects_to_https is None:
        return Finding(name, NON_EVALUE, "Non testé (mode hors ligne ou option --no-http).",
                       "Relancer l'audit en ligne sans --no-http.")
    if r.http_redirects_to_https:
        return Finding(name, OK, "http:// redirige vers https://.", "Rien à faire sur ce point.")
    return Finding(name, PRIORITAIRE, "http:// ne redirige pas vers https://.",
                   "Ajouter une redirection permanente (301/308) vers HTTPS.")


def check_hsts(r: Response) -> Finding:
    name = "HSTS"
    if urlsplit(r.url).scheme != "https":
        return Finding(name, NON_EVALUE, "Sans HTTPS, l'en-tête n'a pas d'effet.",
                       "Activer HTTPS d'abord.")
    value = r.get("Strict-Transport-Security")
    if not value:
        return Finding(name, A_VERIFIER, "En-tête Strict-Transport-Security absent.",
                       "Ajouter Strict-Transport-Security: max-age=31536000; includeSubDomains "
                       "après avoir vérifié que tous les sous-domaines sont en HTTPS.", OWASP_HEADERS)
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    max_age = int(m.group(1)) if m else 0
    if max_age < SIX_MONTHS:
        return Finding(name, A_VERIFIER, f"max-age={max_age} s, soit moins de six mois.",
                       "Augmenter progressivement max-age (au moins 15552000).", OWASP_HEADERS)
    extra = " avec includeSubDomains" if "includesubdomains" in value.lower() else ""
    return Finding(name, OK, f"max-age={max_age} s{extra}.", "Rien à faire sur ce point.")


def _csp_directives(policy: str) -> dict:
    out = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return out


def check_csp(r: Response) -> Finding:
    name = "Politique de contenu (CSP)"
    policy = r.get("Content-Security-Policy")
    if not policy:
        report_only = r.get("Content-Security-Policy-Report-Only")
        observed = ("Seulement en mode Report-Only : rien n'est bloqué."
                    if report_only else "En-tête Content-Security-Policy absent.")
        return Finding(name, A_VERIFIER, observed,
                       "Inventorier les scripts du site puis déployer une CSP, "
                       "d'abord en Report-Only.", OWASP_HEADERS)
    d = _csp_directives(policy)
    scripts = d.get("script-src", d.get("default-src"))
    weak = []
    if scripts is None:
        weak.append("ni script-src ni default-src")
    else:
        if "'unsafe-inline'" in scripts and not any(
                s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in scripts):
            weak.append("'unsafe-inline' sans nonce ni hash")
        if "'unsafe-eval'" in scripts:
            weak.append("'unsafe-eval'")
        if "*" in scripts or "http:" in scripts or "https:" in scripts:
            weak.append("source de scripts trop large")
    if weak:
        return Finding(name, A_VERIFIER, "CSP présente mais permissive : " + ", ".join(weak) + ".",
                       "Remplacer les scripts inline par des nonces ou des hash.", OWASP_HEADERS)
    return Finding(name, OK, "CSP présente, sans source de script permissive détectée.",
                   "Vérifier que la politique couvre aussi object-src et base-uri.")


def check_clickjacking(r: Response) -> Finding:
    name = "Protection contre le clickjacking"
    csp = _csp_directives(r.get("Content-Security-Policy") or "")
    xfo = (r.get("X-Frame-Options") or "").strip().upper()
    if "frame-ancestors" in csp:
        return Finding(name, OK, "CSP frame-ancestors : " + " ".join(csp["frame-ancestors"]) + ".",
                       "Rien à faire sur ce point.")
    if xfo in ("DENY", "SAMEORIGIN"):
        return Finding(name, OK, f"X-Frame-Options: {xfo}.",
                       "Envisager aussi CSP frame-ancestors, plus moderne.")
    return Finding(name, A_VERIFIER, "Ni frame-ancestors ni X-Frame-Options valide.",
                   "Ajouter Content-Security-Policy: frame-ancestors 'self' "
                   "si le site n'a pas à être intégré ailleurs.", OWASP_HEADERS)


def check_nosniff(r: Response) -> Finding:
    name = "X-Content-Type-Options"
    if (r.get("X-Content-Type-Options") or "").strip().lower() == "nosniff":
        return Finding(name, OK, "nosniff présent.", "Rien à faire sur ce point.")
    return Finding(name, A_VERIFIER, "nosniff absent.",
                   "Ajouter X-Content-Type-Options: nosniff.", OWASP_HEADERS)


def check_referrer(r: Response) -> Finding:
    name = "Referrer-Policy"
    value = (r.get("Referrer-Policy") or "").strip().lower()
    if not value:
        return Finding(name, A_VERIFIER, "En-tête absent : le navigateur applique sa valeur par défaut.",
                       "Fixer Referrer-Policy: strict-origin-when-cross-origin.", OWASP_HEADERS)
    if value in ("unsafe-url", "no-referrer-when-downgrade"):
        return Finding(name, A_VERIFIER, f"Valeur permissive : {value}.",
                       "Passer à strict-origin-when-cross-origin.", OWASP_HEADERS)
    return Finding(name, OK, f"Valeur : {value}.", "Rien à faire sur ce point.")


def check_disclosure(r: Response) -> Finding:
    name = "Informations sur la pile technique"
    leaks = []
    server = r.get("Server")
    if server and re.search(r"\d", server):
        leaks.append(f"Server: {server}")
    for h in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        if r.get(h):
            leaks.append(f"{h}: {r.get(h)}")
    if leaks:
        return Finding(name, A_VERIFIER, "Versions exposées — " + " ; ".join(leaks) + ".",
                       "Masquer les numéros de version et vérifier que ces composants sont à jour. "
                       "Les cacher ne remplace pas les mises à jour.", OWASP_HEADERS)
    return Finding(name, OK, "Aucun numéro de version visible dans les en-têtes.",
                   "Rien à faire sur ce point.")


def check_cors(r: Response) -> Finding:
    name = "CORS"
    origin = (r.get("Access-Control-Allow-Origin") or "").strip()
    creds = (r.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
    if not origin:
        return Finding(name, OK, "Pas d'en-tête CORS sur la page d'accueil.",
                       "Les API se contrôlent séparément, endpoint par endpoint.")
    if origin == "*" and creds:
        return Finding(name, PRIORITAIRE, "Origine * avec Allow-Credentials: true.",
                       "Restreindre les origines autorisées à une liste explicite.")
    if origin == "*":
        return Finding(name, A_VERIFIER, "Origine * : toute page peut lire cette réponse.",
                       "Acceptable pour un contenu public ; à vérifier sinon.")
    return Finding(name, OK, f"Origine autorisée : {origin}.", "Rien à faire sur ce point.")


SESSION_HINT = re.compile(r"sess|auth|token|sid|jwt|login", re.I)


def check_cookies(r: Response) -> List[Finding]:
    cookies = r.get_all("Set-Cookie")
    if not cookies:
        return [Finding("Cookies", NON_EVALUE, "Aucun cookie posé sur la page d'accueil.",
                        "Vérifier les attributs sur les parcours de connexion, hors de portée "
                        "d'un audit passif de la page d'accueil.")]
    findings = []
    https = urlsplit(r.url).scheme == "https"
    for raw in cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower(): (a.split("=", 1)[1].strip() if "=" in a else "")
                 for a in raw.split(";")[1:]}
        missing = []
        if https and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs and SESSION_HINT.search(name):
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        elif attrs["samesite"].lower() == "none" and "secure" not in attrs:
            missing.append("Secure (obligatoire avec SameSite=None)")
        label = f"Cookie « {name} »"
        if not missing:
            findings.append(Finding(label, OK, "Secure, SameSite et HttpOnly cohérents.",
                                    "Rien à faire sur ce point."))
        else:
            status = PRIORITAIRE if SESSION_HINT.search(name) and "HttpOnly" in missing else A_VERIFIER
            findings.append(Finding(label, status, "Attribut(s) manquant(s) : " + ", ".join(missing) + ".",
                                    "Ajouter les attributs, en priorité sur les cookies de session.",
                                    "https://developer.mozilla.org/fr/docs/Web/HTTP/Cookies"))
    return findings


def out_of_scope() -> Finding:
    return Finding("Injection SQL, XSS, contrôle d'accès", NON_EVALUE,
                   "Une réponse HTTP ne permet pas de les évaluer.",
                   "Revue de code (requêtes paramétrées, encodage des sorties) ou test "
                   "dans un environnement autorisé.",
                   "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html")


CHECKS = (check_https, check_http_redirect, check_hsts, check_csp, check_clickjacking,
          check_nosniff, check_referrer, check_cors, check_disclosure)


def audit(r: Response) -> List[Finding]:
    findings = [c(r) for c in CHECKS] + check_cookies(r) + [out_of_scope()]
    return sorted(findings, key=lambda f: ORDER[f.status])


# --------------------------------------------------------------------------
# Collecte (une requête GET, redirections suivies à la main)
# --------------------------------------------------------------------------

def _request(url: str) -> Tuple[int, Headers]:
    parts = urlsplit(url)
    conn_cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    kwargs = {"timeout": TIMEOUT_S}
    if parts.scheme == "https":
        kwargs["context"] = ssl.create_default_context()
    conn = conn_cls(parts.netloc, **kwargs)
    try:
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
        resp = conn.getresponse()
        resp.read(65536)  # on ne garde pas le corps
        return resp.status, list(resp.getheaders())
    finally:
        conn.close()


def fetch(url: str) -> Response:
    redirects = []
    for _ in range(MAX_REDIRECTS + 1):
        status, headers = _request(url)
        location = next((v for k, v in headers if k.lower() == "location"), None)
        if status in (301, 302, 303, 307, 308) and location:
            redirects.append(url)
            url = urljoin(url, location)
            continue
        return Response(url=url, status=status, headers=headers, redirects=redirects)
    raise RuntimeError(f"Plus de {MAX_REDIRECTS} redirections.")


def probe_http_redirect(host: str) -> Optional[bool]:
    try:
        status, headers = _request(f"http://{host}/")
    except (OSError, http.client.HTTPException):
        return None
    location = next((v for k, v in headers if k.lower() == "location"), "")
    return status in (301, 302, 303, 307, 308) and location.lower().startswith("https://")


def parse_raw(text: str, url: str = "https://exemple.invalid/") -> Response:
    """Lit une réponse brute (sortie de `curl -sS -D - -o /dev/null URL`)."""
    blocks = [b for b in re.split(r"\r?\n\r?\n", text.strip()) if b.strip()]
    block = blocks[-1].splitlines()  # dernière réponse si curl a suivi des redirections
    status = 200
    if block and block[0].upper().startswith("HTTP/"):
        status = int(block[0].split()[1])
        block = block[1:]
    headers = []
    for line in block:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return Response(url=url, status=status, headers=headers)


def normalize_target(target: str) -> str:
    target = target.strip()
    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target
    parts = urlsplit(target)
    if not parts.hostname:
        raise ValueError(f"Domaine invalide : {target}")
    return f"{parts.scheme}://{parts.netloc}/"


# --------------------------------------------------------------------------
# Rapports
# --------------------------------------------------------------------------

COLORS = {PRIORITAIRE: "\033[31m", A_VERIFIER: "\033[33m", OK: "\033[32m", NON_EVALUE: "\033[90m"}


def summary(findings: Iterable[Finding]) -> dict:
    counts = {s: 0 for s in ORDER}
    for f in findings:
        counts[f.status] += 1
    return counts


def render_text(r: Response, findings: List[Finding], color: bool) -> str:
    c = (lambda s, t: f"{COLORS[s]}{t}\033[0m") if color else (lambda s, t: t)
    lines = [f"Surface {__version__} — {r.url} (HTTP {r.status})"]
    if r.redirects:
        lines.append("Redirections : " + " → ".join(r.redirects + [r.url]))
    lines.append("")
    for f in findings:
        lines.append(f"{c(f.status, f'[{f.status}]'):<24} {f.check}")
        lines.append(f"    observé  : {f.observed}")
        lines.append(f"    ensuite  : {f.next_step}")
    s = summary(findings)
    lines += ["", " · ".join(f"{v} {k.lower()}" for k, v in s.items()),
              "Un en-tête absent ne prouve pas qu'un site est exploitable ; "
              "sa présence ne garantit pas sa sécurité."]
    return "\n".join(lines)


def render_markdown(r: Response, findings: List[Finding]) -> str:
    esc = lambda t: t.replace("|", "\\|")
    out = [f"# Rapport Surface — {r.url}", "",
           f"Réponse HTTP {r.status}. " + " · ".join(f"**{v}** {k.lower()}" for k, v in summary(findings).items()),
           "", "| Statut | Contrôle | Observé | Prochaine étape |", "| --- | --- | --- | --- |"]
    for f in findings:
        step = esc(f.next_step) + (f" ([réf.]({f.ref}))" if f.ref else "")
        out.append(f"| {f.status} | {esc(f.check)} | {esc(f.observed)} | {step} |")
    out += ["", "_Audit passif : une requête GET sur la page d'accueil. "
                "Un en-tête absent ne prouve pas qu'un site est exploitable._"]
    return "\n".join(out)


def render_json(r: Response, findings: List[Finding]) -> str:
    return json.dumps({"url": r.url, "status": r.status, "redirects": r.redirects,
                       "summary": summary(findings), "findings": [asdict(f) for f in findings]},
                      ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="surface", description="Audit web passif d'une page d'accueil.")
    p.add_argument("target", nargs="?", help="domaine ou URL, ex. example.com")
    p.add_argument("--from-file", metavar="FICHIER", help="analyser une réponse brute enregistrée (hors ligne)")
    p.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    p.add_argument("--no-http", action="store_true", help="ne pas tester la redirection http:// → https://")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"surface {__version__}")
    args = p.parse_args(argv)

    if args.from_file:
        with open(args.from_file, encoding="utf-8") as fh:
            response = parse_raw(fh.read(), url=normalize_target(args.target) if args.target else
                                 "https://exemple.invalid/")
    elif args.target:
        url = normalize_target(args.target)
        try:
            response = fetch(url)
        except (OSError, http.client.HTTPException, RuntimeError) as exc:
            print(f"surface : impossible de joindre {url} — {exc}", file=sys.stderr)
            return 2
        if not args.no_http:
            response.http_redirects_to_https = probe_http_redirect(urlsplit(url).netloc)
    else:
        p.error("indiquer un domaine ou --from-file")

    findings = audit(response)
    if args.format == "markdown":
        print(render_markdown(response, findings))
    elif args.format == "json":
        print(render_json(response, findings))
    else:
        print(render_text(response, findings, color=sys.stdout.isatty() and not args.no_color))
    return 1 if any(f.status == PRIORITAIRE for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
