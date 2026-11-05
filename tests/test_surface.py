"""Tests hors ligne : aucun appel réseau."""
import contextlib
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import surface as s  # noqa: E402

HERE = os.path.dirname(__file__)


def resp(headers, url="https://exemple.invalid/", http_redirect=None):
    return s.Response(url=url, status=200, headers=headers, http_redirects_to_https=http_redirect)


def by_check(findings, name):
    return next(f for f in findings if f.check == name)


GOOD = [
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; script-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Server", "nginx"),
    ("Set-Cookie", "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"),
]


class BonneConfiguration(unittest.TestCase):
    def test_aucune_alerte_prioritaire(self):
        findings = s.audit(resp(GOOD, http_redirect=True))
        self.assertFalse([f for f in findings if f.status == s.PRIORITAIRE])
        self.assertFalse([f for f in findings if f.status == s.A_VERIFIER])

    def test_hors_perimetre_toujours_signale(self):
        f = by_check(s.audit(resp(GOOD)), "Injection SQL, XSS, contrôle d'accès")
        self.assertEqual(f.status, s.NON_EVALUE)


class Transport(unittest.TestCase):
    def test_http_seul_est_prioritaire(self):
        self.assertEqual(s.check_https(resp([], url="http://exemple.invalid/")).status, s.PRIORITAIRE)

    def test_redirection_non_testee(self):
        self.assertEqual(s.check_http_redirect(resp([])).status, s.NON_EVALUE)

    def test_redirection_absente(self):
        self.assertEqual(s.check_http_redirect(resp([], http_redirect=False)).status, s.PRIORITAIRE)

    def test_hsts_trop_court(self):
        f = s.check_hsts(resp([("Strict-Transport-Security", "max-age=86400")]))
        self.assertEqual(f.status, s.A_VERIFIER)
        self.assertIn("86400", f.observed)


class PolitiqueDeContenu(unittest.TestCase):
    def test_csp_absente(self):
        self.assertEqual(s.check_csp(resp([])).status, s.A_VERIFIER)

    def test_unsafe_inline_signale(self):
        f = s.check_csp(resp([("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")]))
        self.assertEqual(f.status, s.A_VERIFIER)
        self.assertIn("unsafe-inline", f.observed)

    def test_unsafe_inline_avec_nonce_accepte(self):
        policy = "script-src 'self' 'unsafe-inline' 'nonce-r4nd0m'"
        self.assertEqual(s.check_csp(resp([("Content-Security-Policy", policy)])).status, s.OK)

    def test_report_only_ne_bloque_rien(self):
        f = s.check_csp(resp([("Content-Security-Policy-Report-Only", "default-src 'self'")]))
        self.assertEqual(f.status, s.A_VERIFIER)
        self.assertIn("Report-Only", f.observed)

    def test_clickjacking_par_x_frame_options(self):
        self.assertEqual(s.check_clickjacking(resp([("X-Frame-Options", "sameorigin")])).status, s.OK)


class Cookies(unittest.TestCase):
    def test_cookie_de_session_sans_httponly_prioritaire(self):
        [f] = s.check_cookies(resp([("Set-Cookie", "PHPSESSID=1; Secure; SameSite=Lax")]))
        self.assertEqual(f.status, s.PRIORITAIRE)
        self.assertIn("HttpOnly", f.observed)

    def test_cookie_de_preference_sans_httponly_tolere(self):
        [f] = s.check_cookies(resp([("Set-Cookie", "theme=dark; Secure; SameSite=Lax")]))
        self.assertEqual(f.status, s.OK)

    def test_samesite_none_exige_secure(self):
        [f] = s.check_cookies(resp([("Set-Cookie", "pref=1; SameSite=None")], url="http://x.invalid/"))
        self.assertIn("SameSite=None", f.observed)

    def test_plusieurs_cookies(self):
        found = s.check_cookies(resp([("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]))
        self.assertEqual(len(found), 2)


class AutresControles(unittest.TestCase):
    def test_version_serveur_exposee(self):
        f = s.check_disclosure(resp([("Server", "Apache/2.4.41"), ("X-Powered-By", "PHP/7.4")]))
        self.assertEqual(f.status, s.A_VERIFIER)
        self.assertIn("Apache/2.4.41", f.observed)

    def test_cors_joker_avec_identifiants(self):
        h = [("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")]
        self.assertEqual(s.check_cors(resp(h)).status, s.PRIORITAIRE)


class Lecture(unittest.TestCase):
    def test_exemple_fictif(self):
        with open(os.path.join(HERE, "..", "examples", "reponse-fictive.txt"), encoding="utf-8") as fh:
            r = s.parse_raw(fh.read())
        self.assertEqual(r.status, 200)
        self.assertEqual(len(r.get_all("set-cookie")), 2)
        statuses = {f.check: f.status for f in s.audit(r)}
        self.assertEqual(statuses["Cookie « PHPSESSID »"], s.PRIORITAIRE)
        self.assertEqual(statuses["HSTS"], s.A_VERIFIER)
        self.assertEqual(statuses["X-Content-Type-Options"], s.OK)

    def test_derniere_reponse_apres_redirection(self):
        raw = "HTTP/1.1 301 Moved\nLocation: https://x/\n\nHTTP/2 200\nserver: caddy\n"
        r = s.parse_raw(raw)
        self.assertEqual((r.status, r.get("Server")), (200, "caddy"))

    def test_normalisation_du_domaine(self):
        self.assertEqual(s.normalize_target("Example.com/page"), "https://Example.com/")
        with self.assertRaises(ValueError):
            s.normalize_target("https://")

    def test_cli_code_retour(self):
        path = os.path.join(HERE, "..", "examples", "reponse-fictive.txt")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = s.main(["--from-file", path, "--format", "json"])
        self.assertEqual(code, 1)
        self.assertIn('"PRIORITAIRE": 1', out.getvalue())


if __name__ == "__main__":
    unittest.main()
