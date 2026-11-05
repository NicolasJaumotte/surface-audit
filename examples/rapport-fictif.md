# Rapport Surface — https://exemple.invalid/

Réponse HTTP 200. **1** prioritaire · **5** à vérifier · **4** ok · **2** non évalué

| Statut | Contrôle | Observé | Prochaine étape |
| --- | --- | --- | --- |
| PRIORITAIRE | Cookie « PHPSESSID » | Attribut(s) manquant(s) : HttpOnly, SameSite. | Ajouter les attributs, en priorité sur les cookies de session. ([réf.](https://developer.mozilla.org/fr/docs/Web/HTTP/Cookies)) |
| À VÉRIFIER | HSTS | max-age=86400 s, soit moins de six mois. | Augmenter progressivement max-age (au moins 15552000). ([réf.](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)) |
| À VÉRIFIER | Politique de contenu (CSP) | CSP présente mais permissive : 'unsafe-inline' sans nonce ni hash. | Remplacer les scripts inline par des nonces ou des hash. ([réf.](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)) |
| À VÉRIFIER | Protection contre le clickjacking | Ni frame-ancestors ni X-Frame-Options valide. | Ajouter Content-Security-Policy: frame-ancestors 'self' si le site n'a pas à être intégré ailleurs. ([réf.](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)) |
| À VÉRIFIER | Referrer-Policy | En-tête absent : le navigateur applique sa valeur par défaut. | Fixer Referrer-Policy: strict-origin-when-cross-origin. ([réf.](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)) |
| À VÉRIFIER | Informations sur la pile technique | Versions exposées — Server: nginx/1.18.0 ; X-Powered-By: PHP/7.4.3. | Masquer les numéros de version et vérifier que ces composants sont à jour. Les cacher ne remplace pas les mises à jour. ([réf.](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)) |
| OK | HTTPS | Page servie en HTTPS (https://exemple.invalid/). | Rien à faire sur ce point. |
| OK | X-Content-Type-Options | nosniff présent. | Rien à faire sur ce point. |
| OK | CORS | Pas d'en-tête CORS sur la page d'accueil. | Les API se contrôlent séparément, endpoint par endpoint. |
| OK | Cookie « theme » | Secure, SameSite et HttpOnly cohérents. | Rien à faire sur ce point. |
| NON ÉVALUÉ | Redirection HTTP → HTTPS | Non testé (mode hors ligne ou option --no-http). | Relancer l'audit en ligne sans --no-http. |
| NON ÉVALUÉ | Injection SQL, XSS, contrôle d'accès | Une réponse HTTP ne permet pas de les évaluer. | Revue de code (requêtes paramétrées, encodage des sorties) ou test dans un environnement autorisé. ([réf.](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)) |

_Audit passif : une requête GET sur la page d'accueil. Un en-tête absent ne prouve pas qu'un site est exploitable._
