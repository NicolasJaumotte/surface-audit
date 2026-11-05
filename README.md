# Surface

**Un domaine. Des observations. Des actions à prioriser.**

Surface est un outil d’audit web passif. Il prend un domaine et organise les signaux visibles de sa page d’accueil en trois catégories : **observé**, **à vérifier** et **non évalué**. Le rapport explique la raison de chaque signal et indique quoi vérifier ensuite.

## Exemple fictif

| Contrôle | Résultat | Prochaine étape |
| --- | --- | --- |
| HTTPS | Observé | Confirmer que l’accès HTTP redirige vers HTTPS. |
| Politique de contenu (CSP) | À vérifier | Tester une politique adaptée aux scripts du site. |
| Cookies de session | Non évalué | Vérifier les attributs sur les parcours de connexion. |
| Injection SQL | Hors du contrôle HTTP | Vérifier dans le code que les requêtes utilisent des paramètres. |

Un en-tête absent ne prouve pas qu’un site est exploitable. Inversement, la présence des en-têtes ne garantit pas sa sécurité.

## Reproduire une observation avec curl

```sh
curl -sS -D - -o /dev/null https://example.com/
```

La commande effectue une requête HTTP ordinaire et affiche les en-têtes de la réponse. Elle ne teste pas d’injection SQL.

Le prototype est disponible en accès privé. Ce dépôt présente le projet et son périmètre.

[OWASP : en-têtes de sécurité HTTP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) · [OWASP : prévention des injections SQL](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
