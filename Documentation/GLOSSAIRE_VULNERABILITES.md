# Glossaire des catégories de vulnérabilités

> Référence rapide pour les 15 catégories OWASP Benchmark utilisées dans le projet (Java et Python).
> Dernière mise à jour : 2026-10-03

Chaque catégorie correspond à une entrée officielle du [CWE (MITRE)](https://cwe.mitre.org/), le dictionnaire des types de vulnérabilités. OWASP Benchmark n'est pas ce dictionnaire : c'est une application volontairement truffée de failles, construite pour tester des scanners comme CodeQL sur ces catégories précises.

## Les quatre plus citées en entretien

| Catégorie | Nom complet | CWE | Le problème, en une phrase | Exemple concret |
|---|---|---|---|---|
| `pathtraver` | Path traversal | [22](https://cwe.mitre.org/data/definitions/22.html) | L'appli ouvre un fichier dont le nom vient de l'utilisateur, sans vérifier | Tu demandes `fichier.jpg`, l'attaquant demande `../../etc/passwd` |
| `sqli` | SQL injection | [89](https://cwe.mitre.org/data/definitions/89.html) | Une requête base de données est construite en collant du texte utilisateur tel quel | `' OR '1'='1` dans un champ login pour contourner le mot de passe |
| `xss` | Cross-site scripting | [79](https://cwe.mitre.org/data/definitions/79.html) | Le site réaffiche du texte utilisateur dans la page sans le nettoyer | Un commentaire `<script>vole_tes_cookies()</script>` exécuté chez les autres visiteurs |
| `cmdi` | Command injection | [78](https://cwe.mitre.org/data/definitions/78.html) | L'appli lance une commande système en y collant une entrée utilisateur | Un champ "nom de fichier" devient `; rm -rf /` |

## Injections du même principe, sur d'autres cibles

| Catégorie | Nom complet | CWE | Le problème, en une phrase | Exemple concret |
|---|---|---|---|---|
| `ldapi` | LDAP injection | [90](https://cwe.mitre.org/data/definitions/90.html) | Même principe que SQLi, sur un annuaire LDAP (authentification d'entreprise) | Contourner un login en injectant une syntaxe LDAP spéciale |
| `xpathi` | XPath injection | [643](https://cwe.mitre.org/data/definitions/643.html) | Même principe, sur une requête XPath (recherche dans un document XML) | Extraire tout le contenu d'un fichier XML au lieu d'un seul élément |
| `codeinj` | Code injection | [94](https://cwe.mitre.org/data/definitions/94.html) | L'appli exécute littéralement du code (souvent via `eval`) construit avec une entrée utilisateur | Faire exécuter n'importe quelle instruction Python/Java au serveur |
| `xxe` | XML External Entity | [611](https://cwe.mitre.org/data/definitions/611.html) | Un parseur XML va chercher un fichier ou une ressource externe glissée dans le XML | Le XML référence une ressource qui fait lire `/etc/passwd` au serveur |

## Données et objets mal gérés

| Catégorie | Nom complet | CWE | Le problème, en une phrase | Exemple concret |
|---|---|---|---|---|
| `deserialization` | Désérialisation non sûre | [502](https://cwe.mitre.org/data/definitions/502.html) | L'appli reconstruit un objet à partir de données venant de l'utilisateur, sans vérifier | Un objet piégé exécute du code dès qu'il est désérialisé |
| `redirect` | Open redirect | [601](https://cwe.mitre.org/data/definitions/601.html) | Le site redirige vers une URL fournie par l'utilisateur, sans contrôle | Un lien qui a l'air du vrai site redirige vers un site de phishing |
| `trustbound` | Violation de frontière de confiance | [501](https://cwe.mitre.org/data/definitions/501.html) | Une donnée utilisateur et une donnée interne de confiance sont mélangées dans la même structure, sans séparation claire | Plus subtil : mauvaise pratique de conception, pas un exploit unique |

## Cryptographie et secrets

| Catégorie | Nom complet | CWE | Le problème, en une phrase | Exemple concret |
|---|---|---|---|---|
| `crypto` | Algorithme de chiffrement faible | [327](https://cwe.mitre.org/data/definitions/327.html) | L'appli chiffre avec un algorithme cassé ou obsolète (ex : DES) | Les données "chiffrées" se décodent facilement |
| `hash` | Hash faible | [328](https://cwe.mitre.org/data/definitions/328.html) | Pareil, pour le hachage (ex : mots de passe en MD5) | Le mot de passe en clair se retrouve à partir du hash |
| `weakrand` | Génération aléatoire prévisible | [330](https://cwe.mitre.org/data/definitions/330.html) | Générateur de nombres "aléatoires" pas vraiment aléatoire, utilisé pour un token ou un mot de passe | L'attaquant devine le prochain token de session |
| `securecookie` | Cookie non sécurisé | [614](https://cwe.mitre.org/data/definitions/614.html) | Un cookie sensible (session) est envoyé sans l'attribut `Secure`, donc transmis même en HTTP non chiffré | Le cookie de session est intercepté sur un wifi public |

## Pour aller plus loin

- [cwe.mitre.org](https://cwe.mitre.org/) : fiche officielle par CWE (description, exemple de code vulnérable, moyens d'atténuation).
- [OWASP Top 10](https://owasp.org/Top10/) et [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) : contexte pratique et correctifs.
- [owasp.org/www-project-benchmark](https://owasp.org/www-project-benchmark/) : page du projet OWASP Benchmark utilisé comme corpus (`corpora/BenchmarkJava`, `corpora/BenchmarkPython`).
- La table de correspondance règle CodeQL ↔ catégorie du projet est dans [`src/sast_triage_lab/benchmark/owasp_rules.py`](../src/sast_triage_lab/benchmark/owasp_rules.py), avec la justification de chaque choix.
