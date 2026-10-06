# Corpus et scans CodeQL

Les benchmarks ne sont pas copiés dans ce dépôt. Cette section contiendra les scripts de récupération, les commits figés, les versions CodeQL et les commandes de scan.

## Corpus prévus

- OWASP BenchmarkJava
- OWASP BenchmarkPython

## Règles de reproductibilité

- conserver le commit exact de chaque corpus ;
- conserver la version de CodeQL et la suite de requêtes ;
- enregistrer les sorties SARIF dans `data/raw/` ;
- documenter les exclusions et la graine d'échantillonnage ;
- ne jamais transmettre les labels au qualificateur.

Les commandes d'installation seront ajoutées après vérification de l'environnement local.
