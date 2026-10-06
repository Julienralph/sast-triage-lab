# SAST Triage Lab

Prototype expérimental de qualification d'alertes CodeQL sur Java et Python.
Le projet compare un appel simple à un modèle LLM avec un agent utilisant le
même modèle et deux outils de lecture contrôlée du dépôt.

## Question de recherche

L'exploration de code par un agent permet-elle de mieux qualifier les alertes
CodeQL qu'un appel simple, sans rejeter davantage de vraies vulnérabilités et
à un coût acceptable ?

## Pipeline

```text
Corpus OWASP Java/Python
	-> CodeQL
	-> SARIF
	-> manifeste commun d'alertes
	-> qualification simple ou agent explorateur
	-> résultats JSON
	-> évaluation contre les labels de référence
```

## Arborescence

- `src/core` : modèles, configuration et orchestration
- `src/sarif` : import et normalisation des résultats CodeQL
- `src/qualification` : appel simple, outils de lecture et agent
- `src/evaluation` : labels, métriques et matrices
- `src/safety` : accès en lecture seule et confinement des chemins
- `corpora` : scripts et métadonnées des corpus, sans copier les benchmarks
- `data/raw` : sorties SARIF et labels locaux non publiés
- `data/processed` : manifestes et résultats normalisés
- `configs` : prompts et paramètres versionnés
- `tests` : tests du pipeline et des garde-fous

## Périmètre du MVP

- CodeQL comme unique scanner
- Java et Python
- un seul modèle LLM
- deux méthodes de qualification
- verdicts `true_positive`, `false_positive`, `uncertain`
- erreurs techniques conservées séparément
- évaluation reproductible sur des alertes labellisées

Le projet ne cherche pas à entraîner un modèle, corriger automatiquement le
code, scanner des systèmes tiers ou construire une plateforme multiagents.

## Démarrage rapide

```bash
cd vulndetect
python -m venv .venv
source .venv/bin/activate  # ou .venv\Scripts\activate sur Windows
pip install -r requirements.txt
```

Les commandes CodeQL et la sélection des corpus seront documentées dans
`corpora/README.md`. Les clés API ne doivent jamais être ajoutées au dépôt.

## Étapes de travail

1. Installer et figer CodeQL ainsi que les corpus.
2. Importer et normaliser les sorties SARIF.
3. Faire passer cinq alertes Java et cinq alertes Python dans la chaîne.
4. Ajouter les deux méthodes de qualification et leurs garde-fous.
5. Lancer l'évaluation finale et produire le rapport.
