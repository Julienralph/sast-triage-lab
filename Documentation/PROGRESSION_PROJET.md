# SAST Triage Lab - Progression du projet

> Document de synchronisation entre le dépôt local, Notion et les séances de travail.
>
> Dernière mise à jour : 2026-09-24

## 1. Résumé exécutif

### Projet en une phrase

SAST Triage Lab est un prototype qui prend des alertes CodeQL issues de code Java et Python, consulte le code pertinent et qualifie chaque alerte en `true_positive`, `false_positive` ou `uncertain`.

Le projet compare deux méthodes utilisant le même modèle d'IA :

1. un appel simple au modèle ;
2. un agent capable d'explorer le code avec deux outils contrôlés :
   - lire un extrait de fichier ;
   - rechercher une référence dans le dépôt.

### Question de recherche

> L'exploration du code par un agent permet-elle de mieux qualifier les alertes CodeQL qu'un appel simple au même modèle, sans écarter davantage de vraies vulnérabilités et à un coût acceptable ?

### Objectif professionnel

Produire un projet personnel reproductible à présenter sur le CV, GitHub et en entretien pour démontrer des compétences en cybersécurité applicative, SAST, CodeQL, Python, agents LLM et évaluation expérimentale.

## 2. Périmètre validé

### Inclus

- CodeQL comme scanner unique ;
- Java et Python ;
- OWASP BenchmarkJava ;
- OWASP BenchmarkPython ;
- export SARIF ;
- un seul modèle d'IA ;
- deux méthodes de qualification ;
- un orchestrateur Python installable en CLI ;
- résultats structurés et reproductibles ;
- comparaison avec les labels OWASP ;
- mesure des erreurs, de l'incertitude, de la durée et du coût.

### Exclus

- entraînement d'un modèle ;
- création d'un scanner de vulnérabilités ;
- deuxième scanner ;
- troisième langage ;
- correction automatique du code ;
- interface web complexe ;
- plateforme multiagents ;
- scan de systèmes tiers ;
- terminal libre pour l'agent ;
- accès Internet pour l'agent ;
- accès aux labels pendant l'analyse ;
- accès à l'historique Git pour l'agent ;
- accès en écriture au dépôt analysé.

## 3. Architecture retenue

```text
BenchmarkJava / BenchmarkPython
            |
            v
          CodeQL
            |
            v
       Fichier SARIF
            |
            v
Import et normalisation des alertes
            |
            +----------------------+
            |                      |
            v                      v
     Appel simple          Agent explorateur
            |                      |
            +----------+-----------+
                       |
                       v
             Résultats JSON
                       |
                       v
       Comparaison avec les labels OWASP
                       |
                       v
       Métriques et rapport expérimental
```

### Séparation des composants

```text
vulndetect/
├── pyproject.toml
├── src/
│   └── sast_triage_lab/
│       ├── core/        # modèles et contrats génériques
│       ├── benchmark/   # labels et métriques OWASP
│       ├── sarif/       # import CodeQL/SARIF
│       ├── safety/      # accès en lecture seule
│       └── cli.py       # entrée de commande
├── corpora/
│   ├── BenchmarkJava/
│   ├── BenchmarkPython/
│   └── README.md
├── data/
│   ├── raw/
│   └── processed/
├── configs/
├── tests/
└── Documentation/
```

### Règle d'architecture

`core/` doit rester générique et ne doit pas importer de logique spécifique à OWASP.

`benchmark/` contient les labels, le chargement des résultats attendus et les métriques dépendantes des benchmarks.

## 4. Travaux réalisés

### 4.1 Environnement Python

Un environnement virtuel `.venv` a été créé dans le projet.

Commande :

```powershell
python -m venv .venv
```

Rôle :

- créer un environnement Python isolé ;
- éviter les conflits de dépendances avec d'autres projets ;
- rendre l'installation reproductible.

Activation PowerShell :

```powershell
.\.venv\Scripts\Activate.ps1
```

Le préfixe `(.venv)` confirme que l'environnement est actif.

Une restriction PowerShell a été rencontrée :

```text
l'exécution de scripts est désactivée sur ce système
```

Correction utilisée :

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Cette commande autorise les scripts locaux pour l'utilisateur courant.

### 4.2 Packaging Python

Le projet possède un fichier `pyproject.toml` avec :

- le nom du paquet `sast-triage-lab` ;
- Python `>=3.11` ;
- les dépendances ;
- l'option de développement ;
- l'entrypoint CLI `sast-triage` ;
- la configuration de pytest.

Installation en mode développement :

```powershell
pip install -e ".[dev]"
```

Signification :

- `.` : projet situé dans le dossier courant ;
- `-e` : installation editable, les modifications du code sont utilisées directement ;
- `[dev]` : installation des dépendances de développement, notamment pytest.

### 4.3 Tests et correction du sandbox

Commande :

```powershell
pytest -q
```

Un test échouait initialement avec :

```text
FileNotFoundError: target.py
```

Le test demandait de rejeter une lecture des lignes 1 à 201, mais la condition était :

```python
end_line - start_line > 200
```

Or :

```text
201 - 1 = 200
```

La condition était donc fausse. Elle a été corrigée en :

```python
if start_line < 1 or end_line < start_line or end_line - start_line >= 200:
    raise ValueError("Invalid or oversized line range")
```

Validation finale :

```text
5 passed in 0.04s
```

Les tests couvrent notamment :

- lecture normale d'un fichier ;
- blocage d'un chemin hors du dépôt ;
- blocage d'une lecture trop volumineuse ;
- conservation des erreurs techniques ;
- parsing d'une alerte SARIF de test.

### 4.4 Installation et validation de CodeQL

Le bundle Windows a été téléchargé et placé dans :

```text
.\codeql-bundle-win64\codeql\
```

Commande exécutée :

```powershell
.\codeql-bundle-win64\codeql\codeql.exe resolve languages
```

Résultat important :

```text
java (...\codeql\java)
python (...\codeql\python)
```

Interprétation :

- l'exécutable CodeQL fonctionne ;
- le langage Java est disponible ;
- le langage Python est disponible ;
- la condition technique minimale pour les deux corpus est remplie.

### 4.5 Récupération des benchmarks

Les deux dépôts sont présents dans `corpora/` :

```text
corpora/BenchmarkJava/
corpora/BenchmarkPython/
```

Commande de clonage utilisée ou prévue :

```powershell
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git
git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git
```

### 4.6 Versions Git figées

BenchmarkJava :

```text
20cbf3d11123347e47ed89541e6942836def53f7
```

BenchmarkPython :

```text
f1291485808b66e20ddb6b01b10dc71b3df8c8ba
```

Commandes utilisées :

```powershell
git -C .\BenchmarkJava rev-parse HEAD
git -C .\BenchmarkPython rev-parse HEAD
```

Rôle :

- obtenir l'identifiant exact du code analysé ;
- pouvoir retrouver les mêmes versions plus tard ;
- assurer la reproductibilité de l'expérience.

Vérification de l'état local :

```powershell
git -C .\BenchmarkJava status --short
git -C .\BenchmarkPython status --short
```

Résultat : aucune ligne affichée.

Interprétation :

- les deux dépôts sont propres ;
- aucune modification locale n'a été détectée.

### 4.7 Comptage des fichiers candidats

BenchmarkPython :

```powershell
Get-ChildItem .\BenchmarkPython -Recurse -File |
    Where-Object { $_.Name -like "*BenchmarkTest*" } |
    Measure-Object
```

Résultat :

```text
Count : 2460
```

BenchmarkJava :

```powershell
Get-ChildItem .\BenchmarkJava -Recurse -File |
    Where-Object { $_.Name -like "*BenchmarkTest*" } |
    Measure-Object
```

Résultat :

```text
Count : 5480
```

Interprétation :

- Java contient 5480 fichiers correspondant au motif ;
- Python contient 2460 fichiers correspondant au motif ;
- ces nombres sont des fichiers candidats, pas des alertes CodeQL ;
- ils ne correspondent pas forcément au nombre de cas labellisés.

Règle à retenir :

```text
fichiers physiques != cas labellisés != alertes CodeQL
```

### 4.8 Localisation des labels

BenchmarkJava :

```text
BenchmarkJava/expectedresults-1.2.csv
```

BenchmarkPython :

```text
BenchmarkPython/expectedresults-0.1.csv
```

Commande utilisée :

```powershell
Get-ChildItem .\BenchmarkJava -Recurse -File |
    Where-Object { $_.Name -match "expectedresults|results" } |
    Select-Object FullName
```

Même commande adaptée à Python :

```powershell
Get-ChildItem .\BenchmarkPython -Recurse -File |
    Where-Object { $_.Name -match "expectedresults|results" } |
    Select-Object FullName
```

Rôle :

- localiser les fichiers contenant la vérité terrain ;
- distinguer les labels du code analysé ;
- préparer la future évaluation.

Ces fichiers ne doivent jamais être transmis au modèle ou rendus accessibles à l'agent pendant la qualification.

## 5. Analyse des labels Python

### Lecture du CSV

Commande :

```powershell
$pythonLabels = Import-Csv `
    ".\BenchmarkPython\expectedresults-0.1.csv" `
    -Header test_name,category,real_vulnerability,cwe
```

Rôle :

- lire le fichier CSV ;
- transformer chaque ligne en objet PowerShell ;
- nommer les colonnes ;
- stocker le résultat dans `$pythonLabels`.

Le caractère `` ` `` permet de continuer une commande sur la ligne suivante.

### Structure du fichier Python

En-tête :

```text
# test name, category, real vulnerability, cwe, Benchmark version: 0.1, 2026-01-9
```

Exemples :

```text
BenchmarkTest00001,pathtraver,true,22
BenchmarkTest00004,pathtraver,false,22
```

Colonnes :

| Colonne | Rôle |
|---|---|
| `test_name` | identifiant du cas |
| `category` | famille de vulnérabilité |
| `real_vulnerability` | `true` ou `false` |
| `cwe` | identifiant CWE |

### Répartition Python

Commande :

```powershell
$pythonLabels |
    Group-Object real_vulnerability |
    Select-Object Name,Count
```

Résultat :

```text
true  : 452
false : 778
```

Total : 1230 cas labellisés.

Pourcentages approximatifs :

- vraies vulnérabilités : 36,7 % ;
- cas non vulnérables : 63,3 %.

Rôle de l'analyse :

- mesurer la présence de vraies vulnérabilités ;
- mesurer la présence de cas pouvant produire des fausses alertes ;
- éviter un échantillon composé d'une seule classe.

### Catégories Python

Commande :

```powershell
$pythonLabels |
    Group-Object category |
    Sort-Object Count -Descending |
    Select-Object Name,Count
```

Résultat :

```text
weakrand          326
xpathi            186
pathtraver        168
hash              151
xss                89
deserialization    54
codeinj            53
securecookie       39
trustbound         37
redirect           34
ldapi              29
xxe                28
cmdi               20
sqli               16
```

## 6. Analyse des labels Java

### Lecture du CSV

Commande :

```powershell
$javaLabels = Import-Csv `
    ".\BenchmarkJava\expectedresults-1.2.csv" `
    -Header test_name,category,real_vulnerability,cwe
```

En-tête Java :

```text
# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1
```

Exemples :

```text
BenchmarkTest00001,pathtraver,true,22
BenchmarkTest00003,hash,true,328
BenchmarkTest00004,trustbound,true,501
```

### Répartition Java

Commande :

```powershell
$javaLabels |
    Group-Object real_vulnerability |
    Select-Object Name,Count
```

Résultat :

```text
true  : 1415
false : 1325
```

Total : 2740 cas labellisés.

### Catégories Java

Commande :

```powershell
$javaLabels |
    Group-Object category |
    Sort-Object Count -Descending |
    Select-Object Name,Count
```

Résultat :

```text
sqli           504
weakrand       493
xss             455
pathtraver      268
cmdi            251
crypto          246
hash            236
trustbound      126
securecookie     67
ldapi            59
xpathi           35
```

## 7. Décisions expérimentales actuelles

### Catégories communes identifiées

- `pathtraver` ;
- `xss` ;
- `weakrand` ;
- `hash` ;
- `trustbound` ;
- `securecookie` ;
- `ldapi` ;
- `xpathi` ;
- `cmdi`.

### Choix provisoire

1. `pathtraver`, CWE-22
2. `xss`, CWE-79

Volumes labellisés :

| Catégorie | Java | Python |
|---|---:|---:|
| `pathtraver` | 268 | 168 |
| `xss` | 455 | 89 |

Justification :

- les deux catégories existent dans les deux langages ;
- elles sont suffisamment représentées ;
- elles sont compréhensibles en entretien ;
- elles permettent d'étudier le contexte du code et les flux de données.

Cette décision reste provisoire jusqu'à la production des résultats CodeQL.

## 8. Ce qui reste à faire

### Pas encore réalisé

- vérifier les fichiers de build Java et Python ;
- créer les bases CodeQL ;
- lancer CodeQL sur Java ;
- lancer CodeQL sur Python ;
- exporter les SARIF réels ;
- compter les alertes CodeQL par catégorie ;
- relier les alertes aux cas OWASP ;
- créer le lot de développement ;
- atteindre le jalon de 5 alertes Java et 5 alertes Python ;
- implémenter l'appel réel au modèle ;
- implémenter la validation JSON ;
- implémenter l'agent explorateur ;
- tester les plafonds d'appels et de durée ;
- lancer la comparaison des deux méthodes ;
- calculer les métriques finales ;
- rédiger le rapport ;
- préparer la démonstration et le CV.

## 9. Étape actuelle exacte

Nous sommes à la fin de la phase de référence des corpus du Jour 1.

L'environnement et les données de référence sont identifiés, mais aucune alerte CodeQL réelle n'a encore été générée dans le projet.

La prochaine étape est l'inspection des fichiers de build avant le premier scan.

Commandes à exécuter depuis `vulndetect/corpora` :

```powershell
Get-ChildItem .\BenchmarkJava -Recurse -File -Include pom.xml,build.gradle,build.xml |
    Select-Object FullName
```

```powershell
Get-ChildItem .\BenchmarkPython -Recurse -File -Include requirements.txt,pyproject.toml,setup.py,setup.cfg |
    Select-Object FullName
```

Pourquoi :

- Java peut nécessiter une compilation pour que CodeQL construise sa base ;
- Python peut avoir des dépendances ou une structure particulière ;
- la commande de scan doit être adaptée au projet réel ;
- un échec de build doit être compris et documenté, pas masqué.

## 10. Commandes importantes et rôles

| Commande | Rôle |
|---|---|
| `python -m venv .venv` | créer un environnement Python isolé |
| `.\\.venv\\Scripts\\Activate.ps1` | activer l'environnement PowerShell |
| `Set-ExecutionPolicy ... RemoteSigned` | autoriser les scripts locaux pour l'utilisateur |
| `pip install -e ".[dev]"` | installer le projet et pytest en mode editable |
| `pytest -q` | exécuter les tests avec une sortie courte |
| `Get-ChildItem` | lister des fichiers et dossiers |
| `Where-Object` | filtrer les éléments PowerShell |
| `Measure-Object` | compter ou mesurer des éléments |
| `Import-Csv` | transformer un CSV en objets PowerShell |
| `Group-Object` | regrouper des données |
| `Sort-Object` | trier les résultats |
| `Select-Object` | sélectionner les propriétés affichées |
| `git rev-parse HEAD` | obtenir le commit courant |
| `git status --short` | détecter des modifications locales |
| `codeql resolve languages` | vérifier les langages CodeQL disponibles |

## 11. Compétences acquises

### Python

- environnement virtuel ;
- pip et dépendances ;
- package installable ;
- dataclasses ;
- JSON et CSV ;
- gestion des erreurs ;
- pathlib ;
- tests pytest ;
- garde-fous de lecture.

### PowerShell

- navigation ;
- variables ;
- pipelines ;
- filtrage ;
- regroupement ;
- tri ;
- comptage ;
- exécution de binaires.

### Git

- clone ;
- commit ;
- état du dépôt ;
- version reproductible ;
- traçabilité du corpus.

### Cybersécurité

- SAST ;
- différence entre SAST et DAST ;
- CodeQL ;
- SARIF ;
- CWE ;
- faux positifs ;
- vérité terrain ;
- benchmarks de sécurité.

### Méthodologie expérimentale

- question de recherche ;
- périmètre ;
- séparation développement/évaluation ;
- échantillonnage ;
- labels ;
- reproductibilité ;
- limites d'un benchmark ;
- distinction entre cas, fichiers et alertes.

## 12. Questions à savoir expliquer en entretien

- Pourquoi utiliser CodeQL comme scanner ?
- Quelle différence entre détection et qualification ?
- Pourquoi utiliser SARIF ?
- Pourquoi les labels OWASP ne doivent-ils pas être transmis à l'agent ?
- Pourquoi un benchmark n'est-il pas un ensemble direct d'alertes ?
- Pourquoi conserver les commits des corpus ?
- Quelle différence entre une vraie vulnérabilité et une alerte ?
- Pourquoi comparer Java et Python séparément ?
- Pourquoi choisir deux catégories communes ?
- Pourquoi un verdict `uncertain` est-il nécessaire ?
- Pourquoi une erreur technique ne doit-elle pas devenir `false_positive` ?
- Pourquoi ce projet ne mesure-t-il pas toutes les vulnérabilités manquées par CodeQL ?

## 13. Modèle de journal quotidien

```text
# Jour X - AAAA-MM-JJ

## Objectif

## Commandes exécutées

## Rôle des commandes

## Sorties obtenues

## Interprétation des données

## Ce que j'ai appris

## Difficultés rencontrées

## Décisions prises

## Compétences travaillées

## Questions à revoir

## Prochaine étape
```

## 14. Questionnaires de compréhension par grande étape

### Règle de travail pédagogique

À la fin de chaque grande étape, avant de commencer la suivante :

1. l'assistant pose un court questionnaire lié aux notions et décisions de l'étape ;
2. Julien répond avec ses propres mots, sans chercher une formulation parfaite ;
3. l'assistant corrige les éventuelles incompréhensions avec des explications et exemples ;
4. les questions, les réponses synthétisées et les notions à revoir sont consignées dans cette page et dans Notion ;
5. on ne passe à l'étape suivante qu'après clarification des points essentiels.

Le but est de vérifier la compréhension, pas de noter ou de piéger. Si une réponse révèle une lacune, on réexplique la notion puis on vérifie à nouveau avec une question reformulée.

### Questionnaire de rattrapage - étapes déjà réalisées

Répondre avec ses propres mots. Les réponses peuvent être ajoutées sous chaque question dans Notion.

#### A. Projet et évaluation

1. Quelle est la différence entre CodeQL qui détecte une alerte et notre système qui la qualifie ? Code QL détecte l'alerte et génère un fichier SARIF au format JSON qui sera ensuite ces données seront extraites via notre système qui se chargera de qualifier la menace en faux,vrai ou incertain.
2. À quoi sert le benchmark OWASP dans ce projet ? Est-ce un catalogue de toutes les vulnérabilités publiques ou un corpus de cas de test labellisés ?Le benchmark OWASP sert à labelliser les vulnérabilités de notre projet donc c'est un corpus de cas de test labbellisés
3. Que signifie un label `real_vulnerability=true` ? Que signifie `false` ? true signifie que la vulnérabilité est réelle donc soulève une vraie menace et false signifie que la vulnérabilité est n'est pas réelle donc pas de potentielles menaces
4. Pourquoi les labels ne doivent-ils pas être visibles par le modèle pendant la qualification ? pour que l'évaluation reste honnete 
5. Que fait-on si une alerte n'a aucun label correspondant ? ça veut dire qu'il y'a aucune vérité de référence connue pour cette vulnérabilité 

#### B. Environnement et compilation Java

6. À quoi sert `.venv`, et pourquoi Maven ou Java ne sont-ils pas installés dedans ? ça sert à activer un environnement virtuel,Maven et Java ne sont pas install
7. Quelle différence fais-tu entre Maven et Ant ? Quel fichier configure chacun ?
8. Que font les phases Maven `clean` et `compile` ? Pourquoi CodeQL doit-il observer un vrai lancement du compilateur ?
9. Pourquoi Maven doit-il être lancé depuis BenchmarkJava ou recevoir explicitement le chemin de son `pom.xml` ?
10. Pourquoi avons-nous évité les profils `findsecbugs`, `deploy` et `deploywcontrast` ?

#### C. CodeQL et SARIF

11. Quelle est la différence entre une base CodeQL et un fichier SARIF ?
12. Que signifie `source`, `step` et `sink` dans le `codeFlow` de l'alerte `java/path-injection` ?
13. Que nous apprend le résultat de 4 143 alertes au total et 4 138 dans des fichiers `BenchmarkTest...java` ?
14. Pourquoi les nombres d'alertes CodeQL ne sont-ils pas directement égaux aux nombres de labels OWASP ?
15. Quelles sont les trois étapes du pipeline complet, de l'analyse du code jusqu'à l'évaluation des verdicts ?

### Suivi des réponses

```text
Date du questionnaire :

Notions comprises et expliquées par Julien :
-

Notions à reprendre :
-

Explications ou exemples ajoutés :
-

Validation avant la prochaine étape : en attente / validée
```

### Gabarit à ajouter à chaque futur jalon

```text
## Questionnaire de compréhension - [nom de l'étape]

1. [Question sur l'objectif de l'étape]
    Ma réponse :

2. [Question sur les commandes ou le code utilisé]
    Ma réponse :

3. [Question sur l'interprétation des résultats]
    Ma réponse :

4. [Question sur une limite, un risque ou une décision]
    Ma réponse :

Notions comprises :
-

Notions à revoir :
-

Étape suivante autorisée : oui / pas encore
```
