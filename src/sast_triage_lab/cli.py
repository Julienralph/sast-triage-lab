from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import os
from collections import Counter
from pathlib import Path

from .benchmark.owasp_corpus import build_reference_labels, load_expected_results
from .core.dev_batch import select_dev_batch
from .core.models import CodeQLAlert
from .sarif.parser import load_sarif

_DEFAULTS: dict[str, dict[str, Path]] = {
    "java": {
        "sarif": Path("data/raw/benchmark-java.sarif"),
        "expected": Path("corpora/BenchmarkJava/expectedresults-1.2.csv"),
        "out": Path("data/processed/java-reference-labels.csv"),
        "corpus_root": Path("corpora/BenchmarkJava"),
    },
    "python": {
        "sarif": Path("data/raw/benchmark-python.sarif"),
        "expected": Path("corpora/BenchmarkPython/expectedresults-0.1.csv"),
        "out": Path("data/processed/python-reference-labels.csv"),
        "corpus_root": Path("corpora/BenchmarkPython"),
    },
}


def main() -> None:
    parser = argparse.ArgumentParser(description="SAST Triage Lab command line interface")
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    subparsers = parser.add_subparsers(dest="command")

    build_labels = subparsers.add_parser(
        "build-labels",
        help="Relie les alertes SARIF CodeQL aux labels OWASP Benchmark et écrit un CSV",
    )
    build_labels.add_argument("--language", choices=sorted(_DEFAULTS), required=True)
    build_labels.add_argument("--sarif", type=Path, default=None, help="Chemin du fichier SARIF (défaut : data/raw)")
    build_labels.add_argument("--expected", type=Path, default=None, help="Chemin du CSV expectedresults-* (défaut : corpora/)")
    build_labels.add_argument("--out", type=Path, default=None, help="Chemin du CSV de sortie (défaut : data/processed)")

    dev_batch = subparsers.add_parser(
        "dev-batch",
        help="Sélectionne un petit lot d'alertes Java + Python pour tester la chaîne",
    )
    dev_batch.add_argument(
        "--category", nargs="+", default=["pathtraver"],
        help="Une ou plusieurs catégories OWASP à échantillonner (défaut : pathtraver)",
    )
    dev_batch.add_argument("--true-count", type=int, default=3, help="Nombre de vraies failles par langage et par catégorie (défaut : 3)")
    dev_batch.add_argument("--false-count", type=int, default=2, help="Nombre de faux positifs par langage et par catégorie (défaut : 2)")
    dev_batch.add_argument("--out", type=Path, default=Path("data/processed/dev-batch.json"))
    dev_batch.add_argument(
        "--exclude-batch", type=Path, default=None,
        help="Lot existant dont les alertes ne doivent pas être réutilisées (ex : le lot de développement)",
    )

    qualify_simple = subparsers.add_parser(
        "qualify-simple",
        help="Lance la methode d'appel simple (un seul message, sans outils) sur un lot d'alertes",
    )
    qualify_simple.add_argument("--batch", type=Path, default=Path("data/processed/dev-batch.json"))
    qualify_simple.add_argument("--out", type=Path, default=Path("data/processed/simple-results.json"))
    qualify_simple.add_argument("--max-calls", type=int, default=20, help="Plafond dur du nombre d'appels (defaut : 20)")
    qualify_simple.add_argument("--max-duration", type=float, default=300.0, help="Plafond de duree en secondes (defaut : 300)")
    qualify_simple.add_argument(
        "--max-context-lines", type=int, default=190,
        help="Nombre de lignes lues depuis le debut du fichier (defaut : 190, sous le plafond de 200 du lecteur bride)",
    )

    qualify_agent = subparsers.add_parser(
        "qualify-agent",
        help="Lance la methode agent explorateur (outils read_file/search_references) sur un lot d'alertes",
    )
    qualify_agent.add_argument("--batch", type=Path, default=Path("data/processed/dev-batch.json"))
    qualify_agent.add_argument("--out", type=Path, default=Path("data/processed/agent-results.json"))
    qualify_agent.add_argument("--max-calls", type=int, default=40, help="Plafond dur du nombre d'appels sur tout le lot (defaut : 40)")
    qualify_agent.add_argument("--max-duration", type=float, default=600.0, help="Plafond de duree en secondes (defaut : 600)")
    qualify_agent.add_argument("--max-turns", type=int, default=5, help="Tours maximum par alerte avant de forcer 'uncertain' (defaut : 5)")
    qualify_agent.add_argument(
        "--initial-context-lines", type=int, default=40,
        help="Lignes de code donnees au depart, avant exploration (defaut : 40, volontairement plus court que l'appel simple)",
    )
    qualify_agent.add_argument(
        "--transcripts-dir", type=Path, default=Path("data/processed/transcripts"),
        help="Dossier ou sauvegarder la conversation complete de chaque alerte (defaut : data/processed/transcripts)",
    )

    evaluate = subparsers.add_parser(
        "evaluate",
        help="Compare des resultats de qualification aux labels OWASP (matrice de confusion)",
    )
    evaluate.add_argument("--results", type=Path, default=Path("data/processed/simple-results.json"))

    args = parser.parse_args()

    if args.command == "build-labels":
        _run_build_labels(args)
    elif args.command == "dev-batch":
        _run_dev_batch(args)
    elif args.command == "qualify-simple":
        _run_qualify_simple(args)
    elif args.command == "qualify-agent":
        _run_qualify_agent(args)
    elif args.command == "evaluate":
        _run_evaluate(args)
    else:
        parser.print_help()


def _run_build_labels(args: argparse.Namespace) -> None:
    defaults = _DEFAULTS[args.language]
    sarif_path = args.sarif or defaults["sarif"]
    expected_path = args.expected or defaults["expected"]
    out_path = args.out or defaults["out"]

    alerts = load_sarif(sarif_path, args.language)
    expected = load_expected_results(expected_path)
    labels = build_reference_labels(alerts, expected, args.language)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["alert_id", "expected_verdict", "category", "source"])
        for label in labels:
            writer.writerow([label.alert_id, label.expected_verdict, label.category, label.source])

    print(f"Alertes CodeQL totales ({args.language}) : {len(alerts)}")
    print(f"Alertes reliees a un label OWASP : {len(labels)}")
    counts = Counter((label.category, label.expected_verdict) for label in labels)
    for (category, verdict), count in sorted(counts.items()):
        print(f"  {category} / {verdict} : {count}")
    print(f"Fichier ecrit : {out_path}")


def _run_dev_batch(args: argparse.Namespace) -> None:
    exclude_alert_ids: frozenset[str] = frozenset()
    if args.exclude_batch is not None:
        excluded = json.loads(args.exclude_batch.read_text(encoding="utf-8"))
        exclude_alert_ids = frozenset(entry["alert_id"] for entry in excluded)
        print(f"Exclusion de {len(exclude_alert_ids)} alertes deja presentes dans {args.exclude_batch}")

    entries = []
    for language in sorted(_DEFAULTS):
        defaults = _DEFAULTS[language]
        alerts = load_sarif(defaults["sarif"], language)
        expected = load_expected_results(defaults["expected"])
        labels = build_reference_labels(alerts, expected, language)
        labels_by_alert_id = {label.alert_id: label for label in labels}

        for category in args.category:
            batch = select_dev_batch(
                alerts, labels_by_alert_id, category,
                true_positive_count=args.true_count,
                false_positive_count=args.false_count,
                exclude_alert_ids=exclude_alert_ids,
            )
            if len(batch) < args.true_count + args.false_count:
                print(f"Attention ({language}/{category}) : seulement {len(batch)} alertes trouvees sur {args.true_count + args.false_count} demandees.")

            for entry in batch:
                entries.append({
                    "alert_id": entry.alert.alert_id,
                    "language": entry.alert.language,
                    "rule_id": entry.alert.rule_id,
                    "category": entry.category,
                    "expected_verdict": entry.expected_verdict,
                    "file_path": entry.alert.file_path,
                    "start_line": entry.alert.start_line,
                    "end_line": entry.alert.end_line,
                    "message": entry.alert.message,
                })

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Lot ({', '.join(args.category)}) : {len(entries)} alertes")
    for entry in entries:
        print(f"  {entry['alert_id']:35s} {entry['expected_verdict']:15s} {entry['file_path']}:{entry['start_line']}")
    print(f"Fichier ecrit : {args.out}")


def _run_qualify_simple(args: argparse.Namespace) -> None:
    from dotenv import load_dotenv

    load_dotenv()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ANTHROPIC_API_KEY manquante : remplis-la dans .env avant de lancer cette commande.")
        return

    import anthropic

    from .qualification.simple import SimpleQualifier
    from .safety.budget import BudgetExceeded, CallBudget
    from .safety.sandbox import ReadOnlyRepository

    model = os.environ.get("MODEL_NAME", "claude-sonnet-5")
    entries = json.loads(args.batch.read_text(encoding="utf-8"))

    client = anthropic.Anthropic()
    budget = CallBudget(max_calls=args.max_calls, max_duration_seconds=args.max_duration)
    qualifier = SimpleQualifier(client=client, model=model, budget=budget)
    repositories = {
        language: ReadOnlyRepository(defaults["corpus_root"])
        for language, defaults in _DEFAULTS.items()
    }

    print(f"Modele : {model}  |  plafond : {args.max_calls} appels / {args.max_duration}s")

    results = []
    for entry in entries:
        repository = repositories[entry["language"]]
        try:
            # On lit depuis le debut du fichier plutot qu'une fenetre centree
            # sur la ligne de l'alerte : un helper (methode, classe interne)
            # peut etre defini n'importe ou dans le fichier, souvent apres la
            # ligne de l'alerte elle-meme. 99% des fichiers OWASP Benchmark
            # font moins de 190 lignes (mesure sur le corpus complet), donc
            # ca couvre le fichier entier dans la quasi-totalite des cas.
            context = repository.read_file(entry["file_path"], start_line=1, end_line=args.max_context_lines)
        except (FileNotFoundError, PermissionError, ValueError) as error:
            print(f"  {entry['alert_id']:35s} lecture impossible : {error}")
            continue

        alert = CodeQLAlert(
            alert_id=entry["alert_id"], language=entry["language"], rule_id=entry["rule_id"],
            category=entry["category"], message=entry["message"], file_path=entry["file_path"],
            start_line=entry["start_line"], end_line=entry["end_line"],
        )

        try:
            result = qualifier.qualify(alert, context)
        except BudgetExceeded as error:
            print(f"Arret : {error}")
            break

        results.append(result)
        match = "OK" if result.verdict == entry["expected_verdict"] else "??"
        print(f"  {result.alert_id:35s} verdict={result.verdict:15s} attendu={entry['expected_verdict']:15s} [{match}]")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps([dataclasses.asdict(result) for result in results], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Appels effectues : {budget.calls_made}/{args.max_calls}")
    print(f"Fichier ecrit : {args.out}")


def _run_qualify_agent(args: argparse.Namespace) -> None:
    from dotenv import load_dotenv

    load_dotenv()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ANTHROPIC_API_KEY manquante : remplis-la dans .env avant de lancer cette commande.")
        return

    import anthropic

    from .qualification.agent import ExploringAgentQualifier
    from .safety.budget import BudgetExceeded, CallBudget
    from .safety.sandbox import ReadOnlyRepository

    model = os.environ.get("MODEL_NAME", "claude-sonnet-5")
    entries = json.loads(args.batch.read_text(encoding="utf-8"))

    client = anthropic.Anthropic()
    budget = CallBudget(max_calls=args.max_calls, max_duration_seconds=args.max_duration)
    repositories = {
        language: ReadOnlyRepository(defaults["corpus_root"])
        for language, defaults in _DEFAULTS.items()
    }

    print(f"Modele : {model}  |  plafond : {args.max_calls} appels / {args.max_duration}s  |  {args.max_turns} tours max par alerte")

    results = []
    for entry in entries:
        repository = repositories[entry["language"]]
        agent = ExploringAgentQualifier(
            client=client, model=model, budget=budget, repository=repository, max_turns=args.max_turns,
            transcripts_dir=args.transcripts_dir,
        )
        try:
            # Contexte de depart volontairement plus court que l'appel simple :
            # le but est de voir si l'agent va chercher le reste lui-meme.
            context = repository.read_file(entry["file_path"], start_line=1, end_line=args.initial_context_lines)
        except (FileNotFoundError, PermissionError, ValueError) as error:
            print(f"  {entry['alert_id']:35s} lecture impossible : {error}")
            continue

        alert = CodeQLAlert(
            alert_id=entry["alert_id"], language=entry["language"], rule_id=entry["rule_id"],
            category=entry["category"], message=entry["message"], file_path=entry["file_path"],
            start_line=entry["start_line"], end_line=entry["end_line"],
        )

        try:
            result = agent.qualify(alert, context)
        except BudgetExceeded as error:
            print(f"Arret : {error}")
            break

        results.append(result)
        match = "OK" if result.verdict == entry["expected_verdict"] else "??"
        print(f"  {result.alert_id:35s} verdict={result.verdict:15s} attendu={entry['expected_verdict']:15s} tours={result.model_calls} [{match}]")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps([dataclasses.asdict(result) for result in results], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Appels effectues : {budget.calls_made}/{args.max_calls}")
    print(f"Fichier ecrit : {args.out}")


def _run_evaluate(args: argparse.Namespace) -> None:
    from .benchmark.metrics import confusion_counts, technical_failures
    from .benchmark.models import ReferenceLabel
    from .core.models import QualificationResult

    results_data = json.loads(args.results.read_text(encoding="utf-8"))
    results = [QualificationResult(**entry) for entry in results_data]

    labels_by_alert_id: dict[str, ReferenceLabel] = {}
    for defaults in _DEFAULTS.values():
        label_path = defaults["out"]
        if not label_path.exists():
            print(f"Attention : {label_path} n'existe pas, lance d'abord 'build-labels' pour ce langage.")
            continue
        with label_path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                labels_by_alert_id[row["alert_id"]] = ReferenceLabel(
                    alert_id=row["alert_id"],
                    expected_verdict=row["expected_verdict"],
                    source=row["source"],
                    category=row["category"],
                )

    counts = confusion_counts(results, labels_by_alert_id)
    failures = technical_failures(results)
    unlabeled = sum(1 for r in results if r.alert_id not in labels_by_alert_id)

    verdicts = ["true_positive", "false_positive", "uncertain"]
    print(f"Resultats evalues : {len(results)}")
    print(f"Echecs techniques (appel API en erreur) : {failures}")
    if unlabeled:
        print(f"Resultats sans label de reference trouve : {unlabeled}")
    print()
    header = f"{'attendu / obtenu':20s}" + "".join(f"{v:16s}" for v in verdicts)
    print(header)
    for expected in verdicts:
        row = "".join(f"{counts.get((expected, actual), 0):16d}" for actual in verdicts)
        print(f"{expected:20s}{row}")

    total = sum(counts.values())
    correct = sum(counts.get((v, v), 0) for v in verdicts)
    if total:
        print()
        print(f"Bonnes reponses : {correct}/{total} ({100 * correct / total:.0f}%)")
