"""Isole les alertes en echec technique d'un run precedent, pour les
relancer sans refaire celles qui ont deja un vrai resultat.

Usage :
    python scripts/build_retry_batch.py <lot_original.json> <resultats.json> <lot_a_refaire.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 4:
        print(__doc__)
        raise SystemExit(1)

    batch_path, results_path, out_path = (Path(arg) for arg in sys.argv[1:4])

    batch = json.loads(batch_path.read_text(encoding="utf-8"))
    results = json.loads(results_path.read_text(encoding="utf-8"))

    failed_ids = {r["alert_id"] for r in results if r["technical_status"] == "error"}
    retry_batch = [entry for entry in batch if entry["alert_id"] in failed_ids]

    out_path.write_text(json.dumps(retry_batch, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{len(retry_batch)} alertes en echec technique isolees -> {out_path}")
    if len(retry_batch) != len(failed_ids):
        print(f"Attention : {len(failed_ids)} alertes en echec dans {results_path}, mais seulement {len(retry_batch)} retrouvees dans {batch_path}.")


if __name__ == "__main__":
    main()
