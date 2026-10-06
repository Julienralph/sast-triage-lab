"""Fusionne les resultats d'un run initial et de son run de reprise.

Les resultats du run de reprise remplacent ceux du run initial pour les
memes alert_id (on garde le plus recent). Les autres alertes du run
initial restent inchangees.

Usage :
    python scripts/merge_results.py <resultats_initiaux.json> <resultats_reprise.json> <resultats_fusionnes.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 4:
        print(__doc__)
        raise SystemExit(1)

    base_path, retry_path, out_path = (Path(arg) for arg in sys.argv[1:4])

    base = json.loads(base_path.read_text(encoding="utf-8"))
    retry = json.loads(retry_path.read_text(encoding="utf-8"))

    merged_by_id = {entry["alert_id"]: entry for entry in base}
    replaced = 0
    for entry in retry:
        if entry["alert_id"] in merged_by_id:
            replaced += 1
        merged_by_id[entry["alert_id"]] = entry

    merged = list(merged_by_id.values())
    out_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")

    still_failed = sum(1 for entry in merged if entry["technical_status"] == "error")
    print(f"{len(merged)} resultats au total ({replaced} remplaces par la reprise) -> {out_path}")
    print(f"Echecs techniques restants : {still_failed}")


if __name__ == "__main__":
    main()
