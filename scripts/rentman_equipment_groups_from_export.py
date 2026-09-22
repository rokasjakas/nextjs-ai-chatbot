#!/usr/bin/env python3
"""Ištraukia Rentman įrangos kategorijų (equipment groups / folders) medį
iš Rentman "Equipment" sąrašo eksporto (.xlsx), naudojant jame esantį
"Path" stulpelį (pvz. "Apšvietimas / Prietaisai / Wash").

Tai alternatyva API-based scenarijui (rentman_equipment_groups.py) --
naudinga, kai API tokenas neturi prieigos prie equipment/equipmentgroups
resursų, bet Rentman UI leidžia eksportuoti pilną equipment sąrašą su
kategorijų keliu.

Kaip gauti export failą Rentman'e:
    Warehouse -> Equipment -> pasirink visus įrašus -> ... (More actions)
    -> Export -> įsitikink, kad tarp eksportuojamų stulpelių yra "Path"
    (arba "Folder") -> atsisiųsk .xlsx.

Naudojimas:
    pip install openpyxl
    python scripts/rentman_equipment_groups_from_export.py Export_Equipment.xlsx --out equipment_groups.json
"""

import argparse
import json
import sys

try:
    import openpyxl
except ImportError:
    sys.exit("Trūksta bibliotekos 'openpyxl'. Įsidiek: pip install openpyxl")


def build_tree(paths):
    """paths: iterable of 'A / B / C' stiliaus kategorijų kelių.
    Grąžina [{"name": ..., "parent": ...}, ...] su visais unikaliais
    mazgais medyje (įskaitant tarpinius, net jei jie neturi tiesiogiai
    priskirtos įrangos)."""
    nodes = {}  # pilnas kelias -> (pavadinimas, tėvo pilnas kelias)
    for p in paths:
        if not p:
            continue
        # Rentman lygius skiria " / " (tarpas-brūkšnys-tarpas); paprastas "/"
        # be tarpų gali būti paties kategorijos pavadinimo dalis (pvz. "FOG/Haze").
        parts = [seg.strip() for seg in p.split(" / ") if seg.strip()]
        for i in range(len(parts)):
            full = " / ".join(parts[: i + 1])
            name = parts[i]
            parent_full = " / ".join(parts[:i]) if i > 0 else None
            nodes[full] = (name, parent_full)

    result = []
    for full, (name, parent_full) in nodes.items():
        parent_name = nodes[parent_full][0] if parent_full else None
        result.append({"name": name, "parent": parent_name})

    result.sort(key=lambda x: (x["parent"] is not None, x["parent"] or "", x["name"]))
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Ištraukia equipment groups medį iš Rentman Equipment export .xlsx failo."
    )
    parser.add_argument("xlsx_path", help="Kelias iki Rentman Equipment export .xlsx failo.")
    parser.add_argument(
        "--sheet", default=None, help="Lapo (sheet) pavadinimas, jei ne pirmas lapas."
    )
    parser.add_argument(
        "--path-column",
        default="Path",
        help="Stulpelio pavadinimas su kategorijos keliu (numatyta: 'Path').",
    )
    parser.add_argument("--out", help="Failas, į kurį įrašyti JSON (numatyta: stdout).")
    parser.add_argument("--indent", type=int, default=2, help="JSON įtraukos dydis.")
    args = parser.parse_args()

    wb = openpyxl.load_workbook(args.xlsx_path, data_only=True)
    ws = wb[args.sheet] if args.sheet else wb.worksheets[0]

    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        sys.exit("Failas tuščias.")

    header = rows[0]
    if args.path_column not in header:
        sys.exit(
            f"Stulpelio {args.path_column!r} nėra faile. Rasti stulpeliai: {list(header)}"
        )
    path_idx = header.index(args.path_column)

    paths = {row[path_idx].strip() for row in rows[1:] if row[path_idx]}
    if not paths:
        sys.exit(f"Stulpelyje {args.path_column!r} neradau jokių reikšmių.")

    tree = build_tree(paths)

    text = json.dumps(tree, ensure_ascii=False, indent=args.indent)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"Išsaugota {len(tree)} kategorijų į {args.out}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
