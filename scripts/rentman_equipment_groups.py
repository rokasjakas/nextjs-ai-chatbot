#!/usr/bin/env python3
"""Ištraukia visą Rentman įrangos kategorijų (equipment groups / folders) medį
per Rentman viešąją API (https://api.rentman.net/) ir išveda jį kaip JSON
masyvą: [{"name": "PA", "parent": "Garsas"}, {"name": "Garsas", "parent": None}, ...]

Naudojimas:
    export RENTMAN_API_TOKEN="tavo_api_tokenas"
    python scripts/rentman_equipment_groups.py > equipment_groups.json

    # arba perduoti tokeną tiesiogiai ir įrašyti į failą:
    python scripts/rentman_equipment_groups.py --token TAVO_TOKENAS --out equipment_groups.json

PASTABA dėl endpoint pavadinimo: Rentman API kategorijas dažniausiai vadina
"equipmentgroups", bet kai kuriose API versijose jos gali būti pasiekiamos
per bendrinį "folders" endpoint su filtru pagal itemtype. Scenarijus pirmiau
bando "/equipmentgroups", o jei tas grąžina 404 -- automatiškai pabando
"/folders?itemtype=equipment". Jei abu nepavyksta, paleisk su --endpoint,
nurodydamas tikslų endpoint iš savo api.rentman.net dokumentacijos.

Taip pat scenarijus pats atspėja, kurie JSON laukai atitinka pavadinimą
("displayname"/"name"/"title") ir tėvinę kategoriją ("folder"/"parent"/
"parent_id"), nes tikslūs lauko pavadinimai priklauso nuo Rentman API
versijos -- jei atspėti nepavyksta, įrašai su trūkstamais laukais bus
praleisti ir apie tai bus pranešta per stderr.
"""

import argparse
import json
import os
import sys
from urllib.parse import urljoin

import requests

BASE_URL = "https://api.rentman.net"

# (endpoint path, papildomi query parametrai) -- bandomi šia tvarka,
# kol vienas iš jų grąžina duomenis.
CANDIDATE_ENDPOINTS = [
    ("/equipmentgroups", {}),
    ("/folders", {"itemtype": "equipment"}),
]

NAME_KEYS = ("displayname", "name", "title")
PARENT_KEYS = ("folder", "parent", "parent_id", "folderid")


def extract_id_from_ref(value):
    """Rentman API nuorodas į kitus įrašus dažnai grąžina kaip
    '/equipmentgroups/12' arba tiesiog kaip skaičių/None -- suvienodinam."""
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)):
        return str(int(value))
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
        return value.rstrip("/").rsplit("/", 1)[-1]
    return str(value)


def get_field(item, keys):
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return item[key]
    return None


def fetch_all(session, path, extra_params):
    """Ištraukia visus įrašus iš duoto Rentman API endpoint, su puslapiavimu."""
    results = []
    limit = 100
    offset = 0
    url = urljoin(BASE_URL, path)

    while True:
        params = {"limit": limit, "offset": offset, **extra_params}
        resp = session.get(url, params=params)

        if resp.status_code == 404:
            return None  # leidžiam main() pabandyti kitą endpoint kandidatą

        if resp.status_code in (401, 403):
            sys.exit(
                f"Autentifikacijos/leidimų klaida ({resp.status_code}) kviečiant {path}.\n"
                f"Serverio atsakymas: {resp.text[:1000]}\n\n"
                "Patikrink Rentman administravime (Settings -> API management / tokens), "
                "ar šis tokenas turi įjungtą prieigą prie 'equipmentgroups' / 'Equipment' resurso."
            )

        resp.raise_for_status()
        payload = resp.json()

        if isinstance(payload, dict) and "data" in payload:
            batch = payload["data"]
        elif isinstance(payload, list):
            batch = payload
        else:
            raise SystemExit(
                f"Nežinoma atsakymo struktūra iš {path}: {json.dumps(payload, ensure_ascii=False)[:500]}"
            )

        if not batch:
            break

        results.extend(batch)

        if len(batch) < limit:
            break
        offset += limit

    return results


def build_tree(groups):
    by_id = {}
    for g in groups:
        gid = g.get("id")
        name = get_field(g, NAME_KEYS)
        if gid is None or name is None:
            print(f"WARNING: praleidžiu įrašą be id/name: {g}", file=sys.stderr)
            continue
        by_id[str(gid)] = {"raw": g, "name": name}

    output = []
    for info in by_id.values():
        g = info["raw"]
        parent_id = extract_id_from_ref(get_field(g, PARENT_KEYS))
        parent_name = None
        if parent_id is not None:
            parent_entry = by_id.get(parent_id)
            if parent_entry is not None:
                parent_name = parent_entry["name"]
            else:
                print(
                    f"WARNING: {info['name']!r} nurodo tėvinę kategoriją id={parent_id}, "
                    "kurios nėra grąžintame sąraše -- laikoma be tėvo.",
                    file=sys.stderr,
                )
        output.append({"name": info["name"], "parent": parent_name})

    return output


def main():
    parser = argparse.ArgumentParser(
        description="Ištraukia Rentman equipment groups (įrangos kategorijų) medį per API."
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("RENTMAN_API_TOKEN"),
        help="Rentman API tokenas (arba nustatyk RENTMAN_API_TOKEN aplinkos kintamąjį).",
    )
    parser.add_argument(
        "--endpoint",
        default=None,
        help="Konkretus API endpoint, jei numatytieji kandidatai (/equipmentgroups, /folders) netinka.",
    )
    parser.add_argument("--out", help="Failas, į kurį įrašyti JSON (numatyta: stdout).")
    parser.add_argument("--indent", type=int, default=2, help="JSON įtraukos dydis.")
    args = parser.parse_args()

    if not args.token:
        sys.exit(
            "Trūksta API tokeno. Nustatyk RENTMAN_API_TOKEN aplinkos kintamąjį arba naudok --token."
        )

    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {args.token}",
            "Accept": "application/json",
        }
    )

    candidates = [(args.endpoint, {})] if args.endpoint else CANDIDATE_ENDPOINTS

    groups = None
    tried = []
    for path, extra_params in candidates:
        tried.append(path)
        groups = fetch_all(session, path, extra_params)
        if groups is not None:
            break

    if groups is None:
        sys.exit(
            "Nepavyko rasti equipment groups per bandytus endpoint'us: "
            f"{', '.join(tried)}. Patikrink api.rentman.net dokumentaciją ir "
            "paleisk su --endpoint <tikslus-kelias>."
        )

    if not groups:
        sys.exit("API grąžino tuščią sąrašą -- patikrink, ar tokenas turi prieigą prie sandėlio duomenų.")

    tree = build_tree(groups)

    text = json.dumps(tree, ensure_ascii=False, indent=args.indent)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"Išsaugota {len(tree)} kategorijų į {args.out}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
