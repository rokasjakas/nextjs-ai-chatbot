#!/usr/bin/env python3
"""Ištraukia vieno Rentman projekto suvestinę (pavadinimą, datas, tvarkaraštį
ir įrangos sąrašą su kiekiais) per Rentman API ir išveda VIENĄ JSON objektą,
be jokio papildomo teksto stdout:

{
  "name": "<projekto pavadinimas>",
  "eventDate": "<YYYY-MM-DD>",
  "schedule": {"montazas": "<YYYY-MM-DD HH:MM>", "renginys": "<YYYY-MM-DD HH:MM>", "demontazas": "<YYYY-MM-DD HH:MM>"},
  "equipment": [ {"qty": 16, "name": "Daikto pavadinimas"}, ... ]
}

Naudojimas:
    export RENTMAN_API_TOKEN="tavo_tokenas"
    python scripts/rentman_project_summary.py 1121

Duomenų šaltiniai (patikrinta prieš gyvą API 2026-09):
  - GET /projects/{id}                                    -> pavadinimas, renginio (usage) laikas
  - GET /projectequipmentgroup?project=/projects/{id}      -> visos projekto įrangos kategorijos/grupės,
                                                               kiekviena su savo planperiod_start/end
  - GET /projectequipment?equipment_group=/projectequipmentgroup/{gid}
                                                            -> konkrečios grupės įrangos eilutės (qty, name)

Schedule logika:
  - "renginys"  = projekto usageperiod_start (faktinis renginio laikas)
  - "montazas"  = mažiausia planperiod_start reikšmė tarp VISŲ projekto equipment groups
                  (t.y. anksčiausias laikas, kada bet kuri įranga pradedama ruošti/montuoti)
  - "demontazas"= didžiausia planperiod_end reikšmė tarp VISŲ projekto equipment groups
                  (vėliausias laikas, kada bet kuri įranga demontuojama/grąžinama)
  Ši logika patikrinta su projektu 1121: dauguma equipment groups turėjo platesnį
  langą (pvz. 08:00 dieną prieš iki 08:00 dieną po), o keletas -- tiksliai tokį patį
  langą kaip usageperiod_start/end (tik renginio metu reikalingi daiktai).

Jei projektas dar neturi jokios pridėtos įrangos (equipment groups be daiktų --
tai normalu naujiems/šablonų projektams Rentman'e), "equipment" bus tuščias
masyvas [] ir schedule.montazas/demontazas gali likti tušti (jei nėra nė vienos
grupės su nustatytu planperiod).
"""

import argparse
import json
import os
import sys
from urllib.parse import urljoin

import requests

BASE_URL = "https://api.rentman.net"

NAME_FIELD_CANDIDATES = ("displayname", "name")


def get_session(token):
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})
    return s


def api_get_all(session, path, params, debug=False):
    """Puslapiuoja per limit/offset, grąžina visus 'data' įrašus."""
    results = []
    limit = 300
    offset = 0
    url = urljoin(BASE_URL, path)
    while True:
        p = dict(params or {})
        p.update({"limit": limit, "offset": offset})
        resp = session.get(url, params=p)
        if debug:
            print(f"GET {resp.url} -> {resp.status_code}", file=sys.stderr)
        if resp.status_code != 200:
            sys.exit(f"Klaida kviečiant {path}: {resp.status_code}\n{resp.text[:1000]}")
        payload = resp.json()
        batch = payload.get("data", []) if isinstance(payload, dict) else payload
        results.extend(batch)
        if len(batch) < limit or not payload.get("next_page_url"):
            break
        offset += limit
    return results


def get_field(item, keys):
    for k in keys:
        if item.get(k) not in (None, ""):
            return item[k]
    return None


def to_space_format(dt_str):
    if not dt_str:
        return ""
    return dt_str[:16].replace("T", " ")


def main():
    parser = argparse.ArgumentParser(description="Ištraukia Rentman projekto suvestinę.")
    parser.add_argument("project_id", help="Rentman projekto ID (pvz. 1121)")
    parser.add_argument("--token", default=os.environ.get("RENTMAN_API_TOKEN"), help="API tokenas.")
    parser.add_argument("--debug", action="store_true", help="Spausdinti diagnostiką į stderr.")
    parser.add_argument("--out", help="Failas rezultatui (numatyta: stdout).")
    args = parser.parse_args()

    if not args.token:
        sys.exit("Trūksta API tokeno (--token arba RENTMAN_API_TOKEN).")

    session = get_session(args.token)

    # 1) Projektas
    resp = session.get(urljoin(BASE_URL, f"/projects/{args.project_id}"))
    if args.debug:
        print(f"GET {resp.url} -> {resp.status_code}", file=sys.stderr)
    if resp.status_code != 200:
        sys.exit(f"Nepavyko gauti projekto {args.project_id}: {resp.status_code}\n{resp.text[:1000]}")
    project = resp.json()
    if isinstance(project, dict) and "data" in project:
        project = project["data"]

    name = get_field(project, ("name", "displayname")) or ""
    usage_start = project.get("usageperiod_start") or ""
    event_date = usage_start[:10] if usage_start else ""

    # 2) Visos projekto equipment groups (kategorijos)
    groups = api_get_all(
        session, "/projectequipmentgroup", {"project": f"/projects/{args.project_id}"}, args.debug
    )
    if args.debug:
        print(f"Rasta {len(groups)} equipment groups.", file=sys.stderr)

    plan_starts = [g["planperiod_start"] for g in groups if g.get("planperiod_start")]
    plan_ends = [g["planperiod_end"] for g in groups if g.get("planperiod_end")]

    schedule = {
        "montazas": to_space_format(min(plan_starts)) if plan_starts else "",
        "renginys": to_space_format(usage_start),
        "demontazas": to_space_format(max(plan_ends)) if plan_ends else "",
    }

    # 3) Kiekvienos grupės equipment eilutės
    equipment_out = []
    for g in groups:
        gid = g["id"]
        lines = api_get_all(
            session, "/projectequipment", {"equipment_group": f"/projectequipmentgroup/{gid}"}, args.debug
        )
        for line in lines:
            qty = line.get("quantity")
            name_val = get_field(line, NAME_FIELD_CANDIDATES) or ""
            equipment_out.append({"qty": qty if qty is not None else "", "name": name_val})

    if args.debug:
        print(f"Iš viso equipment eilučių: {len(equipment_out)}", file=sys.stderr)

    result = {
        "name": name,
        "eventDate": event_date,
        "schedule": schedule,
        "equipment": equipment_out,
    }

    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"Išsaugota į {args.out}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
