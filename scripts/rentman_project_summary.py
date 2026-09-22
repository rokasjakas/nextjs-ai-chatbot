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

PASTABA: šis scenarijus parašytas be galimybės tiesiogiai išbandyti prieš
gyvą Rentman API (tinklo apribojimai šioje aplinkoje), todėl:
  - equipment planning duomenims bando kelis galimus endpoint'us paeiliui;
  - schedule (montazas/renginys/demontazas) laukus bando atspėti iš
    standartinių Rentman projekto datų laukų (usageperiod_*, planperiod_*,
    equipment_period_*) -- jei atspėjimas neteisingas, paleisk su --debug,
    kad pamatytum VISUS projekto JSON laukus, ir pasakyk man, kurie iš jų
    iš tikrųjų atitinka montažą/renginį/demontažą, aš iškart pataisysiu.
  - jei paleidus su --debug equipment sąrašas lieka tuščias, atsiųsk man
    stderr išvestį (kokius endpoint'us bandė ir ką jie grąžino) -- pagal
    tai surasiu teisingą endpoint'ą.
"""

import argparse
import json
import os
import sys
from urllib.parse import urljoin

import requests

BASE_URL = "https://api.rentman.net"

# Kandidatai projekto įrangos sąrašo (equipment planning) endpoint'ui.
# {id} bus pakeistas projekto ID.
EQUIPMENT_ENDPOINT_CANDIDATES = [
    "/projects/{id}/equipment",
    "/projects/{id}/planning",
    "/projects/{id}/equipmentplanning",
    "/equipment_periods?project=/projects/{id}",
    "/projectequipment?project=/projects/{id}",
    "/planning?project=/projects/{id}",
]

NAME_FIELD_CANDIDATES = ("displayname", "name")
QTY_FIELD_CANDIDATES = ("quantity", "amount", "qty", "planned_quantity", "planned_amount")
EQUIPMENT_REF_FIELD_CANDIDATES = ("equipment", "equipment_id", "item")


def get_session(token):
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})
    return s


def api_get(session, path, params=None, debug=False):
    url = urljoin(BASE_URL, path.split("?")[0])
    if "?" in path and not params:
        # leidžiam patogiai perduoti query per patį path (kandidatų sąraše)
        from urllib.parse import parse_qsl

        params = dict(parse_qsl(path.split("?", 1)[1]))
    resp = session.get(url, params=params)
    if debug:
        print(f"GET {resp.url} -> {resp.status_code}", file=sys.stderr)
    return resp


def unwrap(payload):
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def extract_id_from_ref(value):
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)):
        return str(int(value))
    if isinstance(value, str):
        return value.strip().rstrip("/").rsplit("/", 1)[-1]
    return str(value)


def fetch_project(session, project_id, debug):
    resp = api_get(session, f"/projects/{project_id}", debug=debug)
    if resp.status_code != 200:
        sys.exit(
            f"Nepavyko gauti projekto {project_id}: {resp.status_code}\n{resp.text[:1000]}"
        )
    data = unwrap(resp.json())
    if isinstance(data, list):
        data = data[0] if data else {}
    return data


def fetch_equipment_lines(session, project_id, debug):
    for template in EQUIPMENT_ENDPOINT_CANDIDATES:
        path = template.format(id=project_id)
        resp = api_get(session, path, debug=debug)
        if resp.status_code == 404:
            continue
        if resp.status_code != 200:
            if debug:
                print(f"  -> praleidžiu ({resp.status_code}): {resp.text[:300]}", file=sys.stderr)
            continue
        data = unwrap(resp.json())
        if isinstance(data, list) and data:
            if debug:
                print(f"  -> RADAU {len(data)} įrašų per {path}", file=sys.stderr)
                print(f"  -> pavyzdys: {json.dumps(data[0], ensure_ascii=False)[:500]}", file=sys.stderr)
            return data, path
    return [], None


def resolve_equipment_names(session, refs, debug):
    """refs: set of equipment id (string). Grąžina {id: name}."""
    result = {}
    for eid in refs:
        resp = api_get(session, f"/equipment/{eid}", debug=debug)
        if resp.status_code != 200:
            continue
        item = unwrap(resp.json())
        if isinstance(item, list):
            item = item[0] if item else {}
        for key in NAME_FIELD_CANDIDATES:
            if item.get(key):
                result[eid] = item[key]
                break
    return result


def get_field(item, keys):
    for k in keys:
        if item.get(k) not in (None, ""):
            return item[k]
    return None


def main():
    parser = argparse.ArgumentParser(description="Ištraukia Rentman projekto suvestinę.")
    parser.add_argument("project_id", help="Rentman projekto ID (pvz. 1121)")
    parser.add_argument(
        "--token", default=os.environ.get("RENTMAN_API_TOKEN"), help="API tokenas."
    )
    parser.add_argument("--debug", action="store_true", help="Spausdinti diagnostiką į stderr.")
    parser.add_argument("--out", help="Failas rezultatui (numatyta: stdout).")
    args = parser.parse_args()

    if not args.token:
        sys.exit("Trūksta API tokeno (--token arba RENTMAN_API_TOKEN).")

    session = get_session(args.token)

    project = fetch_project(session, args.project_id, args.debug)
    if args.debug:
        print(f"PROJECT RAW: {json.dumps(project, ensure_ascii=False, default=str)}", file=sys.stderr)

    name = get_field(project, ("name", "displayname")) or ""

    usage_start = project.get("usageperiod_start") or ""
    usage_end = project.get("usageperiod_end") or ""
    equip_start = project.get("equipment_period_from") or project.get("equipment_period_start") or ""
    equip_end = project.get("equipment_period_to") or project.get("equipment_period_end") or ""
    plan_start = project.get("planperiod_start") or ""
    plan_end = project.get("planperiod_end") or ""

    def date_only(dt_str):
        return dt_str[:10] if dt_str else ""

    def to_space_format(dt_str):
        # Rentman grąžina ISO 8601, pvz. 2026-05-03T10:00:00+02:00
        if not dt_str:
            return ""
        return dt_str[:16].replace("T", " ")

    event_date = date_only(usage_start)

    schedule = {
        "montazas": to_space_format(equip_start or plan_start),
        "renginys": to_space_format(usage_start),
        "demontazas": to_space_format(equip_end or plan_end),
    }

    equipment_lines, used_endpoint = fetch_equipment_lines(session, args.project_id, args.debug)
    if args.debug and not used_endpoint:
        print(
            "WARNING: nė vienas equipment endpoint kandidatas negrąžino duomenų. "
            "Reikės rasti teisingą endpoint pavadinimą.",
            file=sys.stderr,
        )

    equipment_out = []
    refs_to_resolve = set()
    parsed_lines = []
    for line in equipment_lines:
        qty = get_field(line, QTY_FIELD_CANDIDATES)
        eq_ref = get_field(line, EQUIPMENT_REF_FIELD_CANDIDATES)
        inline_name = get_field(line, NAME_FIELD_CANDIDATES)
        eq_id = extract_id_from_ref(eq_ref) if eq_ref else None
        if eq_id and not inline_name:
            refs_to_resolve.add(eq_id)
        parsed_lines.append((qty, eq_id, inline_name))

    resolved_names = resolve_equipment_names(session, refs_to_resolve, args.debug) if refs_to_resolve else {}

    for qty, eq_id, inline_name in parsed_lines:
        name_val = inline_name or (resolved_names.get(eq_id) if eq_id else None) or ""
        equipment_out.append({"qty": qty if qty is not None else "", "name": name_val})

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
