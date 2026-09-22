#!/usr/bin/env python3
"""
Rentman equipment/subrent report.

Connects to the Rentman API (https://api.rentman.net), lists projects in a
given date range, and prints the equipment (and subrent) list of a chosen
project as plain text lines like:

    16x Moving head MAC Aura
    4x  DMX splitter

NOTE ON FIELD NAMES
--------------------
This was written from the documented shape of the Rentman API (bearer-token
auth, paginated `/projects` and `/projects/{id}/projectequipment` resources)
without live access to api.rentman.net to verify exact field names for your
account/API version. The lookups below therefore try several common field
name candidates and fail loudly with the raw JSON (via --debug) rather than
silently guessing. If a name/quantity does not resolve correctly, run with
--debug once, inspect the printed JSON for the item, and adjust the
NAME_FIELDS / QUANTITY_FIELDS lists near the top of the file to match what
your Rentman instance actually returns.

SETUP
-----
    pip install requests
    export RENTMAN_API_TOKEN="your-api-token"   # created in Rentman under
                                                  # Settings > API tokens

USAGE
-----
    python rentman_equipment_report.py --from 2024-06-01 --to 2024-06-30
    python rentman_equipment_report.py --from 2024-06-01 --to 2024-06-30 --project-id 1234
    python rentman_equipment_report.py --from 2024-06-01 --to 2024-06-30 --debug
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import date, datetime
from typing import Any

import requests

BASE_URL = "https://api.rentman.net"
PAGE_LIMIT = 100

# Candidate field names to try, in order, when reading a value off a
# project / equipment-line record. Adjust these if --debug shows different
# keys in your Rentman account.
PROJECT_DATE_FIELD_PAIRS = [
    ("planperiod_start", "planperiod_end"),
    ("usageperiod_start", "usageperiod_end"),
    ("equipment_period_start", "equipment_period_end"),
]
PROJECT_NAME_FIELDS = ["name", "displayname", "project_number", "number"]
NAME_FIELDS = ["name", "equipment_name", "displayname", "description"]
QUANTITY_FIELDS = ["quantity", "amount", "planned_amount", "planned_quantity", "number"]
SUBRENT_FLAG_FIELDS = ["is_subrent", "subrent", "subrented"]


class RentmanClient:
    def __init__(self, token: str, debug: bool = False):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            }
        )
        self.debug = debug
        self._equipment_cache: dict[str, dict[str, Any]] = {}

    def _log(self, *args: Any) -> None:
        if self.debug:
            print("[debug]", *args, file=sys.stderr)

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        url = path if path.startswith("http") else f"{BASE_URL}{path}"
        self._log("GET", url, params)
        resp = self.session.get(url, params=params, timeout=30)
        if resp.status_code == 404:
            self._log("404 for", url)
            return None
        resp.raise_for_status()
        return resp.json()

    def _get_paginated(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Fetches all pages of a Rentman list endpoint (limit/offset pagination)."""
        items: list[dict[str, Any]] = []
        offset = 0
        base_params = dict(params or {})
        while True:
            page_params = {**base_params, "limit": PAGE_LIMIT, "offset": offset}
            payload = self._get(path, page_params)
            if not payload:
                break
            data = payload.get("data", payload if isinstance(payload, list) else [])
            if not data:
                break
            items.extend(data)
            self._log(f"fetched {len(data)} items from {path} (offset={offset})")
            if len(data) < PAGE_LIMIT:
                break
            offset += PAGE_LIMIT
        return items

    def list_projects(self) -> list[dict[str, Any]]:
        return self._get_paginated("/projects")

    def list_project_equipment(self, project_id: Any) -> list[dict[str, Any]]:
        lines = self._get_paginated(f"/projects/{project_id}/projectequipment")
        # Subrent items may live in a dedicated endpoint depending on API
        # version; merge them in if it exists, ignore silently if it 404s.
        subrent = self._get_paginated(f"/projects/{project_id}/subrentals")
        return lines + subrent

    def resolve_equipment_name(self, item: dict[str, Any]) -> str:
        for field in NAME_FIELDS:
            value = item.get(field)
            if value:
                return str(value)

        ref = item.get("equipment") or item.get("article")
        if isinstance(ref, str) and ref:
            if ref not in self._equipment_cache:
                payload = self._get(ref)
                self._equipment_cache[ref] = (payload or {}).get("data", payload or {})
            equipment = self._equipment_cache[ref]
            for field in NAME_FIELDS:
                value = equipment.get(field)
                if value:
                    return str(value)

        return f"Item #{item.get('id', '?')}"


def read_field(record: dict[str, Any], candidates: list[str]) -> Any:
    for field in candidates:
        if record.get(field) not in (None, ""):
            return record[field]
    return None


def parse_date(value: str) -> date:
    return datetime.strptime(value, "%Y-%m-%d").date()


def project_overlaps_range(project: dict[str, Any], start: date, end: date) -> bool:
    for start_field, end_field in PROJECT_DATE_FIELD_PAIRS:
        raw_start, raw_end = project.get(start_field), project.get(end_field)
        if not raw_start or not raw_end:
            continue
        try:
            p_start = datetime.fromisoformat(raw_start.replace("Z", "+00:00")).date()
            p_end = datetime.fromisoformat(raw_end.replace("Z", "+00:00")).date()
        except ValueError:
            continue
        return p_start <= end and p_end >= start
    # No recognized date fields on this project; can't filter it, so skip.
    return False


def project_label(project: dict[str, Any]) -> str:
    name = read_field(project, PROJECT_NAME_FIELDS) or f"Project #{project.get('id')}"
    for start_field, end_field in PROJECT_DATE_FIELD_PAIRS:
        if project.get(start_field) and project.get(end_field):
            return f"[{project['id']}] {name} ({project[start_field][:10]} - {project[end_field][:10]})"
    return f"[{project['id']}] {name}"


def format_quantity(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    if number == int(number):
        return str(int(number))
    return f"{number:g}"


def build_report(client: RentmanClient, project_id: Any) -> list[str]:
    lines = client.list_project_equipment(project_id)
    totals: dict[str, float] = {}
    order: list[str] = []

    for item in lines:
        name = client.resolve_equipment_name(item)
        quantity_raw = read_field(item, QUANTITY_FIELDS)
        try:
            quantity = float(quantity_raw) if quantity_raw is not None else 1.0
        except (TypeError, ValueError):
            quantity = 1.0

        if name not in totals:
            totals[name] = 0.0
            order.append(name)
        totals[name] += quantity

    return [f"{format_quantity(totals[name])}x {name}" for name in order]


def get_token(cli_token: str | None) -> str:
    token = cli_token or os.environ.get("RENTMAN_API_TOKEN")
    if token:
        return token
    return getpass.getpass("Rentman API token: ").strip()


def choose_project(projects: list[dict[str, Any]]) -> dict[str, Any]:
    if not projects:
        print("No projects found in the given date range.")
        sys.exit(1)

    print(f"\nFound {len(projects)} project(s):\n")
    for idx, project in enumerate(projects, start=1):
        print(f"  {idx}. {project_label(project)}")

    while True:
        choice = input("\nSelect a project by number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(projects):
            return projects[int(choice) - 1]
        print("Invalid choice, try again.")


def main() -> None:
    parser = argparse.ArgumentParser(description="List Rentman project equipment/subrent as plain text.")
    parser.add_argument("--from", dest="date_from", required=True, help="Start date, YYYY-MM-DD")
    parser.add_argument("--to", dest="date_to", required=True, help="End date, YYYY-MM-DD")
    parser.add_argument("--project-id", dest="project_id", help="Skip the picker and use this project ID directly")
    parser.add_argument("--token", dest="token", help="Rentman API token (else uses RENTMAN_API_TOKEN env var, else prompts)")
    parser.add_argument("--debug", action="store_true", help="Print raw API requests/responses to stderr")
    args = parser.parse_args()

    start = parse_date(args.date_from)
    end = parse_date(args.date_to)
    if start > end:
        parser.error("--from must not be after --to")

    client = RentmanClient(get_token(args.token), debug=args.debug)

    if args.project_id:
        project_id = args.project_id
    else:
        projects = client.list_projects()
        in_range = [p for p in projects if project_overlaps_range(p, start, end)]
        project = choose_project(in_range)
        project_id = project["id"]

    report_lines = build_report(client, project_id)
    if not report_lines:
        print("No equipment/subrent lines found for this project.")
        return

    print()
    for line in report_lines:
        print(line)


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as exc:
        print(f"Rentman API error: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
