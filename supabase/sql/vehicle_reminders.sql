-- ============================================================
-- Automobilių dokumentų priminimai (draudimas, tech. apžiūra, kelių mokestis).
-- Paleisk Supabase → SQL Editor → įklijuok → Run (saugu paleisti pakartotinai).
-- ============================================================

create table if not exists public.vehicle_reminders (
  vehicle_id       text primary key,
  name             text not null default '',
  plate            text,
  insurance_until  date,
  inspection_until date,
  road_tax_until   date,
  lead_days        int  not null default 14,
  lead_days_by_doc jsonb not null default '{}'::jsonb,
  frequency_days   int  not null default 7,
  emails           text[] not null default '{}',
  -- {"insurance": {"date": "2026-09-23", "until": "2026-10-01"}, ...}
  reminder_hours   int[] not null default '{9}',
  last_sent        jsonb not null default '{}'::jsonb,
  updated_at       timestamptz not null default now()
);

alter table public.vehicle_reminders enable row level security;

drop policy if exists "team manages vehicle reminders" on public.vehicle_reminders;
create policy "team manages vehicle reminders" on public.vehicle_reminders
  for all to authenticated
  using ((auth.jwt() ->> 'email') ilike '%@eventsolutions.lt')
  with check ((auth.jwt() ->> 'email') ilike '%@eventsolutions.lt');
