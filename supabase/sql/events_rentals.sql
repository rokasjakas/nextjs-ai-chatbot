-- ============================================================
-- „Renginiai“ ir „Paėmimai“ — po vieną eilutę kiekvienam renginiui ir
-- kiekvienam įrangos paėmimui, kad keli žmonės galėtų redaguoti vienu metu.
-- Paleisk Supabase → SQL Editor → įklijuok → Run (saugu paleisti pakartotinai).
-- ============================================================
create table if not exists public.events (
  id         text primary key,
  event_date date,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);
create index if not exists events_event_date_idx on public.events (event_date);

create table if not exists public.rentals (
  id         text primary key,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);

alter table public.events  enable row level security;
alter table public.rentals enable row level security;

drop policy if exists "team manages events" on public.events;
create policy "team manages events" on public.events
  for all to authenticated
  using ((auth.jwt() ->> 'email') ilike '%@eventsolutions.lt')
  with check ((auth.jwt() ->> 'email') ilike '%@eventsolutions.lt');

drop policy if exists "team manages rentals" on public.rentals;
create policy "team manages rentals" on public.rentals
  for all to authenticated
  using ((auth.jwt() ->> 'email') ilike '%@eventsolutions.lt')
  with check ((auth.jwt() ->> 'email') ilike '%@eventsolutions.lt');
