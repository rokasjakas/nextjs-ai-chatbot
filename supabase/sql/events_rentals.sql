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

drop policy if exists "team manages rentals" on public.rentals;

-- Prieigos taisyklės (kas gali skaityti / rašyti) nustatomos user_roles.sql
-- pagal vartotojo lygį. Senoji taisyklė „tik @eventsolutions.lt“ pašalinta.
