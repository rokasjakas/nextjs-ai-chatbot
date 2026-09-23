-- ============================================================
-- Bendri svetainės duomenys visai komandai: sandėlio pataisymai (matmenys,
-- žymės), pakavimo variantai, automobilių parkas, krovimų istorija.
-- Paleisk Supabase → SQL Editor → įklijuok → Run (saugu paleisti pakartotinai).
-- ============================================================
create table if not exists public.app_state (
  key        text primary key,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);

alter table public.app_state enable row level security;

drop policy if exists "team manages app state" on public.app_state;
create policy "team manages app state" on public.app_state
  for all to authenticated
  using ((auth.jwt() ->> 'email') ilike '%@eventsolutions.lt')
  with check ((auth.jwt() ->> 'email') ilike '%@eventsolutions.lt');
