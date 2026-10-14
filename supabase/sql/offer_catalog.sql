-- ============================================================
-- Pasiūlymų kūrimas → Įranga / Paslaugos
--  * Įranga – sandėlio daiktų pavadinimai, vienetai ir kainos pasiūlymams;
--  * Įrangos grupės – kelių daiktų rinkiniai kaip viena pasiūlymo eilutė (pvz. 1 m² ekrano);
--  * Paslaugos – pavadinimai ir įkainiai;
--  * Kita – kas pasiūlymuose įrašyta ranka (išsaugoma savaime).
-- Mato tie, kas mato „Pasiūlymų kūrimą“, keičia – kas jį redaguoja.
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.offer_catalog (
  id         text primary key,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);
alter table public.offer_catalog enable row level security;
drop policy if exists "view offer catalog" on public.offer_catalog;
create policy "view offer catalog" on public.offer_catalog
  for select to authenticated using (public.can_view('offers'));
drop policy if exists "edit offer catalog" on public.offer_catalog;
create policy "edit offer catalog" on public.offer_catalog
  for all to authenticated using (public.can_edit('offers')) with check (public.can_edit('offers'));
grant select, insert, update, delete on public.offer_catalog to authenticated;
revoke all on public.offer_catalog from anon;

-- Supabase: read the list of tables again (otherwise the app may still say the table is missing)
notify pgrst, 'reload schema';
