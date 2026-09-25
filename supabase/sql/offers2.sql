-- ============================================================
-- Pasiūlymų kūrimas: klientų duomenų bazė + nauja skiltis „Sukurti projektą“
--  * newproj — skiltis „Sukurti projektą“ (Admin → teisės)
--  * clients — klientai (iš įkeltų ankstesnių pasiūlymų ir įvesti ranka):
--    pavadinimas, įmonės / PVM kodas, adresas, kontaktinis asmuo, el. paštas,
--    telefonas; mato tie, kas mato „Pasiūlymų kūrimą“, keičia – kas jį redaguoja.
-- Realios pasiūlymų išlaidos saugomos pačiame pasiūlyme (offers.data.actual).
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people','newproj'));

insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','newproj',true,true), ('office','newproj',true,false), ('tech','newproj',true,false),
  ('freelance','newproj',false,false), ('runner','newproj',false,false)
on conflict (role, section) do nothing;

create table if not exists public.clients (
  id         text primary key,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);
alter table public.clients enable row level security;
drop policy if exists "view clients" on public.clients;
create policy "view clients" on public.clients
  for select to authenticated using (public.can_view('offers'));
drop policy if exists "edit clients" on public.clients;
create policy "edit clients" on public.clients
  for all to authenticated using (public.can_edit('offers')) with check (public.can_edit('offers'));
grant select, insert, update, delete on public.clients to authenticated;
