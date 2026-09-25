-- ============================================================
-- „Sukurti projektą“ (Sandėlis): projektai kaip Rentman
--  * rp_projects — projektai ir šablonai (is_template = true):
--    subprojektai, laikai, įrangos grupės su daiktais iš sandėlio,
--    papildomos išlaidos, istorija — viskas stulpelyje data (jsonb)
--  * mato tie, kas mato „Sukurti projektą“, keičia — kas jį redaguoja
--  * klientų sąrašą mato ir papildo ir „Sukurti projektą“ vartotojai
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

create table if not exists public.rp_projects (
  id          text primary key,
  name        text not null default '',
  status      text not null default 'draft',
  date_from   timestamptz,
  date_to     timestamptz,
  is_template boolean not null default false,
  data        jsonb not null default '{}'::jsonb,
  created_by  uuid default auth.uid(),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  updated_by  text
);
create index if not exists rp_projects_dates on public.rp_projects (date_from, date_to);

alter table public.rp_projects enable row level security;
drop policy if exists "view rp_projects" on public.rp_projects;
create policy "view rp_projects" on public.rp_projects
  for select to authenticated using (public.can_view('newproj'));
drop policy if exists "edit rp_projects" on public.rp_projects;
create policy "edit rp_projects" on public.rp_projects
  for all to authenticated using (public.can_edit('newproj')) with check (public.can_edit('newproj'));
grant select, insert, update, delete on public.rp_projects to authenticated;

do $$ begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'rp_projects') then
    execute 'alter publication supabase_realtime add table public.rp_projects';
  end if;
end $$;

-- klientai: ir iš „Pasiūlymų kūrimo“, ir iš „Sukurti projektą“
drop policy if exists "view clients" on public.clients;
create policy "view clients" on public.clients
  for select to authenticated using (public.can_view('offers') or public.can_view('newproj'));
drop policy if exists "edit clients" on public.clients;
create policy "edit clients" on public.clients
  for all to authenticated using (public.can_edit('offers') or public.can_edit('newproj'))
  with check (public.can_edit('offers') or public.can_edit('newproj'));
