-- ============================================================
-- Pasiūlymai ir Projektai (Ofisas) + naujas lygis „Projektų vadovas“.
--  * role 'pm' — Projektų vadovas
--  * skiltys: 'offers' (Pasiūlymai), 'jobs' (Projektai)
--  * offers  — komerciniai pasiūlymai (juodraštis / galutinis)
--  * jobs    — projektai, sukurti iš galutinio pasiūlymo (PDF be kainų)
--  * saugykla 'job-files' — projektų PDF
-- Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- naujas lygis ----------
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check
  check (role in ('pending','admin','pm','office','tech','freelance','runner','blocked'));

alter table public.role_permissions drop constraint if exists role_permissions_role_check;
alter table public.role_permissions add constraint role_permissions_role_check
  check (role in ('pm','office','tech','freelance','runner'));
alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers'));

-- numatytosios teisės (Admin skiltyje galima pakeisti)
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','offers',true,true), ('pm','jobs',true,true), ('pm','events',true,true), ('pm','rentals',true,true),
  ('pm','projects',true,true), ('pm','venues',true,true), ('pm','fleet',true,false), ('pm','inventory',true,false),
  ('pm','load',true,false), ('pm','rules',true,false), ('pm','stats',true,false), ('pm','chat',true,true), ('pm','mail',true,true),
  ('office','offers',false,false), ('office','jobs',true,false),
  ('tech','offers',false,false), ('tech','jobs',true,false),
  ('freelance','offers',false,false), ('freelance','jobs',false,false),
  ('runner','offers',false,false), ('runner','jobs',false,false)
on conflict (role, section) do nothing;

create or replace function public.is_approved() returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce(public.my_role() in ('admin','pm','office','tech','freelance','runner'), false)
$$;

create or replace function public.user_can_chat(uid uuid) returns boolean
  language sql stable security definer set search_path = public as $$
  select coalesce((
    select case when p.role = 'admin' then true
                when p.role in ('pm','office','tech','freelance','runner') then
                  coalesce((select rp.can_view or rp.can_edit from public.role_permissions rp
                            where rp.role = p.role and rp.section = 'chat'), false)
                else false end
    from public.profiles p where p.id = uid), false)
$$;

drop policy if exists "team sees members" on public.profiles;
create policy "team sees members" on public.profiles
  for select to authenticated using (
    id = auth.uid() or public.is_admin()
    or (public.is_approved() and role in ('admin','pm','office','tech','freelance','runner'))
  );

-- pasiūlymų nustatymai (rekvizitai, PVM) ir kainų atmintis — redaguoja „Pasiūlymai“
create or replace function public.app_state_can_edit(k text) returns boolean
  language sql stable security definer set search_path = public as $$
  select case k
    when 'itemOverrides' then public.can_edit('inventory')
    when 'customItems'   then public.can_edit('inventory')
    when 'rules'         then public.can_edit('rules')
    when 'vehicles'      then public.can_edit('fleet')
    when 'sessions'      then public.can_edit('load')
    when 'settings'      then public.can_edit('load')
    when 'eventOptions'  then public.can_edit('events') or public.can_edit('rentals')
    when 'offerSettings' then public.can_edit('offers')
    when 'offerPrices'   then public.can_edit('offers')
    else public.is_admin()
  end
$$;

-- ---------- pasiūlymai ----------
create table if not exists public.offers (
  id          uuid primary key default gen_random_uuid(),
  title       text not null default '',
  client      text not null default '',
  offer_date  date,
  status      text not null default 'draft' check (status in ('draft','final')),
  data        jsonb not null default '{}'::jsonb,
  total       numeric(12,2) not null default 0,
  job_id      uuid,
  created_by  uuid default auth.uid() references auth.users(id) on delete set null,
  updated_by  text,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists offers_updated_idx on public.offers (updated_at desc);

alter table public.offers enable row level security;
drop policy if exists "view offers" on public.offers;
create policy "view offers" on public.offers for select to authenticated using (public.can_view('offers'));
drop policy if exists "edit offers" on public.offers;
create policy "edit offers" on public.offers for all to authenticated
  using (public.can_edit('offers')) with check (public.can_edit('offers'));

-- ---------- projektai ----------
create table if not exists public.jobs (
  id          uuid primary key default gen_random_uuid(),
  title       text not null default '',
  client      text not null default '',
  location    text not null default '',
  job_date    date,
  offer_id    uuid references public.offers(id) on delete set null,
  pdf_path    text,
  notes       text not null default '',
  created_by  uuid default auth.uid() references auth.users(id) on delete set null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists jobs_date_idx on public.jobs (job_date);

alter table public.jobs enable row level security;
drop policy if exists "view jobs" on public.jobs;
create policy "view jobs" on public.jobs for select to authenticated using (public.can_view('jobs'));
drop policy if exists "add jobs" on public.jobs;
create policy "add jobs" on public.jobs for insert to authenticated with check (public.can_edit('offers') or public.can_edit('jobs'));
drop policy if exists "change jobs" on public.jobs;
create policy "change jobs" on public.jobs for update to authenticated
  using (public.can_edit('offers') or public.can_edit('jobs')) with check (public.can_edit('offers') or public.can_edit('jobs'));
drop policy if exists "delete jobs" on public.jobs;
create policy "delete jobs" on public.jobs for delete to authenticated using (public.can_edit('jobs'));

-- ---------- projektų PDF ----------
insert into storage.buckets (id, name, public) values ('job-files', 'job-files', false) on conflict (id) do nothing;
drop policy if exists "job files view" on storage.objects;
create policy "job files view" on storage.objects
  for select to authenticated using (bucket_id = 'job-files' and public.can_view('jobs'));
drop policy if exists "job files add" on storage.objects;
create policy "job files add" on storage.objects
  for insert to authenticated with check (bucket_id = 'job-files' and (public.can_edit('offers') or public.can_edit('jobs')));
drop policy if exists "job files change" on storage.objects;
create policy "job files change" on storage.objects
  for update to authenticated using (bucket_id = 'job-files' and (public.can_edit('offers') or public.can_edit('jobs')));
drop policy if exists "job files delete" on storage.objects;
create policy "job files delete" on storage.objects
  for delete to authenticated using (bucket_id = 'job-files' and (public.can_edit('offers') or public.can_edit('jobs')));
