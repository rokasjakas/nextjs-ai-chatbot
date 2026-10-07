-- ============================================================
-- „Erdvės“ — renginių vietų aprašai (adresas, patekimas, elektra, dūmai,
-- liftas / laiptai, kontaktai, 3D turas, nuotraukos).
-- Paleisti PO user_roles.sql. Supabase → SQL Editor → Run.
-- Saugu paleisti pakartotinai.
-- ============================================================

-- nauja skiltis teisių lentelėje
alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people'));

-- numatytosios teisės (Admin skiltyje galima pakeisti)
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('office','venues',true,true),
  ('tech','venues',true,false),
  ('freelance','venues',true,false),
  ('runner','venues',false,false)
on conflict (role, section) do nothing;

-- viena eilutė — viena erdvė
create table if not exists public.venues (
  id         text primary key,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);

alter table public.venues enable row level security;
drop policy if exists "view venues" on public.venues;
create policy "view venues" on public.venues
  for select to authenticated using (public.can_view('venues'));
drop policy if exists "edit venues" on public.venues;
create policy "edit venues" on public.venues
  for all to authenticated using (public.can_edit('venues')) with check (public.can_edit('venues'));

-- nuotraukos: privati saugykla, mato tik turintys prieigą prie „Erdvės“
insert into storage.buckets (id, name, public)
values ('venue-photos', 'venue-photos', false)
on conflict (id) do nothing;

drop policy if exists "venue photos view" on storage.objects;
create policy "venue photos view" on storage.objects
  for select to authenticated using (bucket_id = 'venue-photos' and public.can_view('venues'));
drop policy if exists "venue photos add" on storage.objects;
create policy "venue photos add" on storage.objects
  for insert to authenticated with check (bucket_id = 'venue-photos' and public.can_edit('venues'));
drop policy if exists "venue photos change" on storage.objects;
create policy "venue photos change" on storage.objects
  for update to authenticated using (bucket_id = 'venue-photos' and public.can_edit('venues'));
drop policy if exists "venue photos delete" on storage.objects;
create policy "venue photos delete" on storage.objects
  for delete to authenticated using (bucket_id = 'venue-photos' and public.can_edit('venues'));
