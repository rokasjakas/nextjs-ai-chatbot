-- ============================================================
-- Įrangos nuotraukos ir „Išdavimai“ (įrangos išdavimas / nuoma):
--  * nauja skiltis 'handovers' — Išdavimai (Admin → teisės)
--  * handovers — po vieną eilutę kiekvienam išdavimui (kaip „Paėmimai“)
--  * saugykla 'equipment-photos' — išorės ir vidaus nuotraukos:
--      rentals/<id>/…   (paėmimų nuotraukos, teisės pagal „Paėmimai“)
--      handovers/<id>/… (išdavimų nuotraukos, teisės pagal „Išdavimai“)
-- Paleisti PO offers.sql. Supabase → SQL Editor → Run. Saugu paleisti pakartotinai.
-- ============================================================

alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers'));

insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','handovers',true,true), ('office','handovers',true,true), ('tech','handovers',true,true),
  ('freelance','handovers',false,false), ('runner','handovers',false,false)
on conflict (role, section) do nothing;

create table if not exists public.handovers (
  id         text primary key,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);
alter table public.handovers enable row level security;
drop policy if exists "view handovers" on public.handovers;
create policy "view handovers" on public.handovers
  for select to authenticated using (public.can_view('handovers'));
drop policy if exists "edit handovers" on public.handovers;
create policy "edit handovers" on public.handovers
  for all to authenticated using (public.can_edit('handovers')) with check (public.can_edit('handovers'));

-- nuotraukos
insert into storage.buckets (id, name, public) values ('equipment-photos', 'equipment-photos', false)
on conflict (id) do nothing;

create or replace function public.equipment_photo_access(obj_name text, edit boolean) returns boolean
  language sql stable security definer set search_path = public as $$
  select case (storage.foldername(obj_name))[1]
    when 'rentals'   then case when edit then public.can_edit('rentals')   else public.can_view('rentals')   end
    when 'handovers' then case when edit then public.can_edit('handovers') else public.can_view('handovers') end
    else false end
$$;
grant execute on function public.equipment_photo_access(text, boolean) to authenticated;

drop policy if exists "equipment photos view" on storage.objects;
create policy "equipment photos view" on storage.objects
  for select to authenticated using (bucket_id = 'equipment-photos' and public.equipment_photo_access(name, false));
drop policy if exists "equipment photos add" on storage.objects;
create policy "equipment photos add" on storage.objects
  for insert to authenticated with check (bucket_id = 'equipment-photos' and public.equipment_photo_access(name, true));
drop policy if exists "equipment photos change" on storage.objects;
create policy "equipment photos change" on storage.objects
  for update to authenticated using (bucket_id = 'equipment-photos' and public.equipment_photo_access(name, true));
drop policy if exists "equipment photos delete" on storage.objects;
create policy "equipment photos delete" on storage.objects
  for delete to authenticated using (bucket_id = 'equipment-photos' and public.equipment_photo_access(name, true));
