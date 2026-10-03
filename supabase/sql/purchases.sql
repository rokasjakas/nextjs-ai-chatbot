-- ============================================================
-- „Pirkiniai“: pirkinių skiltys (kaip Excel lapai: VIDEO, LIGHT, AUDIO, Bendri daiktai…)
--  * viena eilutė = viena skiltis; jos lentelė (eilutės, langeliai, formulės) – rows (jsonb)
--  * vieša (visible = 'public') – mato visi, kam leista „Pirkiniai“, keisti gali kas juos redaguoja;
--    tik man (visible = 'private') – mato ir keičia tik sukūręs
--  * viešumą ir pavadinimą keičia tik savininkas (ar administratorius)
-- Supabase → SQL Editor → New query → įklijuok VISĄ → Run. Saugu paleisti pakartotinai.
-- ============================================================

-- ---------- skiltis „Pirkiniai“ teisių lentelėje ----------
alter table public.role_permissions drop constraint if exists role_permissions_section_check;
alter table public.role_permissions add constraint role_permissions_section_check
  check (section in ('events','rentals','projects','load','inventory','rules','fleet','stats','venues','chat','mail','offers','jobs','handovers','people','newproj','invoices','buy'));
insert into public.role_permissions (role, section, can_view, can_edit) values
  ('pm','buy',true,true), ('office','buy',true,true), ('tech','buy',true,true),
  ('freelance','buy',false,false), ('runner','buy',false,false)
on conflict (role, section) do nothing;

create table if not exists public.purchase_lists (
  id               uuid primary key default gen_random_uuid(),
  name             text not null default 'Nauja skiltis',
  visible          text not null default 'public' check (visible in ('public','private')),
  owner            uuid not null default auth.uid() references auth.users(id) on delete cascade,
  owner_name       text,
  sort             integer not null default 0,
  cols             jsonb not null default '[]'::jsonb,   -- column titles (A…H)
  rows             jsonb not null default '[]'::jsonb,   -- [{id, sec?, c:{A:'…', B:'=…'}}]
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  updated_by       uuid,
  updated_by_name  text
);
create index if not exists purchase_lists_sort on public.purchase_lists (sort, created_at);

create or replace function public.purchase_lists_guard() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'UPDATE' and old.owner <> auth.uid() and not public.is_admin() then
    if new.owner <> old.owner or new.visible <> old.visible or new.name <> old.name then
      raise exception 'Pavadinimą ir matomumą keičia tik skilties savininkas.';
    end if;
  end if;
  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end $$;
drop trigger if exists purchase_lists_guard on public.purchase_lists;
create trigger purchase_lists_guard before insert or update on public.purchase_lists
  for each row execute function public.purchase_lists_guard();

alter table public.purchase_lists enable row level security;
drop policy if exists "purchase lists view" on public.purchase_lists;
create policy "purchase lists view" on public.purchase_lists for select to authenticated
  using (owner = auth.uid() or (visible = 'public' and public.can_view('buy')));
drop policy if exists "purchase lists add" on public.purchase_lists;
create policy "purchase lists add" on public.purchase_lists for insert to authenticated
  with check (owner = auth.uid() and (public.can_edit('buy') or (visible = 'private' and public.can_view('buy'))));
drop policy if exists "purchase lists change" on public.purchase_lists;
create policy "purchase lists change" on public.purchase_lists for update to authenticated
  using (owner = auth.uid() or (visible = 'public' and public.can_edit('buy')))
  with check (owner = auth.uid() or (visible = 'public' and public.can_edit('buy')));
drop policy if exists "purchase lists delete" on public.purchase_lists;
create policy "purchase lists delete" on public.purchase_lists for delete to authenticated
  using (owner = auth.uid() or public.is_admin());
revoke all on public.purchase_lists from anon;
grant select, insert, update, delete on public.purchase_lists to authenticated;

-- Supabase: read the list of tables again
notify pgrst, 'reload schema';
